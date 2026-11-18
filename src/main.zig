//! `zperm` CLI —— 三语言 JWT 互通对拍工具（与 C# `tools/csharp/JwtInterop`、
//! Rust `Pek.RCard/examples/jwt_tool.rs` 命令输出格式对称）。
//!
//! 用法：
//!   zperm jwt gen    <secret> <payloadJson|@file> [expireMinutes] [--iss=..] [--sub=..] [--jti=..]
//!   zperm jwt genraw <secret> <payloadJson|@file>
//!   zperm jwt verify <secret> <token>
//!   zperm jwt inspect <token>
//!   zperm jwt selfcheck
//!
//! 输出统一为 `KEY=VALUE` 行，便于 PowerShell / shell 解析。

const std = @import("std");
const jwt = @import("jwt.zig");
const secret_mod = @import("secret.zig");

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;

    var args = std.ArrayList([]const u8).empty;
    defer args.deinit(gpa);

    var it = try std.process.Args.Iterator.initAllocator(init.minimal.args, gpa);
    defer it.deinit();
    while (it.next()) |arg| try args.append(gpa, arg);

    var buf: [8192]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(io, &buf);
    const w = &stdout.interface;
    defer w.flush() catch {};

    if (args.items.len < 3) {
        try usage(w);
        return 2;
    }

    if (!std.mem.eql(u8, args.items[1], "jwt")) {
        try w.print("ERROR=unknown group {s}\n", .{args.items[1]});
        try usage(w);
        return 2;
    }

    const cmd = args.items[2];
    if (std.mem.eql(u8, cmd, "gen")) return cmdGen(io, gpa, w, args.items[3..], false);
    if (std.mem.eql(u8, cmd, "genraw")) return cmdGen(io, gpa, w, args.items[3..], true);
    if (std.mem.eql(u8, cmd, "verify")) return cmdVerify(io, gpa, w, args.items[3..]);
    if (std.mem.eql(u8, cmd, "inspect")) return cmdInspect(gpa, w, args.items[3..]);
    if (std.mem.eql(u8, cmd, "selfcheck")) return cmdSelfCheck(gpa, w);

    try w.print("ERROR=unknown command {s}\n", .{cmd});
    try usage(w);
    return 2;
}

fn usage(w: *std.Io.Writer) !void {
    try w.print(
        \\usage:
        \\  zperm jwt gen     <secret> <payloadJson|@file> [expireMinutes] [--iss=..] [--sub=..] [--jti=..]
        \\  zperm jwt genraw  <secret> <payloadJson|@file>      # 原样签名（不注入 exp/iat）
        \\  zperm jwt verify  <secret> <token>
        \\  zperm jwt inspect <token>
        \\  zperm jwt selfcheck
        \\
    , .{});
}

fn nowSeconds(io: std.Io) i64 {
    const ts = std.Io.Clock.real.now(io);
    const ns_per_s: i96 = std.time.ns_per_s;
    return @intCast(@divFloor(ts.nanoseconds, ns_per_s));
}

fn loadPayload(io: std.Io, gpa: std.mem.Allocator, raw: []const u8) ![]u8 {
    if (raw.len > 0 and raw[0] == '@') {
        return std.Io.Dir.cwd().readFileAlloc(io, raw[1..], gpa, .unlimited);
    }
    return gpa.dupe(u8, raw);
}

fn cmdGen(
    io: std.Io,
    gpa: std.mem.Allocator,
    w: *std.Io.Writer,
    params: []const []const u8,
    verbatim: bool,
) !u8 {
    if (params.len < 2) {
        try w.print("ERROR=gen 需要 <secret> <payloadJson|@file>\n", .{});
        return 2;
    }

    const secret_text = params[0];
    const parsed = jwt.parseSecret(secret_text) catch |e| {
        try w.print("ERROR={s}\n", .{@import("secret.zig").describe(e)});
        return 2;
    };

    // 可选参数：位置 2 = 分钟；其余为 --iss/--sub/--jti
    var minutes: i64 = 120;
    var issuer: ?[]const u8 = null;
    var subject: ?[]const u8 = null;
    var jti: ?[]const u8 = null;
    var i: usize = 2;
    while (i < params.len) : (i += 1) {
        const p = params[i];
        if (std.mem.startsWith(u8, p, "--iss=")) {
            issuer = p["--iss=".len..];
        } else if (std.mem.startsWith(u8, p, "--sub=")) {
            subject = p["--sub=".len..];
        } else if (std.mem.startsWith(u8, p, "--jti=")) {
            jti = p["--jti=".len..];
        } else if (p.len > 0 and p[0] != '-') {
            minutes = std.fmt.parseInt(i64, p, 10) catch {
                try w.print("ERROR=expireMinutes 不是整数：{s}\n", .{p});
                return 2;
            };
        } else {
            try w.print("ERROR=未知参数 {s}\n", .{p});
            return 2;
        }
    }

    const payload_json = loadPayload(io, gpa, params[1]) catch |e| {
        try w.print("ERROR=读取负载失败：{t}\n", .{e});
        return 2;
    };
    defer gpa.free(payload_json);

    const now = nowSeconds(io);

    var builder = jwt.Builder{
        .key = parsed.key,
        .algorithm = parsed.algorithm,
        .issuer = issuer,
        .subject = subject,
        .id = jti,
        .issued_at = if (verbatim) null else now,
        .expire = if (verbatim) null else saturateAdd(now, saturateMul(minutes, 60)),
    };

    const token = if (verbatim)
        builder.encodeVerbatim(gpa, payload_json)
    else
        builder.encodeJson(gpa, payload_json, now);

    const tok = token catch |e| {
        try w.print("ERROR={s}\n", .{jwt.message(e)});
        return 1;
    };
    defer gpa.free(tok);

    // 与其它语言工具一致：输出解码后的 header / payload
    var check = jwt.Builder{};
    if (check.parseUnverified(gpa, tok)) |decoded| {
        var d = decoded;
        defer d.deinit();
        var hdr_buf: [4096]u8 = undefined;
        var pl_buf: [8192]u8 = undefined;
        try w.print("HEADER={s}\n", .{renderJson(&d.header, &hdr_buf)});
        try w.print("PAYLOAD={s}\n", .{renderJson(&d.payload, &pl_buf)});
    } else |_| {}
    try w.print("TOKEN={s}\n", .{tok});
    return 0;
}

fn cmdVerify(
    io: std.Io,
    gpa: std.mem.Allocator,
    w: *std.Io.Writer,
    params: []const []const u8,
) !u8 {
    if (params.len < 2) {
        try w.print("ERROR=verify 需要 <secret> <token>\n", .{});
        return 2;
    }

    const parsed = jwt.parseSecret(params[0]) catch |e| {
        try w.print("RESULT=FAIL\nMESSAGE={s}\n", .{secret_mod.describe(e)});
        return 1;
    };

    var builder = jwt.Builder{ .key = parsed.key, .algorithm = parsed.algorithm };
    var decoded = builder.validate(gpa, params[1], nowSeconds(io)) catch |e| {
        try w.print("RESULT=FAIL\nMESSAGE={s}\n", .{jwt.message(e)});
        return 1;
    };
    defer decoded.deinit();

    var pl_buf: [8192]u8 = undefined;
    try w.print("RESULT=OK\n", .{});
    try w.print("PAYLOAD={s}\n", .{renderJson(&decoded.payload, &pl_buf)});
    return 0;
}

fn cmdInspect(gpa: std.mem.Allocator, w: *std.Io.Writer, params: []const []const u8) !u8 {
    if (params.len < 1) {
        try w.print("ERROR=inspect 需要 <token>\n", .{});
        return 2;
    }

    var builder = jwt.Builder{};
    var decoded = builder.parseUnverified(gpa, params[0]) catch |e| {
        try w.print("RESULT=FAIL\nMESSAGE={s}\n", .{jwt.message(e)});
        return 1;
    };
    defer decoded.deinit();

    var hdr_buf: [4096]u8 = undefined;
    var pl_buf: [8192]u8 = undefined;
    try w.print("HEADER={s}\n", .{renderJson(&decoded.header, &hdr_buf)});
    try w.print("PAYLOAD={s}\n", .{renderJson(&decoded.payload, &pl_buf)});
    try w.print("RESULT=OK\n", .{});
    return 0;
}

/// 内置黄金样本自检（不依赖外部进程）：C# 签发样本必须被本实现验通。
fn cmdSelfCheck(gpa: std.mem.Allocator, w: *std.Io.Writer) !u8 {
    const token = "eyJhbGciOiJIUzI1NiJ9." ++
        "eyJzdWIiOiI0MiIsIm5hbWUiOiJhbGljZSIsImZyb20iOiJyY2FyZCIsImNsaWVudFR5cGUiOiJhcHAiLCJpc3MiOiJQZWsuUkNhcmQiLCJleHAiOjE3OTE2MDAzMzgsImlhdCI6MTc5MTU5MzEzOCwianRpIjoiNDIifQ." ++
        "4fiepkRzWbMCix2zjk3TxRnvQfvwO0hzIGzPCSyxv6M";

    var builder = jwt.Builder.fromSecret("HS256:rcard-interop-key-2026") catch {
        try w.print("SELFCHECK=FAIL reason=bad-secret\n", .{});
        return 1;
    };
    var decoded = builder.validate(gpa, token, 1791593138 + 60) catch |e| {
        try w.print("SELFCHECK=FAIL reason=csharp-golden:{s}\n", .{jwt.message(e)});
        return 1;
    };
    decoded.deinit();

    try w.print("SELFCHECK=OK\n", .{});
    return 0;
}

/// 把 ObjectMap 渲染到栈缓冲；失败时返回 `{}`。
fn renderJson(map: *const std.json.ObjectMap, buf: []u8) []const u8 {
    var fw = std.Io.Writer.fixed(buf);
    std.json.Stringify.value(std.json.Value{ .object = map.* }, .{}, &fw) catch return "{}";
    return fw.buffered();
}

fn saturateAdd(a: i64, b: i64) i64 {
    const r = @addWithOverflow(a, b);
    return if (r[1] != 0) (if (b > 0) std.math.maxInt(i64) else std.math.minInt(i64)) else r[0];
}

fn saturateMul(a: i64, b: i64) i64 {
    const r = @mulWithOverflow(a, b);
    return if (r[1] != 0) (if ((a > 0) == (b > 0)) std.math.maxInt(i64) else std.math.minInt(i64)) else r[0];
}
