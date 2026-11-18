//! `zperm` CLI —— 三语言 JWT 互通对拍工具（与 C# `tools/csharp/JwtInterop`、
//! Rust `Pek.RCard/examples/jwt_tool.rs` 命令输出格式对称）。
//!
//! 用法：
//!   zperm jwt gen    <secret> <payloadJson|@file> [expireMinutes] [--iss=..] [--sub=..] [--jti=..]
//!   zperm jwt genraw <secret> <payloadJson|@file>
//!   zperm jwt verify <secret> <token>
//!   zperm jwt inspect <token>
//!   zperm jwt selfcheck
//!   zperm session list         <db> <uid>
//!   zperm session check        <db> <token>
//!   zperm session revoke       <db> <token>
//!   zperm session revokeuser   <db> <uid>
//!   zperm session revokeclient <db> <uid> <client>
//!   zperm model check          [modelPath]
//!
//! 所有 session 子命令支持 `--model=<path>` / `--prefix=<keyPrefix>` / `--idle=<secs>` / `--max=<secs>`。
//! 输出统一为 `KEY=VALUE` 行，便于 PowerShell / shell 解析。
//! 退出码：0 = 成功/放行；1 = 业务失败（校验失败、会话无效等）；2 = 用法错误。

const std = @import("std");
const jwt = @import("jwt.zig");
const secret_mod = @import("secret.zig");
const session_mod = @import("session.zig");
const sqlite_store = @import("sqlite_store.zig");
const model_guard = @import("model_guard.zig");
const redis_store = @import("redis_store.zig");
const zcode = @import("zcode");
const zzig = @import("zzig");

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

    const group = args.items[1];
    const cmd = args.items[2];

    if (std.mem.eql(u8, group, "session")) {
        return cmdSession(io, gpa, w, cmd, args.items[3..]);
    }
    if (std.mem.eql(u8, group, "redis")) {
        return cmdRedis(io, gpa, w, cmd, args.items[3..]);
    }
    if (std.mem.eql(u8, group, "model")) {
        if (std.mem.eql(u8, cmd, "check")) return cmdModelCheck(gpa, w, args.items[3..]);
        try w.print("ERROR=unknown command model {s}\n", .{cmd});
        try usage(w);
        return 2;
    }

    if (!std.mem.eql(u8, group, "jwt")) {
        try w.print("ERROR=unknown group {s}\n", .{group});
        try usage(w);
        return 2;
    }

    if (std.mem.eql(u8, cmd, "gen")) return cmdGen(io, gpa, w, args.items[3..], false);
    if (std.mem.eql(u8, cmd, "genraw")) return cmdGen(io, gpa, w, args.items[3..], true);
    if (std.mem.eql(u8, cmd, "verify")) return cmdVerify(gpa, w, args.items[3..]);
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
        \\  zperm session register     <db> <token> <uid>      # 登记会话（等价登录成功后的 register）
        \\  zperm session list         <db> <uid>
        \\  zperm session check        <db> <token>
        \\  zperm session revoke       <db> <token>
        \\  zperm session revokeuser   <db> <uid>
        \\  zperm session revokeclient <db> <uid> <client>
        \\      # 可选：--model=Entity/Model.xml  --prefix=  --idle=<secs>  --max=<secs>
        \\      # 只给连接名（未配置连接串时回退）：--conn=Permissions [--data=Data]
        \\      #   生成 Data Source=Data/Permissions.db;Provider=SQLite;Migration=On（与 C# 一致）
        \\      # 走 Redis：--redis=127.0.0.1:6379 [--redisdb=0] [--password=]，此时**不需要** <db>
        \\      # register 专用：--client=<name>（默认 cli）  --pwd=<pwdTag>
        \\
        \\  zperm model check [modelPath]     # 模型守卫（防代码↔Model.xml 漂移）
        \\
        \\  zperm redis ping <server> [--db=0] [--password=]
        \\  zperm redis get  <server> <token> [--db=0]
        \\  zperm redis del  <server> <token> [--db=0]
        \\  zperm redis put  <server> <token> <uid> <issuedUnix> <expiresUnix> [--db=0] [--refresh=]
        \\      # 键与值格式对齐 C# JsonWebTokenStore（jwt:token:access:{{token}} + 毫秒）
        \\
    , .{});
}

/// 当前 Unix 秒（复用 zzig：Windows 直调 Win32，不依赖 `io`）。
fn nowSeconds() i64 {
    return zzig.DateTime.nowUnix();
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

    const now = nowSeconds();

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
    var decoded = builder.validate(gpa, params[1], nowSeconds()) catch |e| {
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

/// `zperm redis ...`：C# 键空间镜像的读写（用于运维排障与 C# 双向对拍）。
///
/// 键与值格式完全对齐 C# `JsonWebTokenStore`（`jwt:token:access:{token}` + PascalCase JSON + 毫秒）。
fn cmdRedis(
    io: std.Io,
    gpa: std.mem.Allocator,
    w: *std.Io.Writer,
    cmd: []const u8,
    params: []const []const u8,
) !u8 {
    var db: i32 = 0;
    var password: ?[]const u8 = null;
    var refresh: []const u8 = "";

    var pos = std.ArrayList([]const u8).empty;
    defer pos.deinit(gpa);

    for (params) |p| {
        if (!std.mem.startsWith(u8, p, "--")) {
            try pos.append(gpa, p);
            continue;
        }
        const kv = p[2..];
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse {
            try w.print("ERROR=参数 {s} 需要 --key=value 形式\n", .{p});
            return 2;
        };
        const k = kv[0..eq];
        const v = kv[eq + 1 ..];
        if (std.mem.eql(u8, k, "db")) {
            db = std.fmt.parseInt(i32, v, 10) catch {
                try w.print("ERROR=--db 需要整数，收到 {s}\n", .{v});
                return 2;
            };
        } else if (std.mem.eql(u8, k, "password")) {
            password = v;
        } else if (std.mem.eql(u8, k, "refresh")) {
            refresh = v;
        } else {
            try w.print("ERROR=未知参数 --{s}\n", .{k});
            return 2;
        }
    }

    if (pos.items.len < 1) {
        try w.print("ERROR=redis 需要 <server>（如 127.0.0.1:6379）\n", .{});
        return 2;
    }
    const server = pos.items[0];

    var mirror = redis_store.CSharpMirror.open(gpa, io, server, password, db) catch |e| {
        try w.print(
            "ERROR=连接 Redis 失败：{s}\n" ++
                "SERVER={s}\nDB={d}\n" ++
                "HINT=确认 redis-server 已启动、地址端口正确；有密码时传 --password=<pwd>\n",
            .{ @errorName(e), server, db },
        );
        return 1;
    };
    defer mirror.deinit();

    if (std.mem.eql(u8, cmd, "ping")) {
        const ok = mirror.ping();
        try w.print("PING={d}\nSERVER={s}\nDB={d}\n", .{ @intFromBool(ok), server, db });
        return if (ok) 0 else 1;
    }

    if (std.mem.eql(u8, cmd, "get")) {
        if (pos.items.len < 2) {
            try w.print("ERROR=get 需要 <server> <token>\n", .{});
            return 2;
        }
        const token = pos.items[1];
        const value = mirror.getValue(token) orelse {
            try w.print("EXISTS=0\nTOKEN={s}\nKEY={s}{s}\n", .{ token, redis_store.CSharpMirror.AccessKeyPrefix, token });
            return 1;
        };
        defer gpa.free(value);
        try w.print("EXISTS=1\nKEY={s}{s}\nVALUE={s}\n", .{ redis_store.CSharpMirror.AccessKeyPrefix, token, value });
        return 0;
    }

    if (std.mem.eql(u8, cmd, "del")) {
        if (pos.items.len < 2) {
            try w.print("ERROR=del 需要 <server> <token>\n", .{});
            return 2;
        }
        const ok = mirror.remove(pos.items[1]);
        try w.print("REMOVED={d}\n", .{@intFromBool(ok)});
        return if (ok) 0 else 1;
    }

    if (std.mem.eql(u8, cmd, "put")) {
        if (pos.items.len < 5) {
            try w.print("ERROR=put 需要 <server> <token> <uid> <issuedUnix> <expiresUnix>\n", .{});
            return 2;
        }
        const uid = (try parseIntArg(w, "<uid>", pos.items[2])) orelse return 2;
        const issued = (try parseIntArg(w, "<issuedUnix>", pos.items[3])) orelse return 2;
        const expires = (try parseIntArg(w, "<expiresUnix>", pos.items[4])) orelse return 2;

        const ok = mirror.saveAccess(
            pos.items[1],
            @intCast(uid),
            issued,
            expires,
            refresh,
            0,
        );
        try w.print("SAVED={d}\nKEY={s}{s}\n", .{ @intFromBool(ok), redis_store.CSharpMirror.AccessKeyPrefix, pos.items[1] });
        return if (ok) 0 else 1;
    }

    try w.print("ERROR=未知 redis 子命令 {s}\n", .{cmd});
    return 2;
}

/// `zperm session ...`：会话管理。全部落在 `session.Keeper` 上，CLI 不复制任何语义。
///
/// 后端二选一：默认 SQLite（第一个位置参数为 Pek.ZCode 连接串）；
/// 传 `--redis=<server>` 则走 Redis（此时**不需要** `<db>` 位置参数）。
fn cmdSession(
    io: std.Io,
    gpa: std.mem.Allocator,
    w: *std.Io.Writer,
    cmd: []const u8,
    params: []const []const u8,
) !u8 {
    var model_path: []const u8 = sqlite_store.DEFAULT_MODEL_PATH;
    var prefix: []const u8 = "";
    var policy = session_mod.Policy{};
    var redis_server: ?[]const u8 = null;
    var redis_db: i32 = 0;
    var redis_password: ?[]const u8 = null;
    var conn_name: ?[]const u8 = null;
    var data_dir: []const u8 = "Data";
    var client_name: []const u8 = "cli";
    var pwd_tag: []const u8 = "";

    var pos = std.ArrayList([]const u8).empty;
    defer pos.deinit(gpa);

    for (params) |p| {
        if (!std.mem.startsWith(u8, p, "--")) {
            try pos.append(gpa, p);
            continue;
        }
        const kv = p[2..];
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse {
            try w.print("ERROR=参数 {s} 需要 --key=value 形式\n", .{p});
            return 2;
        };
        const k = kv[0..eq];
        const v = kv[eq + 1 ..];
        if (std.mem.eql(u8, k, "model")) {
            model_path = v;
        } else if (std.mem.eql(u8, k, "prefix")) {
            prefix = v;
        } else if (std.mem.eql(u8, k, "redis")) {
            redis_server = v;
        } else if (std.mem.eql(u8, k, "conn")) {
            conn_name = v;
        } else if (std.mem.eql(u8, k, "data")) {
            data_dir = v;
        } else if (std.mem.eql(u8, k, "redisdb")) {
            redis_db = std.fmt.parseInt(i32, v, 10) catch {
                try w.print("ERROR=--redisdb 需要整数，收到 {s}\n", .{v});
                return 2;
            };
        } else if (std.mem.eql(u8, k, "password")) {
            redis_password = v;
        } else if (std.mem.eql(u8, k, "client")) {
            client_name = v;
        } else if (std.mem.eql(u8, k, "pwd")) {
            pwd_tag = v;
        } else if (std.mem.eql(u8, k, "idle")) {
            policy.idle_secs = std.fmt.parseInt(i64, v, 10) catch {
                try w.print("ERROR=--idle 需要整数秒，收到 {s}\n", .{v});
                return 2;
            };
        } else if (std.mem.eql(u8, k, "max")) {
            policy.max_secs = std.fmt.parseInt(i64, v, 10) catch {
                try w.print("ERROR=--max 需要整数秒，收到 {s}\n", .{v});
                return 2;
            };
        } else {
            try w.print("ERROR=未知参数 --{s}\n", .{k});
            return 2;
        }
    }

    // 两个后端各持有一份实例（`Store` 里的 ptr 指向它，生命周期必须覆盖后续所有调用）
    var sqlite_holder: ?sqlite_store.SqliteStore = null;
    defer if (sqlite_holder) |*x| x.deinit();
    var redis_holder: ?redis_store.RedisStore = null;
    defer if (redis_holder) |*x| x.deinit();

    var store: session_mod.Store = undefined;
    var db_from_pos = false;

    if (redis_server) |srv| {
        redis_holder = redis_store.RedisStore.open(gpa, io, srv, redis_password, redis_db) catch |e| {
            try w.print(
                "ERROR=连接 Redis 失败：{s}\n" ++
                    "SERVER={s}\nDB={d}\n" ++
                    "HINT=确认 redis-server 已启动、地址端口正确；有密码时传 --password=<pwd>\n",
                .{ @errorName(e), srv, redis_db },
            );
            return 1;
        };
        store = redis_holder.?.store();
        if (!redis_holder.?.ping()) {
            try w.print("ERROR=Redis 无响应 PING\nSERVER={s}\n", .{srv});
            return 1;
        }
    } else if (conn_name) |name| {
        // 未配置连接串时的回退：按连接名生成默认 SQLite（与 C# `DAL.Init` 一致）。
        // 连接名只允许字母数字与 - _ .，非法名这里的 error.InvalidConnName 会给出来。
        const conn = zcode.defaultSqliteConnStr(gpa, name, data_dir) catch |e| {
            try w.print(
                "ERROR=连接名非法：{s}\nCONN={s}\n" ++
                    "HINT=连接名只允许字母/数字/`-`/`_`/`.`（与 C# `_symbols` 口径一致）\n",
                .{ @errorName(e), name },
            );
            return 2;
        };
        defer gpa.free(conn);

        // 目录不存在时建好（C# 侧由 DataPath 保证；Zig 的 Dal 没有 io，只能这里做）
        if (data_dir.len > 0) std.Io.Dir.cwd().createDirPath(io, data_dir) catch {};

        try w.print("CONN={s}\nCONNSTR={s}\n", .{ name, conn });
        sqlite_holder = sqlite_store.SqliteStore.open(gpa, conn, model_path) catch |e| {
            try w.print(
                "ERROR=打开会话库失败：{s}\nCONNSTR={s}\nMODEL={s}\n",
                .{ @errorName(e), conn, model_path },
            );
            return 1;
        };
        store = sqlite_holder.?.store();
    } else {
        if (pos.items.len < 1) {
            try w.print(
                "ERROR=session 需要 <db>（Pek.ZCode 连接串，如 \"Data Source=Data\\sessions.db\"）\n" ++
                    "      或 --conn=<连接名>（未配置即回退 Data/<连接名>.db，与 C# 一致）\n" ++
                    "      或 --redis=127.0.0.1:6379 [--redisdb=0]\n",
                .{},
            );
            return 2;
        }
        db_from_pos = true;
        const db = pos.items[0];
        sqlite_holder = sqlite_store.SqliteStore.open(gpa, db, model_path) catch |e| {
            // 失败原因按「日志与错误信息规范」给全：做什么 + 为什么 + 关键上下文 + 下一步
            try w.print(
                "ERROR=打开会话库失败：{s}\n" ++
                    "DB={s}\n" ++
                    "MODEL={s}\n" ++
                    "HINT=常见原因：① 目录不存在（如 Data\\）→ 先创建该目录，或用 --conn=<连接名> 自动建；" ++
                    "② SQLite 动态库不可用（sqlite3 库需在 exe 同目录或 PATH）；" ++
                    "③ 连接串格式应为 \"Data Source=<文件路径>;Provider=SQLite\"\n",
                .{ @errorName(e), db, model_path },
            );
            return 1;
        };
        store = sqlite_holder.?.store();
    }

    // 统一口径：只有「显式连接串」模式的第一个位置参数是库连接串，消费掉它；
    // 之后 `pos.items[0]` 一律是子命令的第一个业务参数（token / uid …）。
    if (db_from_pos and pos.items.len > 0) {
        _ = pos.orderedRemove(0);
    }

    const keeper = session_mod.Keeper.init(gpa, store, prefix, policy);
    const now = nowSeconds();

    if (std.mem.eql(u8, cmd, "register")) {
        return sessionRegister(w, &keeper, pos.items, client_name, pwd_tag, now);
    }
    if (std.mem.eql(u8, cmd, "list")) return sessionList(gpa, w, &keeper, pos.items, now);
    if (std.mem.eql(u8, cmd, "check")) return sessionCheck(gpa, w, &keeper, pos.items, now);
    if (std.mem.eql(u8, cmd, "revoke")) return sessionRevoke(w, &keeper, pos.items, now);
    if (std.mem.eql(u8, cmd, "revokeuser")) return sessionRevokeUser(w, &keeper, pos.items, now);
    if (std.mem.eql(u8, cmd, "revokeclient")) return sessionRevokeClient(w, &keeper, pos.items, now);

    try w.print("ERROR=未知 session 子命令 {s}\n", .{cmd});
    return 2;
}

/// 解析位置参数里的整数；失败时已打印 ERROR，返回 null。
fn parseIntArg(w: *std.Io.Writer, name: []const u8, raw: []const u8) !?i64 {
    return std.fmt.parseInt(i64, raw, 10) catch {
        try w.print("ERROR={s} 需要整数，收到 {s}\n", .{ name, raw });
        return null;
    };
}

/// 登记会话（相当于登录成功后调 `Keeper.register`）。
/// 之前 CLI 没有这个入口，导致 Redis/SQLite 会话后端无法端到端验证。
fn sessionRegister(
    w: *std.Io.Writer,
    keeper: *const session_mod.Keeper,
    pos: []const []const u8,
    client: []const u8,
    pwd_tag: []const u8,
    now: i64,
) !u8 {
    if (pos.len < 2) {
        try w.print("ERROR=register 需要 <token> <uid>（SQLite 模式下前面还有 <db>）\n", .{});
        return 2;
    }
    const token = pos[0];
    const uid = (try parseIntArg(w, "<uid>", pos[1])) orelse return 2;

    const ok = keeper.register(token, uid, pwd_tag, client, now);
    try w.print(
        "REGISTERED={d}\nSTORE={s}\nUID={d}\nCLIENT={s}\n",
        .{ @intFromBool(ok), keeper.storeKind(), uid, client },
    );
    return if (ok) 0 else 1;
}

fn sessionList(
    gpa: std.mem.Allocator,
    w: *std.Io.Writer,
    keeper: *const session_mod.Keeper,
    pos: []const []const u8,
    now: i64,
) !u8 {
    if (pos.len < 1) {
        try w.print("ERROR=list 需要 <uid>（SQLite 模式下前面还有 <db>）\n", .{});
        return 2;
    }
    const uid = (try parseIntArg(w, "<uid>", pos[0])) orelse return 2;

    try w.print("STORE={s}\nUID={d}\n", .{ keeper.storeKind(), uid });
    const maybe = keeper.sessions(uid, now);
    const items = maybe orelse {
        try w.print("COUNT=0\nNOTE=存储不支持集合或当前不可用（SQLite/Redis 支持；纯 JWT 模式不支持）\n", .{});
        return 1;
    };
    defer {
        for (items) |it| it.deinit(gpa);
        gpa.free(items);
    }

    try w.print("COUNT={d}\n", .{items.len});
    for (items, 0..) |it, i| {
        try w.print("SESSION.{d}.CLIENT={s}\n", .{ i, it.client });
        try w.print("SESSION.{d}.IAT={d}\n", .{ i, it.iat });
        try w.print("SESSION.{d}.EXP={d}\n", .{ i, it.exp });
    }
    return 0;
}

fn sessionCheck(
    gpa: std.mem.Allocator,
    w: *std.Io.Writer,
    keeper: *const session_mod.Keeper,
    pos: []const []const u8,
    now: i64,
) !u8 {
    if (pos.len < 1) {
        try w.print("ERROR=check 需要 <token>（SQLite 模式下前面还有 <db>）\n", .{});
        return 2;
    }

    try w.print("STORE={s}\n", .{keeper.storeKind()});
    switch (keeper.check(pos[0], now)) {
        .active => |a| {
            defer a.deinit(gpa);
            try w.print("STATE=active\nCLIENT={s}\nPWD={s}\nAUTHORIZE=1\n", .{ a.client, a.pwd_tag });
            return 0;
        },
        .invalid => {
            try w.print("STATE=invalid\nAUTHORIZE=0\n", .{});
            return 1;
        },
        .untracked => {
            try w.print("STATE=untracked\nAUTHORIZE=1\nNOTE=存储未配置或不可用，按纯 JWT 口径放行\n", .{});
            return 0;
        },
    }
}

fn sessionRevoke(
    w: *std.Io.Writer,
    keeper: *const session_mod.Keeper,
    pos: []const []const u8,
    now: i64,
) !u8 {
    if (pos.len < 1) {
        try w.print("ERROR=revoke 需要 <token>（SQLite 模式下前面还有 <db>）\n", .{});
        return 2;
    }
    const ok = keeper.revoke(pos[0], now);
    try w.print("REVOKED={d}\n", .{@intFromBool(ok)});
    return if (ok) 0 else 1;
}

fn sessionRevokeUser(
    w: *std.Io.Writer,
    keeper: *const session_mod.Keeper,
    pos: []const []const u8,
    now: i64,
) !u8 {
    if (pos.len < 1) {
        try w.print("ERROR=revokeuser 需要 <uid>（SQLite 模式下前面还有 <db>）\n", .{});
        return 2;
    }
    const uid = (try parseIntArg(w, "<uid>", pos[0])) orelse return 2;
    const ok = keeper.revokeUser(uid, now);
    try w.print("UID={d}\nBUMPED={d}\n", .{ uid, @intFromBool(ok) });
    return if (ok) 0 else 1;
}

fn sessionRevokeClient(
    w: *std.Io.Writer,
    keeper: *const session_mod.Keeper,
    pos: []const []const u8,
    now: i64,
) !u8 {
    if (pos.len < 2) {
        try w.print("ERROR=revokeclient 需要 <uid> <client>（SQLite 模式下前面还有 <db>）\n", .{});
        return 2;
    }
    const uid = (try parseIntArg(w, "<uid>", pos[0])) orelse return 2;
    const ok = keeper.revokeClient(uid, pos[1], now);
    try w.print("UID={d}\nCLIENT={s}\nBUMPED={d}\n", .{ uid, pos[1], @intFromBool(ok) });
    return if (ok) 0 else 1;
}

/// `zperm model check [modelPath]`：模型守卫，防止代码与 `Entity/Model.xml` 悄悄漂移。
fn cmdModelCheck(gpa: std.mem.Allocator, w: *std.Io.Writer, params: []const []const u8) !u8 {
    var model_path: []const u8 = sqlite_store.DEFAULT_MODEL_PATH;
    for (params) |p| {
        if (std.mem.startsWith(u8, p, "--model=")) {
            model_path = p["--model=".len..];
        } else if (!std.mem.startsWith(u8, p, "--")) {
            model_path = p;
        } else {
            try w.print("ERROR=未知参数 {s}\n", .{p});
            return 2;
        }
    }

    var report = model_guard.check(gpa, model_path);
    defer report.deinit();

    try w.print("MODEL={s}\n", .{model_path});
    try w.print("CONN={s}\n", .{report.conn_name orelse "-"});
    try w.print("COLUMNS={d}\nINDEXES={d}\n", .{ report.columns, report.indexes });
    for (report.problems[0..report.problem_count]) |p| {
        try w.print("PROBLEM={s}\n", .{p});
    }
    if (!report.ok()) {
        try w.print("CHECK=FAIL\n", .{});
        return 1;
    }
    try w.print("CHECK=OK\n", .{});
    return 0;
}

fn saturateAdd(a: i64, b: i64) i64 {
    const r = @addWithOverflow(a, b);
    return if (r[1] != 0) (if (b > 0) std.math.maxInt(i64) else std.math.minInt(i64)) else r[0];
}

fn saturateMul(a: i64, b: i64) i64 {
    const r = @mulWithOverflow(a, b);
    return if (r[1] != 0) (if ((a > 0) == (b > 0)) std.math.maxInt(i64) else std.math.minInt(i64)) else r[0];
}
