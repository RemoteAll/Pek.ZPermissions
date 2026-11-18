//! 会话热路径性能基准（`zig build bench`，固定 ReleaseFast）。
//!
//! 测的是 `Keeper.check` 这条**每次请求都会走**的路径：
//!   令牌 → SHA-256 → hex → 拼 `{prefix}session:{hex}` → 存储查找
//!
//! 对比三组：
//!   A. 当前实现：手写 hex + `allocPrint("{s}session:{s}")`
//!   B. 改用 zzig `sha256Hex`（栈上 64 字节）+ 单次 `alloc` + `memcpy`
//!   C. `Keeper.check` 端到端（MemoryStore）
//!
//! 为什么进程内测：`zperm session check` 单次进程启动就要几十毫秒，
//! 完全淹没 ns 级的键构造开销。

const std = @import("std");
const zperm = @import("pek_zpermissions");
const zzig = @import("zzig");

const N_KEY: usize = 1_000_000;
const N_CHECK: usize = 1_000_000;

const TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiIsIm5hbWUiOiJwZXJrIn0.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

fn nowNs(io: std.Io) i128 {
    return std.Io.Clock.real.now(io).nanoseconds;
}

fn nsPerOp(t0: i128, t1: i128, n: usize) f64 {
    if (n == 0) return 0;
    return @as(f64, @floatFromInt(t1 - t0)) / @as(f64, @floatFromInt(n));
}

/// A：当前实现（手写 hex + allocPrint）
fn keyOld(alloc: std.mem.Allocator, prefix: []const u8, token: []const u8) ?[]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(token, &digest, .{});

    const table = "0123456789abcdef";
    var hex: [64]u8 = undefined;
    for (digest, 0..) |b, i| {
        hex[i * 2] = table[b >> 4];
        hex[i * 2 + 1] = table[b & 0x0f];
    }
    return std.fmt.allocPrint(alloc, "{s}session:{s}", .{ prefix, hex[0..] }) catch null;
}

/// B：优化实现（zzig sha256Hex 栈输出 + 单次 alloc + memcpy）
fn keyNew(alloc: std.mem.Allocator, prefix: []const u8, token: []const u8) ?[]u8 {
    const hex = zzig.hash.sha256Hex(token);
    const lit = "session:";
    const out = alloc.alloc(u8, prefix.len + lit.len + hex.len) catch return null;
    @memcpy(out[0..prefix.len], prefix);
    @memcpy(out[prefix.len..][0..lit.len], lit);
    @memcpy(out[prefix.len + lit.len ..][0..hex.len], &hex);
    return out;
}

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(io, &buf);
    const w = &stdout.interface;
    defer w.flush() catch {};

    try w.print("[bench] token={d} 字节，prefix=\"\"（默认）\n", .{TOKEN.len});

    // ── ① 裸 SHA-256 + hex ──
    {
        var sink: usize = 0;
        const t0 = nowNs(io);
        var i: usize = 0;
        while (i < N_KEY) : (i += 1) {
            const hex = zzig.hash.sha256Hex(TOKEN);
            sink +%= hex[0];
        }
        const t1 = nowNs(io);
        std.mem.doNotOptimizeAway(sink);
        try w.print("BENCH sha256Hex          {d:>9.1} ns/op（{d} 次）\n", .{ nsPerOp(t0, t1, N_KEY), N_KEY });
    }

    // ── ② A：当前 sessionKey ──
    {
        var sink: usize = 0;
        const t0 = nowNs(io);
        var i: usize = 0;
        while (i < N_KEY) : (i += 1) {
            const k = keyOld(gpa, "", TOKEN) orelse return 1;
            sink +%= k.len;
            gpa.free(k);
        }
        const t1 = nowNs(io);
        std.mem.doNotOptimizeAway(sink);
        try w.print("BENCH key 当前(allocPrint) {d:>9.1} ns/op\n", .{nsPerOp(t0, t1, N_KEY)});
    }

    // ── ③ B：优化 sessionKey ──
    {
        var sink: usize = 0;
        const t0 = nowNs(io);
        var i: usize = 0;
        while (i < N_KEY) : (i += 1) {
            const k = keyNew(gpa, "", TOKEN) orelse return 1;
            sink +%= k.len;
            gpa.free(k);
        }
        const t1 = nowNs(io);
        std.mem.doNotOptimizeAway(sink);
        try w.print("BENCH key 优化(单次alloc)  {d:>9.1} ns/op\n", .{nsPerOp(t0, t1, N_KEY)});
    }

    // ── ④ 两种实现产出必须完全一致（否则优化没意义）──
    {
        const a = keyOld(gpa, "pfx:", TOKEN) orelse return 1;
        defer gpa.free(a);
        const b = keyNew(gpa, "pfx:", TOKEN) orelse return 1;
        defer gpa.free(b);
        if (!std.mem.eql(u8, a, b)) {
            try w.print("EQUIV=FAIL\n  old={s}\n  new={s}\n", .{ a, b });
            return 1;
        }
        try w.print("EQUIV=OK  {s}\n", .{b});
    }

    // ── ⑤ Keeper.check 端到端（MemoryStore，已登记）──
    {
        var mem = zperm.MemoryStore.init(gpa);
        defer mem.deinit();

        var keeper = zperm.SessionKeeper.init(gpa, mem.store(), "", .{});
        const now: i64 = @intCast(@divFloor(nowNs(io), @as(i128, std.time.ns_per_s)));
        if (!keeper.register(TOKEN, 42, "pwd-tag", "web", now)) {
            try w.print("SKIP Keeper.check：登记失败\n", .{});
            return 1;
        }

        var sink: usize = 0;
        const t0 = nowNs(io);
        var i: usize = 0;
        while (i < N_CHECK) : (i += 1) {
            const st = keeper.check(TOKEN, now);
            sink +%= switch (st) {
                .active => |act| blk: {
                    var a = act;
                    a.deinit(gpa);
                    break :blk 1;
                },
                .invalid => 2,
                .untracked => 3,
            };
        }
        const t1 = nowNs(io);
        std.mem.doNotOptimizeAway(sink);
        try w.print("BENCH Keeper.check 端到端 {d:>9.1} ns/op（{d} 次，含 SHA-256+JSON+两级版本）\n", .{ nsPerOp(t0, t1, N_CHECK), N_CHECK });

        // ── ⑥ 只做「键 + store.get」：拆出存储侧开销 ──
        const key = keyNew(gpa, "", TOKEN) orelse return 1;
        defer gpa.free(key);
        const store = mem.store();
        {
            var s2: usize = 0;
            const g0 = nowNs(io);
            var j: usize = 0;
            while (j < N_CHECK) : (j += 1) {
                const v = store.get(gpa, key, now) orelse continue;
                s2 +%= v.len;
                gpa.free(v);
            }
            const g1 = nowNs(io);
            std.mem.doNotOptimizeAway(s2);
            try w.print("BENCH store.get 单项     {d:>9.1} ns/op（MemoryStore：锁+map+复制）\n", .{nsPerOp(g0, g1, N_CHECK)});
        }

        // ── ⑦ 只做 JSON 解析：拆出解析开销 ──
        {
            const sample = "{\"uid\":42,\"pwd\":\"pwd-tag\",\"client\":\"web\",\"ver\":0,\"cver\":0,\"iat\":1795000000,\"abs\":1797592000,\"exp\":1795604800}";
            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();
            var s3: usize = 0;
            const v0 = nowNs(io);
            var k: usize = 0;
            while (k < N_CHECK) : (k += 1) {
                const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), sample, .{}) catch continue;
                if (parsed == .object) s3 +%= 1;
                _ = arena.reset(.retain_capacity);
            }
            const v1 = nowNs(io);
            std.mem.doNotOptimizeAway(s3);
            try w.print("BENCH JSON 解析单项      {d:>9.1} ns/op（std.json.parseFromSliceLeaky）\n", .{nsPerOp(v0, v1, N_CHECK)});

            // ── ⑧ zzig jsmn 单次取值（含一次 token 化 + 一次分配）──
            var s4: usize = 0;
            const q0 = nowNs(io);
            var m: usize = 0;
            while (m < N_CHECK) : (m += 1) {
                const v = zzig.json.JsonQuery.init(gpa, sample).getInt(i64, "exp") catch continue;
                s4 +%= @intCast(v & 0xFF);
            }
            const q1 = nowNs(io);
            std.mem.doNotOptimizeAway(s4);
            try w.print("BENCH JSON jsmn 取1字段  {d:>9.1} ns/op（zzig JsonQuery，含一次 parse）\n", .{nsPerOp(q0, q1, N_CHECK)});

            // ── ⑨ zzig jsmn 一次解析 + 一次遍历取全字段（Keeper.check 的真实路径）──
            // JsonQuery 每个 get 都会重新 parse；JsonDoc 只 parse 一次，
            // getIntsInto 把 6 个整数键合并成一次遍历。
            var s5: i64 = 0;
            var ints: [6]i64 = undefined;
            const d0 = nowNs(io);
            var n: usize = 0;
            while (n < N_CHECK) : (n += 1) {
                var doc = zzig.json.JsonDoc.init(gpa, sample) catch continue;
                defer doc.deinit();
                doc.getIntsInto(&.{ "exp", "abs", "uid", "ver", "cver", "iat" }, &ints);
                var acc: i64 = 0;
                for (ints) |v| acc +%= v;
                acc +%= @intCast((doc.getStringRaw("client") catch @as([]const u8, "")).len);
                acc +%= @intCast((doc.getStringRaw("pwd") catch @as([]const u8, "")).len);
                s5 +%= acc;
            }
            const d1 = nowNs(io);
            std.mem.doNotOptimizeAway(s5);
            try w.print("BENCH JSON jsmn 全字段  {d:>9.1} ns/op（zzig JsonDoc：1 次解析+1 次遍历）\n", .{nsPerOp(d0, d1, N_CHECK)});
        }
    }

    return 0;
}
