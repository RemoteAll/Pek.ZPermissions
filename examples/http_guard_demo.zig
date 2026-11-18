//! 真实 HTTP 服务上跑 `http_auth` 中间件的示例（供 `tools/http_guard_e2e.ps1` 做端到端验证）。
//!
//! 用法：
//!   http-guard-demo <secret> <port>
//!     secret 形如 `HS256:demo-key`
//!
//! 路由：
//!   GET /health      → 200（命中豁免前缀，不需要令牌）
//!   GET /api/whoami  → 需要 `Authorization: Bearer <token>`；通过后从链路状态取 uid/client
//!
//! 说明：本示例只负责「把中间件挂到真服务上」，业务 handler 里没有任何鉴权代码——
//! 身份由 `http_auth` 写入 `Ctx.state`，这正是该中间件的价值。

const std = @import("std");
const zperm = @import("pek_zpermissions");
const zzig = @import("zzig");

const router = zzig.web.router;

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;

    var args = std.ArrayList([]const u8).empty;
    defer args.deinit(gpa);

    var it = try std.process.Args.Iterator.initAllocator(init.minimal.args, gpa);
    defer it.deinit();
    while (it.next()) |arg| try args.append(gpa, arg);

    if (args.items.len < 3) {
        std.debug.print("usage: http-guard-demo <secret> <port>\n", .{});
        return 2;
    }

    const secret = zperm.secret.parse(args.items[1]) catch |e| {
        std.debug.print("secret 无效：{s}\n", .{zperm.secret.describe(e)});
        return 2;
    };
    const port = std.fmt.parseInt(u16, args.items[2], 10) catch {
        std.debug.print("port 无效：{s}\n", .{args.items[2]});
        return 2;
    };

    var app = try zzig.web.App.init(gpa, io, .{ .wwwroot = null, .gzip = false });
    defer app.deinit();

    // 鉴权中间件：注册后所有路由自动受保护（豁免前缀除外）
    var guard = zperm.http_auth.Guard.init(io, .{ .secret = secret });
    try app.useMiddleware(guard.middleware());

    try app.get("/health", router.handler(health));
    try app.get("/api/whoami", router.handler(whoami));

    std.debug.print("[demo] http://127.0.0.1:{d}  secret={s}\n", .{ port, args.items[1] });
    try app.run("127.0.0.1", port, .{});
    return 0;
}

fn health(_: *router.Ctx) anyerror!router.Response {
    return .{ .body = "{\"ok\":true}" };
}

fn whoami(c: *router.Ctx) anyerror!router.Response {
    const uid = c.stateValue(zperm.http_auth.STATE_UID) orelse "-";
    const client = c.stateValue(zperm.http_auth.STATE_CLIENT) orelse "";
    const body = try std.fmt.allocPrint(
        c.arena,
        "{{\"uid\":\"{s}\",\"client\":\"{s}\"}}",
        .{ uid, client },
    );
    return .{ .body = body };
}
