//! HTTP 鉴权中间件：接入 `zzig` 的 `web.App` / `router`（**不新造 HTTP 栈**）。
//!
//! 上游 `zzig/http/server.zig` 明确写着「**鉴权/限流不在这里**：由业务层做」，
//! 本文件就是补这一层，按 `router.Middleware` 的形态提供，注册方式：
//!
//! ```zig
//! var guard = http_auth.Guard.init(.{ .secret = secret, .keeper = &keeper });
//! try app.router.useMiddleware(guard.middleware());
//! ```
//!
//! # 只做三件事
//!
//! 1. 取 `Authorization: Bearer <token>`（缺失/格式错 → `401`）
//! 2. 验签 + 过期（`jwt.Builder.validate`，失败 → `401`）
//! 3. 会话校验（`Keeper.check`：`invalid` → `403`；`untracked` → **放行**）
//!
//! 第 3 步沿用本库硬口径：**任何存储问题都不能把用户挡在外面**，
//! 只有「存储可用且明确无效（登出/踢线/过期）」才拒绝。
//!
//! # 通过后写进链路状态（业务 handler 不必再解析一次 JWT）
//!
//! | 键 | 含义 |
//! |---|---|
//! | `auth.uid` | `sub` 声明 |
//! | `auth.client` | 会话记录里的客户端标识（需配 `keeper`） |
//! | `auth.pwd` | 口令指纹（需配 `keeper`） |
//!
//! 豁免路径（默认 `/health`、`/healthz`、`/login`、`/api/login`、`/favicon.ico`）直接放行，
//! 不写任何 `auth.*` 状态。

const std = @import("std");
const zzig = @import("zzig");
const jwt = @import("jwt.zig");
const session = @import("session.zig");
const secret_mod = @import("secret.zig");

const router = zzig.web.router;

/// 链路状态键：`sub` 声明。
pub const STATE_UID = "auth.uid";
/// 链路状态键：客户端标识（需配 `keeper`）。
pub const STATE_CLIENT = "auth.client";
/// 链路状态键：口令指纹（需配 `keeper`）。
pub const STATE_PWD = "auth.pwd";

/// 默认免鉴权前缀（**前缀匹配**，所以 `/login` 也覆盖 `/login/xxx`）。
pub const DEFAULT_SKIP = [_][]const u8{
    "/health",
    "/healthz",
    "/login",
    "/api/login",
    "/favicon.ico",
};

pub const Config = struct {
    /// 密钥（`secret.parse("HS256:key")` 的结果）
    secret: secret_mod.Secret,
    /// 会话校验器；`null` = 只验 JWT（不查登记/吊销）
    keeper: ?*const session.Keeper = null,
    /// 免鉴权路径前缀
    skip_prefixes: []const []const u8 = &DEFAULT_SKIP,
    /// 令牌所在请求头（值形如 `Bearer <token>`）
    header_name: []const u8 = "authorization",
    /// 验签后是否再校验会话状态（登出 / 踢线立即失效）
    require_session: bool = true,
};

/// 鉴权结果（`deny.reason` 一律是静态文案，可直接放进响应）。
pub const Outcome = union(enum) {
    /// 验签通过（并在需要时写入了 `auth.*` 状态）
    allow,
    /// 命中豁免前缀，未做任何校验
    anonymous,
    /// 拒绝
    deny: Deny,

    pub const Deny = struct {
        status: std.http.Status,
        reason: []const u8,
    };
};

pub const Guard = struct {
    cfg: Config,

    /// 构造。**不需要 `io`**：当前时间走 `zzig.DateTime.nowUnix()`（Windows 直调 Win32）。
    pub fn init(cfg: Config) Guard {
        return .{ .cfg = cfg };
    }

    /// 转成路由中间件，供 `router.useMiddleware` / `app` 注册。
    pub fn middleware(self: *Guard) router.Middleware {
        return .{ .ctx = self, .call = invoke };
    }

    /// 核心校验。**时间由调用方传入**（便于测试与跨端复现）。
    pub fn authorize(self: *Guard, c: *router.Ctx, now: i64) Outcome {
        if (self.isSkipped(c.req.path)) return .anonymous;

        const token = extractToken(c.req, self.cfg.header_name) orelse return .{
            .deny = .{ .status = .unauthorized, .reason = "缺少 Authorization: Bearer <token>" },
        };

        var builder = jwt.Builder{ .key = self.cfg.secret.key, .algorithm = self.cfg.secret.algorithm };
        const decoded = builder.validate(c.arena, token, now) catch |e| return .{
            .deny = .{ .status = .unauthorized, .reason = jwt.message(e) },
        };

        // `sub` 声明（JWT 自带身份，即使没配 keeper 也能拿到）
        if (decoded.payload.get("sub")) |v| {
            switch (v) {
                .string => |s| c.setState(STATE_UID, s) catch {},
                .integer => |n| {
                    const text = std.fmt.allocPrint(c.arena, "{d}", .{n}) catch return .allow;
                    c.setState(STATE_UID, text) catch {};
                },
                else => {},
            }
        }

        if (self.cfg.require_session) {
            if (self.cfg.keeper) |k| {
                switch (k.check(token, now)) {
                    .active => |a| {
                        var active = a;
                        defer active.deinit(k.allocator);
                        // 必须复制进请求 arena：`active` 的内存由 keeper 的分配器持有，deinit 后即失效
                        const client = c.arena.dupe(u8, active.client) catch "";
                        const pwd = c.arena.dupe(u8, active.pwd_tag) catch "";
                        if (client.len > 0) c.setState(STATE_CLIENT, client) catch {};
                        if (pwd.len > 0) c.setState(STATE_PWD, pwd) catch {};
                    },
                    .invalid => return .{
                        .deny = .{ .status = .forbidden, .reason = "会话已失效（已登出 / 已过期 / 被踢线）" },
                    },
                    // 硬口径：存储不可用 / 未配置 → 按纯 JWT 放行
                    .untracked => {},
                }
            }
        }

        return .allow;
    }

    fn isSkipped(self: *const Guard, path: []const u8) bool {
        for (self.cfg.skip_prefixes) |p| {
            if (p.len == 0) continue;
            if (std.mem.startsWith(u8, path, p)) return true;
        }
        return false;
    }

    fn invoke(
        ptr: ?*anyopaque,
        c: *router.Ctx,
        next: router.Next,
    ) anyerror!router.Response {
        const self: *Guard = @ptrCast(@alignCast(ptr orelse return next.run(c)));
        switch (self.authorize(c, nowSeconds())) {
            .allow, .anonymous => return next.run(c),
            .deny => |d| return denyResponse(c, d),
        }
    }
};

fn denyResponse(c: *router.Ctx, d: Outcome.Deny) router.Response {
    const body = std.fmt.allocPrint(
        c.arena,
        "{{\"code\":{d},\"message\":\"{s}\"}}",
        .{ @backingInt(d.status), d.reason },
    ) catch "{\"code\":401,\"message\":\"Unauthorized\"}";
    return router.Response.jsonStatus(d.status, body);
}

/// 从请求头取 `Bearer` 令牌（scheme 大小写不敏感）。
fn extractToken(req: router.Request, header_name: []const u8) ?[]const u8 {
    const raw = req.header(header_name) orelse return null;
    const value = std.mem.trim(u8, raw, " \t");
    const sep = std.mem.indexOfScalar(u8, value, ' ') orelse return null;
    if (!std.ascii.eqlIgnoreCase(value[0..sep], "bearer")) return null;
    const token = std.mem.trim(u8, value[sep + 1 ..], " \t");
    return if (token.len == 0) null else token;
}

/// 当前 Unix 秒（复用 zzig，不重复造）。
fn nowSeconds() i64 {
    return zzig.DateTime.nowUnix();
}

// ————— 测试 —————

const TEST_SECRET = "HS256:http-auth-test-key";

fn testCtx(arena: std.mem.Allocator, path: []const u8, bearer: ?[]const u8) !router.Ctx {
    var headers_buf: [1]std.http.Header = undefined;
    const headers: []const std.http.Header = if (bearer) |b| blk: {
        headers_buf[0] = .{ .name = "authorization", .value = b };
        break :blk headers_buf[0..1];
    } else &.{};
    return router.Ctx{ .arena = arena, .req = .{ .method = "GET", .path = path, .headers = headers } };
}

test "http_auth：豁免路径放行且不写状态" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var guard = Guard.init(.{ .secret = try jwt.parseSecret(TEST_SECRET) });
    var c = try testCtx(a, "/health/live", null);

    try std.testing.expectEqual(Outcome.anonymous, guard.authorize(&c, 1000));
    try std.testing.expect(c.stateValue(STATE_UID) == null);
}

test "http_auth：缺令牌 / 非 Bearer / 坏签名 / 过期 一律 401" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var guard = Guard.init(.{ .secret = try jwt.parseSecret(TEST_SECRET) });

    // 缺令牌
    {
        var c = try testCtx(a, "/api/secret", null);
        const o = guard.authorize(&c, 1000);
        try std.testing.expect(o == .deny);
        try std.testing.expectEqual(std.http.Status.unauthorized, o.deny.status);
    }
    // 非 Bearer
    {
        var c = try testCtx(a, "/api/secret", "Basic dXNlcjpwYXNz");
        try std.testing.expectEqual(std.http.Status.unauthorized, guard.authorize(&c, 1000).deny.status);
    }
    // 格式对但签名不对（拿别的密钥签）
    {
        var other = try jwt.Builder.fromSecret("HS256:another-key");
        const bad = try other.encodeVerbatim(a, "{\"sub\":\"42\"}");
        var c = try testCtx(a, "/api/secret", try std.fmt.allocPrint(a, "Bearer {s}", .{bad}));
        const o = guard.authorize(&c, 1000);
        try std.testing.expectEqual(std.http.Status.unauthorized, o.deny.status);
        try std.testing.expectEqualStrings("签名验证失败", o.deny.reason);
    }
    // 过期
    {
        var b = try jwt.Builder.fromSecret(TEST_SECRET);
        const expired = try b.encodeVerbatim(a, "{\"sub\":\"42\",\"exp\":1000}");
        var c = try testCtx(a, "/api/secret", try std.fmt.allocPrint(a, "Bearer {s}", .{expired}));
        const o = guard.authorize(&c, 5000);
        try std.testing.expectEqual(std.http.Status.unauthorized, o.deny.status);
        try std.testing.expectEqualStrings("令牌已过期", o.deny.reason);
    }
}

test "http_auth：验签通过 → allow 且写入 auth.uid；scheme 大小写不敏感" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var guard = Guard.init(.{ .secret = try jwt.parseSecret(TEST_SECRET) });

    var b = try jwt.Builder.fromSecret(TEST_SECRET);
    const token = try b.encodeVerbatim(a, "{\"sub\":\"42\"}");
    var c = try testCtx(a, "/api/secret", try std.fmt.allocPrint(a, "bearer {s}", .{token}));

    try std.testing.expectEqual(Outcome.allow, guard.authorize(&c, 1000));
    try std.testing.expectEqualStrings("42", c.stateValue(STATE_UID).?);
}

test "http_auth：会话被踢线 → 403；存储不可用（untracked）→ 放行" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var b = try jwt.Builder.fromSecret(TEST_SECRET);
    const token = try b.encodeVerbatim(a, "{\"sub\":\"42\"}");

    // ① 没有存储 → untracked → 放行（硬口径）
    {
        var keeper = session.Keeper.init(a, null, "", .{});
        var guard = Guard.init(.{
            .secret = try jwt.parseSecret(TEST_SECRET),
            .keeper = &keeper,
        });
        var c = try testCtx(a, "/api/secret", try std.fmt.allocPrint(a, "Bearer {s}", .{token}));
        try std.testing.expectEqual(Outcome.allow, guard.authorize(&c, 1000));
    }

    // ② 内存存储里登记后登出 → invalid → 403
    {
        var mem = session.MemoryStore.init(a);
        defer mem.deinit();
        const store = mem.store();

        var keeper = session.Keeper.init(a, store, "", .{});
        try std.testing.expect(keeper.register(token, 42, "pwd-tag", "web", 1000));

        var guard = Guard.init(.{
            .secret = try jwt.parseSecret(TEST_SECRET),
            .keeper = &keeper,
        });

        // 登记后一次：active → 放行，并写入 client / pwd
        {
            var c = try testCtx(a, "/api/secret", try std.fmt.allocPrint(a, "Bearer {s}", .{token}));
            try std.testing.expectEqual(Outcome.allow, guard.authorize(&c, 1000));
            try std.testing.expectEqualStrings("web", c.stateValue(STATE_CLIENT).?);
            try std.testing.expectEqualStrings("pwd-tag", c.stateValue(STATE_PWD).?);
        }

        // 登出后再来：invalid → 403
        try std.testing.expect(keeper.revoke(token, 1000));
        {
            var c = try testCtx(a, "/api/secret", try std.fmt.allocPrint(a, "Bearer {s}", .{token}));
            const o = guard.authorize(&c, 1000);
            try std.testing.expect(o == .deny);
            try std.testing.expectEqual(std.http.Status.forbidden, o.deny.status);
        }
    }
}
