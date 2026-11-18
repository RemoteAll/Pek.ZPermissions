//! Redis 后端：一套 Redis，两种口径。
//!
//! | 口径 | 键 | 值 | 谁读 |
//! |---|---|---|---|
//! | Rust `Pek.RPermissions::session` | `{prefix}session:{sha256(token)}` | `{"uid","pwd","client","ver","cver","iat","abs","exp"}` | Rust / Zig |
//! | C# `Pek.Permissions.JsonWebTokenStore` | `jwt:token:access:{token}` + `jwt:token:bind:{refresh}` + `jwt:user:tokens:{uid}` | `JsonWebToken` 的 JSON（**毫秒**时间戳） | C# |
//!
//! 两种口径互不干扰（键空间不同），可**同时启用**：
//! - [`RedisStore`] 让 Zig/Rust 侧「重启不丢 + 多实例共享 + 可登出/踢线」；
//! - [`CSharpMirror`] 让 C# 侧（`ExistsToken` / `GetCompleteTokenInfo`）也能识别这些会话，
//!   反之 C# 登出删掉 `jwt:token:access:*` 后，Zig 侧也能通过 `exists` 感知。
//!
//! C# 侧依据（已核实的本地源码）：
//! - `JsonWebTokenStore.cs:279` `GetTokenKey => $"jwt:token:access:{token}"`
//! - `JsonWebTokenStore.cs:273` `GetRefreshTokenKey => $"jwt:token:refresh:{token}"`
//! - `JsonWebTokenStore.cs:285` `GetBindRefreshTokenKey => $"jwt:token:bind:{token}"`
//! - `GetUserTokensKey => $"jwt:user:tokens:{userId}"`，且**Redis 模式下也是普通字符串**
//!   （`AddUserTokenForRedis` 用 `_cache.Get<HashSet<String>>` + `_cache.Set(...)`，
//!   落库是 JSON 数组，**不是** Redis SET 类型）
//! - `Pek.Common\Security\JsonWebToken.cs` 字段：`UId` / `AccessToken` / `AccessTokenUtcExpires` /
//!   `RefreshToken` / `RefreshUtcExpires` / `StartTime`；其中 `AccessTokenUtcExpires` 与 `StartTime`
//!   都是**毫秒**时间戳（`ToJsGetTime()` / `UnixTime.ToTimestamp()` 默认含毫秒）
//! - `JsonWebTokenStore.cs:190` `ExistsToken => _cache.ContainsKey(GetTokenKey(token))`（只判键存在）
//!
//! 注意：`JsonWebToken` 的值格式按上述字段名与单位构造；C# 侧反序列化（NewLife FastJson）字段名
//! 大小写不敏感，故 PascalCase 一定可读。**未在真实 Redis + 真实 C# 进程上对拍过**（本机无 Redis），
//! 首次接生产前请跑一次 `tools/redis-check.ps1` 对拍。

const std = @import("std");
const redis = @import("redis.zig");
const session = @import("session.zig");

pub const Store = session.Store;

// ---------- Rust 口径 ----------

/// Rust 口径的 Redis 存储（键 `{prefix}session:{sha256}` + `{prefix}userver:*` + `{prefix}sessions:{uid}`）。
pub const RedisStore = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    host: []const u8,
    port: u16,
    mutex: std.Thread.Mutex = .{},
    /// 最近一次操作是否成功（失败后进入「不可用」→ Keeper 退回纯 JWT 放行）
    up: bool = true,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, host: []const u8, port: u16) RedisStore {
        return .{ .allocator = allocator, .io = io, .host = host, .port = port };
    }

    pub fn store(self: *RedisStore) Store {
        return .{ .ptr = self, .vtable = &vtable };
    }

    /// 主动探活（`PING`），用于启动自检。
    pub fn ping(self: *RedisStore) bool {
        var c = redis.Client.connect(self.allocator, self.io, self.host, self.port) catch {
            self.setUp(false);
            return false;
        };
        defer c.deinit();
        const ok = c.ping();
        self.setUp(ok);
        return ok;
    }

    fn setUp(self: *RedisStore, up: bool) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.up = up;
    }

    fn connect(self: *RedisStore) ?redis.Client {
        const c = redis.Client.connect(self.allocator, self.io, self.host, self.port) catch {
            self.setUp(false);
            return null;
        };
        self.setUp(true);
        return c;
    }

    const vtable = Store.VTable{
        .available = availableFn,
        .get = getFn,
        .set = setFn,
        .del = delFn,
        .sadd = saddFn,
        .srem = sremFn,
        .smembers = smembersFn,
    };

    fn availableFn(ptr: *anyopaque) bool {
        const self: *RedisStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.up;
    }

    fn getFn(ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8, now: i64) ?[]u8 {
        _ = allocator;
        _ = now;
        const self: *RedisStore = @ptrCast(@alignCast(ptr));
        const c = self.connect() orelse return null;
        var client = c;
        defer client.deinit();
        return client.get(key) catch {
            self.setUp(false);
            return null;
        };
    }

    fn setFn(ptr: *anyopaque, key: []const u8, value: []const u8, ttl_secs: i64) bool {
        const self: *RedisStore = @ptrCast(@alignCast(ptr));
        var c = self.connect() orelse return false;
        defer c.deinit();
        const ok = c.set(key, value, ttl_secs);
        self.setUp(ok);
        return ok;
    }

    fn delFn(ptr: *anyopaque, key: []const u8) bool {
        const self: *RedisStore = @ptrCast(@alignCast(ptr));
        var c = self.connect() orelse return false;
        defer c.deinit();
        const ok = c.del(key);
        self.setUp(true); // DEL 不存在也算命令成功
        return ok;
    }

    fn saddFn(ptr: *anyopaque, key: []const u8, member: []const u8, ttl_secs: i64) bool {
        const self: *RedisStore = @ptrCast(@alignCast(ptr));
        var c = self.connect() orelse return false;
        defer c.deinit();

        var reply = c.cmd(&.{ "SADD", key, member }) catch {
            self.setUp(false);
            return false;
        };
        reply.deinit(self.allocator);
        const added = switch (reply) {
            .int => |n| n >= 0,
            else => false,
        };
        if (added and ttl_secs > 0) {
            var ttl_buf: [24]u8 = undefined;
            const ttl_text = std.fmt.bufPrint(&ttl_buf, "{d}", .{ttl_secs}) catch return added;
            var expire = c.cmd(&.{ "EXPIRE", key, ttl_text }) catch return added;
            expire.deinit(self.allocator);
        }
        self.setUp(true);
        return added;
    }

    fn sremFn(ptr: *anyopaque, key: []const u8, member: []const u8) bool {
        const self: *RedisStore = @ptrCast(@alignCast(ptr));
        var c = self.connect() orelse return false;
        defer c.deinit();
        var reply = c.cmd(&.{ "SREM", key, member }) catch {
            self.setUp(false);
            return false;
        };
        reply.deinit(self.allocator);
        self.setUp(true);
        return switch (reply) {
            .int => |n| n > 0,
            else => false,
        };
    }

    fn smembersFn(ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8) ?[][]u8 {
        const self: *RedisStore = @ptrCast(@alignCast(ptr));
        var c = self.connect() orelse return null;
        defer c.deinit();

        var reply = c.cmd(&.{ "SMEMBERS", key }) catch {
            self.setUp(false);
            return null;
        };
        defer reply.deinit(self.allocator);

        var out = std.ArrayList([]u8).empty;
        switch (reply) {
            .array => |items| {
                for (items) |item| {
                    const text = item.bulk orelse continue;
                    const copy = allocator.dupe(u8, text) catch {
                        for (out.items) |m| allocator.free(m);
                        out.deinit(allocator);
                        return null;
                    };
                    out.append(allocator, copy) catch {
                        allocator.free(copy);
                        for (out.items) |m| allocator.free(m);
                        out.deinit(allocator);
                        return null;
                    };
                }
            },
            else => return null,
        }
        self.setUp(true);
        return out.toOwnedSlice(allocator) catch null;
    }
};

// ---------- C# 口径 ----------

/// C# `JsonWebTokenStore` 的键空间镜像（双写 / 双检）。
pub const CSharpMirror = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    host: []const u8,
    port: u16,

    /// C# 侧时间戳单位：**毫秒**（`ToJsGetTime()` / `UnixTime.ToTimestamp()` 默认含毫秒）
    pub const TimestampUnit = enum { millis, secs };

    pub fn init(allocator: std.mem.Allocator, io: std.Io, host: []const u8, port: u16) CSharpMirror {
        return .{ .allocator = allocator, .io = io, .host = host, .port = port };
    }

    pub const AccessKeyPrefix = "jwt:token:access:";
    pub const BindKeyPrefix = "jwt:token:bind:";
    pub const RefreshKeyPrefix = "jwt:token:refresh:";
    pub const UserTokensPrefix = "jwt:user:tokens:";

    /// 写入 C# 口径的访问令牌记录（对齐 `JsonWebTokenStore.SaveToken`）。
    ///
    /// - `access_expires_unix`：访问令牌到期时刻（Unix 秒；内部按毫秒写入）
    /// - `refresh_token` / `refresh_expires_unix`：可空（空则按 C# 的空串/0 写入）
    pub fn saveAccess(
        self: *const CSharpMirror,
        token: []const u8,
        uid: i32,
        issued_unix: i64,
        access_expires_unix: i64,
        refresh_token: []const u8,
        refresh_expires_unix: i64,
    ) bool {
        var c = redis.Client.connect(self.allocator, self.io, self.host, self.port) catch return false;
        defer c.deinit();

        const value = buildAccessValue(
            self.allocator,
            token,
            uid,
            issued_unix,
            access_expires_unix,
            refresh_token,
            refresh_expires_unix,
        ) orelse return false;
        defer self.allocator.free(value);

        const ttl = @max(access_expires_unix - issued_unix, 1);
        if (!c.set(try self.key(AccessKeyPrefix, token), value, ttl)) return false;

        if (refresh_token.len > 0) {
            _ = c.set(self.key(BindKeyPrefix, refresh_token) catch return false, value, ttl);
        }

        // 用户令牌关联：C# 在 Redis 模式下也是**普通字符串（JSON 数组）**
        if (uid > 0) {
            self.addUserToken(&c, uid, token, ttl + 3600);
        }
        return true;
    }

    /// 对应 C# `ExistsToken`（只判键存在）。
    pub fn exists(self: *const CSharpMirror, token: []const u8) bool {
        var c = redis.Client.connect(self.allocator, self.io, self.host, self.port) catch return false;
        defer c.deinit();
        return c.exists(self.key(AccessKeyPrefix, token) catch return false);
    }

    /// 对应 C# `GetToken`（读原始 JSON 值，调用方 free）。
    pub fn getValue(self: *const CSharpMirror, token: []const u8) ?[]u8 {
        var c = redis.Client.connect(self.allocator, self.io, self.host, self.port) catch return null;
        defer c.deinit();
        return c.get(self.key(AccessKeyPrefix, token) catch return null) catch null;
    }

    /// 对应 C# `RemoveToken`（删 access / bind，并从用户令牌数组移除）。
    pub fn remove(self: *const CSharpMirror, token: []const u8) bool {
        var c = redis.Client.connect(self.allocator, self.io, self.host, self.port) catch return false;
        defer c.deinit();

        const access_key = self.key(AccessKeyPrefix, token) catch return false;
        defer self.allocator.free(access_key);

        // 先读出来拿 UId / RefreshToken（与 C# `RemoveTokenInternal` 一致）
        var uid: i32 = 0;
        var refresh_token: []u8 = &.{};
        const maybe = c.get(access_key) catch null;
        if (maybe) |text| {
            defer self.allocator.free(text);
            if (self.parseRecord(self.allocator, text)) |info| {
                uid = info.uid;
                if (info.refresh_token.len > 0) {
                    refresh_token = self.allocator.dupe(u8, info.refresh_token) catch &.{};
                }
                info.deinit(self.allocator);
            }
        }
        defer if (refresh_token.len > 0) self.allocator.free(refresh_token);

        _ = c.del(access_key);
        if (refresh_token.len > 0) {
            const bind_key = self.key(BindKeyPrefix, refresh_token) catch return true;
            defer self.allocator.free(bind_key);
            _ = c.del(bind_key);
        }
        if (uid > 0) self.removeUserToken(&c, uid, token);
        return true;
    }

    /// 探活。
    pub fn ping(self: *const CSharpMirror) bool {
        var c = redis.Client.connect(self.allocator, self.io, self.host, self.port) catch return false;
        defer c.deinit();
        return c.ping();
    }

    // ---------- 内部 ----------

    pub const Record = struct {
        uid: i32,
        refresh_token: []u8,

        pub fn deinit(self: Record, allocator: std.mem.Allocator) void {
            allocator.free(self.refresh_token);
        }
    };

    /// 解析 C# `JsonWebToken` 的 JSON（容错：字段缺失按 0/空处理）。
    /// 返回的记录由调用方 `deinit`。
    pub fn parseRecord(self: *const CSharpMirror, allocator: std.mem.Allocator, text: []const u8) ?Record {
        _ = self;
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        const parsed = std.json.parseFromSliceLeaky(std.json.Value, a, text, .{}) catch return null;
        const obj = switch (parsed) {
            .object => |m| m,
            else => return null,
        };

        var uid: i32 = 0;
        if (obj.get("UId")) |v| {
            switch (v) {
                .integer => |i| uid = @intCast(i),
                else => {},
            }
        }

        var refresh: []const u8 = "";
        if (obj.get("RefreshToken")) |v| {
            switch (v) {
                .string => |s| refresh = s,
                else => {},
            }
        }

        return .{ .uid = uid, .refresh_token = allocator.dupe(u8, refresh) catch return null };
    }

    fn key(self: *const CSharpMirror, prefix: []const u8, suffix: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}{s}", .{ prefix, suffix });
    }

    fn addUserToken(self: *const CSharpMirror, c: *redis.Client, uid: i32, token: []const u8, ttl: i64) void {
        self.mutateUserTokens(c, uid, token, .add, ttl);
    }

    fn removeUserToken(self: *const CSharpMirror, c: *redis.Client, uid: i32, token: []const u8) void {
        self.mutateUserTokens(c, uid, token, .remove, 0);
    }

    const Mode = enum { add, remove };

    fn mutateUserTokens(self: *const CSharpMirror, c: *redis.Client, uid: i32, token: []const u8, mode: Mode, ttl: i64) void {
        const user_tokens_key = std.fmt.allocPrint(self.allocator, "{s}{d}", .{ UserTokensPrefix, uid }) catch return;
        defer self.allocator.free(user_tokens_key);

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var tokens = std.ArrayList([]const u8).empty;
        defer tokens.deinit(a);

        const maybe = c.get(user_tokens_key) catch null;
        if (maybe) |text| {
            defer self.allocator.free(text);
            const parsed = std.json.parseFromSliceLeaky(std.json.Value, a, text, .{}) catch null;
            if (parsed) |v| {
                switch (v) {
                    .array => |items| {
                        for (items) |item| {
                            switch (item) {
                                .string => |s| tokens.append(a, s) catch {},
                                else => {},
                            }
                        }
                    },
                    else => {},
                }
            }
        }

        switch (mode) {
            .add => {
                var duplicated = false;
                for (tokens.items) |t| {
                    if (std.mem.eql(u8, t, token)) {
                        duplicated = true;
                        break;
                    }
                }
                if (!duplicated) tokens.append(a, token) catch return;
            },
            .remove => {
                var i: usize = 0;
                while (i < tokens.items.len) {
                    if (std.mem.eql(u8, tokens.items[i], token)) {
                        _ = tokens.orderedRemove(i);
                    } else {
                        i += 1;
                    }
                }
                if (tokens.items.len == 0) {
                    _ = c.del(user_tokens_key);
                    return;
                }
            },
        }

        // 构造 JSON 数组（与 C# `HashSet<String>` 的 `ToJson()` 同形）
        var out = std.ArrayList(u8).empty;
        defer out.deinit(self.allocator);
        out.append(self.allocator, '[') catch return;
        for (tokens.items, 0..) |t, idx| {
            if (idx > 0) out.append(self.allocator, ',') catch return;
            out.append(self.allocator, '"') catch return;
            for (t) |ch| {
                switch (ch) {
                    '"' => out.appendSlice(self.allocator, "\\\"") catch return,
                    '\\' => out.appendSlice(self.allocator, "\\\\") catch return,
                    else => out.append(self.allocator, ch) catch return,
                }
            }
            out.append(self.allocator, '"') catch return;
        }
        out.append(self.allocator, ']') catch return;

        _ = c.set(user_tokens_key, out.items, ttl);
    }
};

/// 构造 C# `JsonWebToken` 的记录值（对齐 `Pek.Common\Security\JsonWebToken.cs` 的字段与单位）。
///
/// - 字段名用**属性名原样**（PascalCase）：NewLife 的 JSON 读取大小写不敏感，PascalCase 一定可读；
/// - `AccessTokenUtcExpires` / `StartTime` 为**毫秒**（`ToJsGetTime()` / `UnixTime.ToTimestamp()` 默认含毫秒）；
/// - `RefreshToken` 为空时写空串、`RefreshUtcExpires` 写 0（与 C# 的默认值一致）。
pub fn buildAccessValue(
    allocator: std.mem.Allocator,
    token: []const u8,
    uid: i32,
    issued_unix: i64,
    access_expires_unix: i64,
    refresh_token: []const u8,
    refresh_expires_unix: i64,
) ?[]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{{\"UId\":{d},\"AccessToken\":\"{s}\",\"AccessTokenUtcExpires\":{d},\"RefreshToken\":\"{s}\",\"RefreshUtcExpires\":{d},\"StartTime\":{d}}}",
        .{
            uid,
            token,
            access_expires_unix * 1000,
            refresh_token,
            if (refresh_expires_unix > 0) refresh_expires_unix * 1000 else 0,
            issued_unix * 1000,
        },
    ) catch null;
}

// ---------- 测试 ----------

test "csharp-mirror: 访问令牌记录格式（对齐 JsonWebToken 字段与毫秒单位）" {
    const allocator = std.testing.allocator;
    const value = buildAccessValue(allocator, "H.P.S", 42, 1794992609, 1794999809, "", 0) orelse
        return error.OutOfMemory;
    defer allocator.free(value);

    try std.testing.expectEqualStrings(
        "{\"UId\":42,\"AccessToken\":\"H.P.S\",\"AccessTokenUtcExpires\":1794999809000,\"RefreshToken\":\"\",\"RefreshUtcExpires\":0,\"StartTime\":1794992609000}",
        value,
    );
}

test "csharp-mirror: 带刷新令牌时填入对应字段" {
    const allocator = std.testing.allocator;
    const value = buildAccessValue(allocator, "H.P.S", 7, 1000, 2000, "R.S.T", 3000) orelse
        return error.OutOfMemory;
    defer allocator.free(value);

    try std.testing.expect(std.mem.indexOf(u8, value, "\"RefreshToken\":\"R.S.T\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, value, "\"RefreshUtcExpires\":3000000") != null);
}

test "csharp-mirror: 键前缀与 C# 源码一致" {
    // 依据：JsonWebTokenStore.cs:273/279/285 与 GetUserTokensKey
    try std.testing.expectEqualStrings("jwt:token:access:", CSharpMirror.AccessKeyPrefix);
    try std.testing.expectEqualStrings("jwt:token:refresh:", CSharpMirror.RefreshKeyPrefix);
    try std.testing.expectEqualStrings("jwt:token:bind:", CSharpMirror.BindKeyPrefix);
    try std.testing.expectEqualStrings("jwt:user:tokens:", CSharpMirror.UserTokensPrefix);
}
