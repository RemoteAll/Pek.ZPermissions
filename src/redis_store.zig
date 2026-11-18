//! Redis 后端（多实例共享）——**复用 `Pek.ZRedis`**（对齐 C# `DH.NRedis` / Rust `Pek.RRedis`），
//! 本仓库不重复实现 RESP。
//!
//! 两套键空间，互不干扰，可同时启用：
//!
//! | 口径 | 键 | 值 | 谁读 |
//! |---|---|---|---|
//! | Rust `Pek.RPermissions::session` | `{prefix}session:{sha256(token)}` | `{"uid","pwd","client","ver","cver","iat","abs","exp"}` | Rust / Zig |
//! | C# `Pek.Permissions.JsonWebTokenStore` | `jwt:token:access:{token}`、`jwt:token:bind:{refresh}`、`jwt:user:tokens:{uid}` | `JsonWebToken` 的 JSON（**毫秒**时间戳） | C# |
//!
//! C# 侧依据（已核实的本地源码）：
//! - `JsonWebTokenStore.cs:273/279/285`：`jwt:token:refresh:` / `jwt:token:access:` / `jwt:token:bind:`
//! - `GetUserTokensKey => $"jwt:user:tokens:{userId}"`，且 **Redis 模式下也是普通字符串**
//!   （`AddUserTokenForRedis` 用 `Get<HashSet<String>>` + `Set(...)`，落库是 JSON 数组，**不是** Redis SET）
//! - `Pek.Common\Security\JsonWebToken.cs`：`UId` / `AccessToken` / `AccessTokenUtcExpires` /
//!   `RefreshToken` / `RefreshUtcExpires` / `StartTime`；后两者与 `StartTime` 均为**毫秒**
//! - `JsonWebTokenStore.cs:190` `ExistsToken => _cache.ContainsKey(GetTokenKey(token))`（只判键存在）

const std = @import("std");
const zredis = @import("pek_zredis");
const session = @import("session.zig");

pub const Store = session.Store;

/// 把一条命令发给 Redis 并返回原始回复；调用方负责 `v.deinit(gpa)`。
fn exec(client: *zredis.Redis, args: []const []const u8) ?zredis.Value {
    return client.execute(args) catch null;
}

// ---------- Rust 口径 ----------

/// Rust 口径的 Redis 存储（键 `{prefix}session:{sha256}` + `{prefix}userver:*` + `{prefix}sessions:{uid}`）。
pub const RedisStore = struct {
    allocator: std.mem.Allocator,
    client: zredis.Redis,
    mutex: session.SpinLock = .{},
    /// 最近一次操作是否成功（失败后进入「不可用」→ Keeper 退回纯 JWT 放行）
    up: bool = true,

    /// 连接。`server` 用 Pek.ZRedis 的连接串口径（如 `127.0.0.1:6379`）。
    pub fn open(
        allocator: std.mem.Allocator,
        io: std.Io,
        server: []const u8,
        password: ?[]const u8,
        db: i32,
    ) !RedisStore {
        const client = try zredis.Redis.open(allocator, io, server, password, db);
        return .{ .allocator = allocator, .client = client };
    }

    pub fn deinit(self: *RedisStore) void {
        self.client.deinit();
        self.* = undefined;
    }

    pub fn store(self: *RedisStore) Store {
        return .{ .ptr = self, .vtable = &vtable };
    }

    /// 探活（`PING`）。
    pub fn ping(self: *RedisStore) bool {
        var v = exec(&self.client, &.{"PING"}) orelse {
            self.setUp(false);
            return false;
        };
        defer v.deinit(self.allocator);
        const ok = v != .err;
        self.setUp(ok);
        return ok;
    }

    fn setUp(self: *RedisStore, up: bool) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.up = up;
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
        _ = now; // TTL 由 Redis 自己维护
        const self: *RedisStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return null;

        var v = exec(&self.client, &.{ "GET", key }) orelse {
            self.up = false;
            return null;
        };
        defer v.deinit(self.allocator);
        return switch (v) {
            .bulk => |b| allocator.dupe(u8, b) catch null,
            else => null,
        };
    }

    fn setFn(ptr: *anyopaque, key: []const u8, value: []const u8, ttl_secs: i64, now: i64) bool {
        _ = now;
        const self: *RedisStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return false;

        var ttl_buf: [24]u8 = undefined;
        const ok = if (ttl_secs > 0) blk: {
            const ttl_text = std.fmt.bufPrint(&ttl_buf, "{d}", .{ttl_secs}) catch return false;
            var v = exec(&self.client, &.{ "SET", key, value, "EX", ttl_text }) orelse break :blk false;
            defer v.deinit(self.allocator);
            break :blk v != .err;
        } else blk: {
            var v = exec(&self.client, &.{ "SET", key, value }) orelse break :blk false;
            defer v.deinit(self.allocator);
            break :blk v != .err;
        };
        self.up = ok;
        return ok;
    }

    fn delFn(ptr: *anyopaque, key: []const u8) bool {
        const self: *RedisStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return false;

        var v = exec(&self.client, &.{ "DEL", key }) orelse {
            self.up = false;
            return false;
        };
        defer v.deinit(self.allocator);
        return (v.asInt() orelse 0) > 0;
    }

    fn saddFn(ptr: *anyopaque, key: []const u8, member: []const u8, ttl_secs: i64, now: i64) bool {
        _ = now;
        const self: *RedisStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return false;

        var v = exec(&self.client, &.{ "SADD", key, member }) orelse {
            self.up = false;
            return false;
        };
        defer v.deinit(self.allocator);
        if (v == .err) return false;

        if (ttl_secs > 0) {
            var ttl_buf: [24]u8 = undefined;
            const ttl_text = std.fmt.bufPrint(&ttl_buf, "{d}", .{ttl_secs}) catch return true;
            if (exec(&self.client, &.{ "EXPIRE", key, ttl_text })) |ev| {
                var e = ev;
                e.deinit(self.allocator);
            }
        }
        return true;
    }

    fn sremFn(ptr: *anyopaque, key: []const u8, member: []const u8) bool {
        const self: *RedisStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return false;

        var v = exec(&self.client, &.{ "SREM", key, member }) orelse {
            self.up = false;
            return false;
        };
        defer v.deinit(self.allocator);
        return (v.asInt() orelse 0) > 0;
    }

    fn smembersFn(ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8) ?[][]u8 {
        const self: *RedisStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return null;

        var v = exec(&self.client, &.{ "SMEMBERS", key }) orelse {
            self.up = false;
            return null;
        };
        defer v.deinit(self.allocator);

        var out = std.ArrayList([]u8).empty;
        switch (v) {
            .array, .set => |items| {
                for (items) |item| {
                    const text = switch (item) {
                        .bulk => |b| b,
                        else => continue,
                    };
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
        return out.toOwnedSlice(allocator) catch null;
    }
};

// ---------- C# 口径 ----------

pub const CSharpMirror = struct {
    allocator: std.mem.Allocator,
    client: zredis.Redis,
    mutex: session.SpinLock = .{},

    pub const AccessKeyPrefix = "jwt:token:access:";
    pub const BindKeyPrefix = "jwt:token:bind:";
    pub const RefreshKeyPrefix = "jwt:token:refresh:";
    pub const UserTokensPrefix = "jwt:user:tokens:";

    pub fn open(
        allocator: std.mem.Allocator,
        io: std.Io,
        server: []const u8,
        password: ?[]const u8,
        db: i32,
    ) !CSharpMirror {
        const client = try zredis.Redis.open(allocator, io, server, password, db);
        return .{ .allocator = allocator, .client = client };
    }

    pub fn deinit(self: *CSharpMirror) void {
        self.client.deinit();
        self.* = undefined;
    }

    pub const Record = struct {
        uid: i32,
        refresh_token: []u8,

        pub fn deinit(self: Record, allocator: std.mem.Allocator) void {
            allocator.free(self.refresh_token);
        }
    };

    /// 写入访问令牌记录（对齐 C# `JsonWebTokenStore.SaveToken`）。
    pub fn saveAccess(
        self: *CSharpMirror,
        token: []const u8,
        uid: i32,
        issued_unix: i64,
        access_expires_unix: i64,
        refresh_token: []const u8,
        refresh_expires_unix: i64,
    ) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

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
        const access_key = std.fmt.allocPrint(self.allocator, "{s}{s}", .{ AccessKeyPrefix, token }) catch return false;
        defer self.allocator.free(access_key);

        if (!self.setKey(access_key, value, ttl)) return false;

        if (refresh_token.len > 0) {
            const bind_key = std.fmt.allocPrint(self.allocator, "{s}{s}", .{ BindKeyPrefix, refresh_token }) catch return false;
            defer self.allocator.free(bind_key);
            _ = self.setKey(bind_key, value, ttl);
        }

        if (uid > 0) self.mutateUserTokens(uid, token, .add, ttl + 3600);
        return true;
    }

    /// 对应 C# `ExistsToken`（只判键存在）。
    pub fn exists(self: *CSharpMirror, token: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const key = std.fmt.allocPrint(self.allocator, "{s}{s}", .{ AccessKeyPrefix, token }) catch return false;
        defer self.allocator.free(key);

        var v = exec(&self.client, &.{ "EXISTS", key }) orelse return false;
        defer v.deinit(self.allocator);
        return (v.asInt() orelse 0) > 0;
    }

    /// 对应 C# `GetToken`（读原始 JSON，调用方 free）。
    pub fn getValue(self: *CSharpMirror, token: []const u8) ?[]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const key = std.fmt.allocPrint(self.allocator, "{s}{s}", .{ AccessKeyPrefix, token }) catch return null;
        defer self.allocator.free(key);

        var v = exec(&self.client, &.{ "GET", key }) orelse return null;
        defer v.deinit(self.allocator);
        return switch (v) {
            .bulk => |b| self.allocator.dupe(u8, b) catch null,
            else => null,
        };
    }

    /// 对应 C# `RemoveToken`（删 access / bind，并从用户令牌数组移除）。
    pub fn remove(self: *CSharpMirror, token: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const access_key = std.fmt.allocPrint(self.allocator, "{s}{s}", .{ AccessKeyPrefix, token }) catch return false;
        defer self.allocator.free(access_key);

        var uid: i32 = 0;
        var refresh_token: []u8 = &.{};
        defer if (refresh_token.len > 0) self.allocator.free(refresh_token);

        if (self.getValueLocked(access_key)) |text| {
            defer self.allocator.free(text);
            if (self.parseRecord(self.allocator, text)) |info| {
                uid = info.uid;
                if (info.refresh_token.len > 0) {
                    refresh_token = self.allocator.dupe(u8, info.refresh_token) catch &.{};
                }
                info.deinit(self.allocator);
            }
        }

        _ = self.delKey(access_key);

        if (refresh_token.len > 0) {
            const bind_key = std.fmt.allocPrint(self.allocator, "{s}{s}", .{ BindKeyPrefix, refresh_token }) catch return true;
            defer self.allocator.free(bind_key);
            _ = self.delKey(bind_key);
        }
        if (uid > 0) self.mutateUserTokens(uid, token, .remove, 0);
        return true;
    }

    /// 探活。
    pub fn ping(self: *CSharpMirror) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        var v = exec(&self.client, &.{"PING"}) orelse return false;
        defer v.deinit(self.allocator);
        return v != .err;
    }

    /// 解析 C# `JsonWebToken` 的 JSON（容错：字段缺失按 0/空处理）。返回记录由调用方 `deinit`。
    pub fn parseRecord(self: *CSharpMirror, allocator: std.mem.Allocator, text: []const u8) ?Record {
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

    // ---------- 内部（已持有锁） ----------

    fn getValueLocked(self: *CSharpMirror, key: []const u8) ?[]u8 {
        var v = exec(&self.client, &.{ "GET", key }) orelse return null;
        defer v.deinit(self.allocator);
        return switch (v) {
            .bulk => |b| self.allocator.dupe(u8, b) catch null,
            else => null,
        };
    }

    fn setKey(self: *CSharpMirror, key: []const u8, value: []const u8, ttl: i64) bool {
        var ttl_buf: [24]u8 = undefined;
        const ttl_text = std.fmt.bufPrint(&ttl_buf, "{d}", .{@max(ttl, 1)}) catch return false;
        var v = exec(&self.client, &.{ "SET", key, value, "EX", ttl_text }) orelse return false;
        defer v.deinit(self.allocator);
        return v != .err;
    }

    fn delKey(self: *CSharpMirror, key: []const u8) bool {
        var v = exec(&self.client, &.{ "DEL", key }) orelse return false;
        defer v.deinit(self.allocator);
        return (v.asInt() orelse 0) > 0;
    }

    const Mode = enum { add, remove };

    fn mutateUserTokens(self: *CSharpMirror, uid: i32, token: []const u8, mode: Mode, ttl: i64) void {
        const key = std.fmt.allocPrint(self.allocator, "{s}{d}", .{ UserTokensPrefix, uid }) catch return;
        defer self.allocator.free(key);

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var tokens = std.ArrayList([]const u8).empty;
        defer tokens.deinit(a);

        if (self.getValueLocked(key)) |text| {
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
                    _ = self.delKey(key);
                    return;
                }
            },
        }

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

        _ = self.setKey(key, out.items, ttl);
    }
};

/// 构造 C# `JsonWebToken` 的记录值（对齐 `Pek.Common\Security\JsonWebToken.cs` 的字段与单位）。
///
/// - 字段名用**属性名原样**（PascalCase）：NewLife 的 JSON 读取大小写不敏感；
/// - `AccessTokenUtcExpires` / `StartTime` 为**毫秒**（`ToJsGetTime()` / `UnixTime.ToTimestamp()` 默认含毫秒）；
/// - `RefreshToken` 为空时写空串、`RefreshUtcExpires` 写 0（与 C# 默认值一致）。
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

// ---------- 测试（不依赖真实 Redis） ----------

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
