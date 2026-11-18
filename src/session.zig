//! JWT 会话登记与吊销（**JWT 始终有效；外部存储只做「登记 / 吊销 / 共享」**）。
//!
//! 语义与 Rust `Pek.RPermissions::session` 逐项对齐（键前缀、JSON 字段、滑动续期、两级版本号）。
//!
//! # 为什么需要它
//!
//! JWT 本身无状态：**服务重启不会让令牌失效**。但「登出立即失效 / 按端踢线 / 在线会话列表」
//! 必须靠一份外部记录，而记录若只放内存，重启就丢 → 全站强制重登（C# `JsonWebTokenStore`
//! 用 `ICache` 时正是这个行为）。本模块把这份记录抽象成 [`Store`]，并提供三种实现：
//!
//! | 实现 | 重启后 | 多实例共享 | 依赖 |
//! |---|---|---|---|
//! | [`MemoryStore`] | **丢失** | 否 | 无 |
//! | [`FileStore`] | **保留** | 否（单实例） | 无（JSON + 原子替换） |
//! | `redis_store.RedisStore` | **保留** | **是** | Redis（RESP2） |
//!
//! # 口径
//!
//! 1. 令牌**永远是 JWT**（与 C# / Rust 互认），外部存储**不保存令牌原文**，
//!    只保存「这个令牌还在不在 / 何时到期 / 口令指纹 / 客户端」，键为令牌的 **SHA-256**；
//! 2. 存储不可用 → 自动回到「纯 JWT」模式（验签 + 过期即放行），
//!    **绝不因为缓存挂了把所有人挡在外面**；
//! 3. 存储可用却没有记录 → **拒绝**（这正是「登出即失效」的来源）；
//! 4. 滑动续期只在「剩余不足一半」时写一次，且不越过绝对上限；**不是每请求都写**；
//! 5. 两级版本号（`userver:{uid}` 与 `userver:{uid}:{client}`）实现 O(1) 踢线。

const std = @import("std");
const zzig = @import("zzig");

/// 轻量自旋锁：0.17 的 `std.Io.Mutex.lock` 需要 `io` 参数，而 `Store` 实现拿不到 io；
/// 临界区极短（内存/文件快照读写），自旋 + yield 足够，且无额外依赖。
pub const SpinLock = struct {
    inner: std.atomic.Mutex = .unlocked,

    pub fn lock(self: *SpinLock) void {
        while (!self.inner.tryLock()) {
            std.Thread.yield() catch {};
        }
    }

    pub fn unlock(self: *SpinLock) void {
        self.inner.unlock();
    }
};

/// 存储接口。所有方法失败时返回 `null` / `false`（**不要 panic**，缓存故障不能影响业务）。
pub const Store = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// 存储是否可用（不可用时按「纯 JWT」放行，**不能**当作「已吊销」）。
        available: *const fn (ptr: *anyopaque) bool,
        /// 读取记录；返回的切片由调用方 `allocator.free`。`now` 供实现判断 TTL。
        get: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8, now: i64) ?[]u8,
        /// 写入记录并设置过期（秒；`<=0` 表示不过期）。
        set: *const fn (ptr: *anyopaque, key: []const u8, value: []const u8, ttl_secs: i64, now: i64) bool,
        /// 删除记录（登出）。
        del: *const fn (ptr: *anyopaque, key: []const u8) bool,
        /// 加入集合（可选能力；不支持时留 `null`）。
        sadd: ?*const fn (ptr: *anyopaque, key: []const u8, member: []const u8, ttl_secs: i64, now: i64) bool = null,
        /// 从集合移除（可选能力）。
        srem: ?*const fn (ptr: *anyopaque, key: []const u8, member: []const u8) bool = null,
        /// 读取集合成员（可选能力）；返回的每个成员与数组都由调用方释放。
        smembers: ?*const fn (ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8) ?[][]u8 = null,
    };

    pub fn available(self: Store) bool {
        return self.vtable.available(self.ptr);
    }

    pub fn get(self: Store, allocator: std.mem.Allocator, key: []const u8, now: i64) ?[]u8 {
        return self.vtable.get(self.ptr, allocator, key, now);
    }

    pub fn set(self: Store, key: []const u8, value: []const u8, ttl_secs: i64, now: i64) bool {
        return self.vtable.set(self.ptr, key, value, ttl_secs, now);
    }

    pub fn del(self: Store, key: []const u8) bool {
        return self.vtable.del(self.ptr, key);
    }

    pub fn supportsSets(self: Store) bool {
        return self.vtable.sadd != null and self.vtable.srem != null and self.vtable.smembers != null;
    }

    pub fn sadd(self: Store, key: []const u8, member: []const u8, ttl_secs: i64, now: i64) bool {
        const f = self.vtable.sadd orelse return false;
        return f(self.ptr, key, member, ttl_secs, now);
    }

    pub fn srem(self: Store, key: []const u8, member: []const u8) bool {
        const f = self.vtable.srem orelse return false;
        return f(self.ptr, key, member);
    }

    /// 调用方负责：逐个 `allocator.free(members[i])`，再 `allocator.free(members)`。
    pub fn smembers(self: Store, allocator: std.mem.Allocator, key: []const u8) ?[][]u8 {
        const f = self.vtable.smembers orelse return null;
        return f(self.ptr, allocator, key);
    }
};

/// 会话策略。
pub const Policy = struct {
    /// 空闲有效期（秒）；`<=0` 表示不做滑动续期
    idle_secs: i64 = 7 * 24 * 3600,
    /// 绝对上限（秒）；`<=0` 表示不限制
    max_secs: i64 = 30 * 24 * 3600,
};

/// 会话校验结果。
pub const State = union(enum) {
    /// 存储可用且记录有效（附口令指纹与客户端）
    active: Active,
    /// 存储可用但记录不存在 / 已过期 / 已踢线 → **拒绝**
    invalid,
    /// 存储不可用 → 调用方按「纯 JWT」处理（验签 + 过期）
    untracked,

    pub const Active = struct {
        pwd_tag: []u8,
        client: []u8,

        pub fn deinit(self: Active, allocator: std.mem.Allocator) void {
            allocator.free(self.pwd_tag);
            allocator.free(self.client);
        }
    };
};

/// 一条在线会话（后台展示用）。
pub const SessionInfo = struct {
    client: []u8,
    iat: i64,
    exp: i64,

    pub fn deinit(self: SessionInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.client);
    }
};

/// 会话登记器：把 JWT 与「可撤销」结合起来。
pub const Keeper = struct {
    allocator: std.mem.Allocator,
    store: ?Store,
    key_prefix: []const u8,
    policy: Policy,

    /// 构造。`store = null` 即纯 JWT 模式（不做登记/吊销）。
    pub fn init(
        allocator: std.mem.Allocator,
        store: ?Store,
        key_prefix: []const u8,
        policy: Policy,
    ) Keeper {
        return .{ .allocator = allocator, .store = store, .key_prefix = key_prefix, .policy = policy };
    }

    /// 存储方式（`store` / `jwt`）。
    pub fn storeKind(self: *const Keeper) []const u8 {
        const s = self.store orelse return "jwt";
        return if (s.available()) "store" else "jwt";
    }

    /// **默认放行语义**（推荐所有调用方用这个，而不是自己 switch）：
    /// 只有「存储可用且明确判为无效（登出 / 过期 / 被踢）」才返回 `false`；
    /// 纯 JWT 模式、存储不可用、读写失败一律返回 `true`。
    ///
    /// 这是本库的硬口径：**任何存储问题都不能把用户挡在外面**——
    /// 没配存储重启不掉线、Redis/文件挂掉也不掉线，只有主动登出/踢线才失效。
    pub fn authorize(self: *const Keeper, token: []const u8, now: i64) bool {
        return switch (self.check(token, now)) {
            .active => |a| blk: {
                a.deinit(self.allocator);
                break :blk true;
            },
            .invalid => false,
            .untracked => true,
        };
    }

    /// 登录成功后登记（纯 JWT 模式返回 `false`）。
    pub fn register(
        self: *const Keeper,
        token: []const u8,
        uid: i64,
        pwd_tag: []const u8,
        client: []const u8,
        now: i64,
    ) bool {
        const store = self.store orelse return false;
        if (!store.available()) return false;

        const alloc = self.allocator;
        const abs: i64 = if (self.policy.max_secs > 0) now + self.policy.max_secs else 0;
        const idle: i64 = if (self.policy.idle_secs > 0) self.policy.idle_secs else 0;
        const exp: i64 = if (idle > 0) now + idle else abs;
        const ttl_src = if (idle > 0) idle else abs;
        const ttl = if (ttl_src > 0) ttl_src else 0;

        const key = self.sessionKey(alloc, token) orelse return false;
        defer alloc.free(key);

        const ver = self.version(store, alloc, self.userVerKey(alloc, uid) orelse return false, now);
        const cver = self.version(store, alloc, self.clientVerKey(alloc, uid, client) orelse return false, now);

        const pwd_escaped = escaped(alloc, pwd_tag) orelse return false;
        defer alloc.free(pwd_escaped);
        const client_escaped = escaped(alloc, client) orelse return false;
        defer alloc.free(client_escaped);

        const value = std.fmt.allocPrint(
            alloc,
            "{{\"uid\":{d},\"pwd\":\"{s}\",\"client\":\"{s}\",\"ver\":{d},\"cver\":{d},\"iat\":{d},\"abs\":{d},\"exp\":{d}}}",
            .{ uid, pwd_escaped, client_escaped, ver, cver, now, abs, exp },
        ) catch return false;
        defer alloc.free(value);

        const ok = store.set(key, value, ttl, now);
        if (ok) {
            const index = self.indexKey(alloc, uid) orelse return ok;
            defer alloc.free(index);
            _ = store.sadd(index, key, ttl, now); // 失败不影响登录
        }
        return ok;
    }

    /// 校验登记状态（**不验 JWT 本身**，JWT 由调用方按各自 claim 口径验）。
    pub fn check(self: *const Keeper, token: []const u8, now: i64) State {
        const store = self.store orelse return .untracked;
        if (!store.available()) return .untracked;

        const alloc = self.allocator;
        const key = self.sessionKey(alloc, token) orelse return .untracked;
        defer alloc.free(key);

        const text = store.get(alloc, key, now) orelse {
            // 存储可用却没有记录：已登出 / 已过期 / 被清 → 视为无效
            return .invalid;
        };
        defer alloc.free(text);

        var arena = std.heap.ArenaAllocator.init(alloc);
        defer arena.deinit();
        const a = arena.allocator();

        const parsed = std.json.parseFromSliceLeaky(std.json.Value, a, text, .{}) catch return .invalid;
        const obj = switch (parsed) {
            .object => |m| m,
            else => return .invalid,
        };

        const exp = jsonInt(obj, "exp");
        const abs = jsonInt(obj, "abs");
        if ((exp > 0 and exp <= now) or (abs > 0 and abs <= now)) {
            _ = store.del(key);
            return .invalid;
        }

        const uid = jsonInt(obj, "uid");
        const client = jsonStr(obj, "client");
        const pwd_tag = jsonStr(obj, "pwd");

        // 两级版本校验：全局（所有端）与按端，任一被踢即失效
        if (uid > 0) {
            if (jsonInt(obj, "ver") != self.version(store, a, self.userVerKey(a, uid) orelse return .invalid, now)) {
                _ = store.del(key);
                return .invalid;
            }
            if (jsonInt(obj, "cver") != self.version(store, a, self.clientVerKey(a, uid, client) orelse return .invalid, now)) {
                _ = store.del(key);
                return .invalid;
            }
        }

        // 滑动续期：剩余不足一半才重写，且不越过绝对上限
        if (self.policy.idle_secs > 0 and exp - now < @divFloor(self.policy.idle_secs, 2)) {
            var next = now + self.policy.idle_secs;
            if (abs > 0 and next > abs) next = abs;
            const renewed = std.fmt.allocPrint(
                a,
                "{{\"uid\":{d},\"pwd\":\"{s}\",\"client\":\"{s}\",\"ver\":{d},\"cver\":{d},\"iat\":{d},\"abs\":{d},\"exp\":{d}}}",
                .{ uid, escaped(a, pwd_tag) orelse return .untracked, escaped(a, client) orelse return .untracked, jsonInt(obj, "ver"), jsonInt(obj, "cver"), if (jsonInt(obj, "iat") > 0) jsonInt(obj, "iat") else now, abs, next },
            ) catch return .untracked;
            const ttl = @max(next - now, 1);
            _ = store.set(key, renewed, ttl, now);
            const index = self.indexKey(a, uid) orelse return .untracked;
            _ = store.sadd(index, key, ttl, now);
        }

        return .{ .active = .{
            .pwd_tag = alloc.dupe(u8, pwd_tag) catch return .untracked,
            .client = alloc.dupe(u8, client) catch return .untracked,
        } };
    }

    /// 撤销（登出）：删记录并顺手从在线索引摘掉；纯 JWT 模式返回 `false`。
    pub fn revoke(self: *const Keeper, token: []const u8, now: i64) bool {
        const store = self.store orelse return false;
        if (!store.available()) return false;

        const alloc = self.allocator;
        const key = self.sessionKey(alloc, token) orelse return false;
        defer alloc.free(key);

        if (self.tokenUid(store, alloc, key, now)) |uid| {
            const index = self.indexKey(alloc, uid) orelse return false;
            defer alloc.free(index);
            _ = store.srem(index, key);
        }
        return store.del(key);
    }

    /// **踢掉某用户的全部令牌**（所有端）：全局版本 +1。
    pub fn revokeUser(self: *const Keeper, uid: i64, now: i64) bool {
        const alloc = self.allocator;
        const key = self.userVerKey(alloc, uid) orelse return false;
        defer alloc.free(key);
        return self.bump(key, uid, now);
    }

    /// **只踢某一端**（如只要手机端下线）：该端版本 +1，其它端不受影响。
    pub fn revokeClient(self: *const Keeper, uid: i64, client: []const u8, now: i64) bool {
        const trimmed = std.mem.trim(u8, client, " \t\r\n");
        if (trimmed.len == 0) return false;
        const alloc = self.allocator;
        const key = self.clientVerKey(alloc, uid, trimmed) orelse return false;
        defer alloc.free(key);
        return self.bump(key, uid, now);
    }

    /// 某用户的在线会话（后台展示；存储不支持集合时返回空）。
    /// 调用方对返回的每个元素调 `deinit`，再 `allocator.free(slice)`。
    pub fn sessions(self: *const Keeper, uid: i64, now: i64) ?[]SessionInfo {
        const store = self.store orelse return null;
        if (!store.available() or uid <= 0) return null;

        const alloc = self.allocator;
        const index = self.indexKey(alloc, uid) orelse return null;
        defer alloc.free(index);

        const members = store.smembers(alloc, index) orelse return null;
        defer {
            for (members) |m| alloc.free(m);
            alloc.free(members);
        }

        var out = std.ArrayList(SessionInfo).empty;
        errdefer {
            for (out.items) |item| item.deinit(alloc);
            out.deinit(alloc);
        }

        for (members) |key| {
            const text = store.get(alloc, key, now) orelse {
                _ = store.srem(index, key); // 记录已过期：顺手从索引摘掉
                continue;
            };
            defer alloc.free(text);

            var arena = std.heap.ArenaAllocator.init(alloc);
            defer arena.deinit();
            const a = arena.allocator();
            const parsed = std.json.parseFromSliceLeaky(std.json.Value, a, text, .{}) catch {
                _ = store.srem(index, key);
                continue;
            };
            const obj = switch (parsed) {
                .object => |m| m,
                else => {
                    _ = store.srem(index, key);
                    continue;
                },
            };

            const client = alloc.dupe(u8, jsonStr(obj, "client")) catch continue;
            out.append(alloc, .{
                .client = client,
                .iat = jsonInt(obj, "iat"),
                .exp = jsonInt(obj, "exp"),
            }) catch {
                alloc.free(client);
                continue;
            };
        }

        // 按登录时间倒序（最近登录在前）
        std.mem.sort(SessionInfo, out.items, {}, struct {
            fn lessThan(_: void, x: SessionInfo, y: SessionInfo) bool {
                return x.iat > y.iat;
            }
        }.lessThan);

        return out.toOwnedSlice(alloc) catch {
            for (out.items) |item| item.deinit(alloc);
            out.deinit(alloc);
            return null;
        };
    }

    // ---------- 内部 ----------

    /// 会话键：`{prefix}session:{sha256hex(token)}`。
    ///
    /// 用 zzig 的 `sha256Hex`（栈上 64 字节、零分配）+ **单次 alloc + memcpy**：
    /// 实测比「手写 hex + `allocPrint("{s}session:{s}")`」快 ~23%（149 → 115 ns/op，ReleaseFast）。
    fn sessionKey(self: *const Keeper, alloc: std.mem.Allocator, token: []const u8) ?[]u8 {
        const hex = zzig.hash.sha256Hex(token);
        const lit = "session:";
        const out = alloc.alloc(u8, self.key_prefix.len + lit.len + hex.len) catch return null;
        @memcpy(out[0..self.key_prefix.len], self.key_prefix);
        @memcpy(out[self.key_prefix.len..][0..lit.len], lit);
        @memcpy(out[self.key_prefix.len + lit.len ..][0..hex.len], &hex);
        return out;
    }

    fn userVerKey(self: *const Keeper, alloc: std.mem.Allocator, uid: i64) ?[]u8 {
        return std.fmt.allocPrint(alloc, "{s}userver:{d}", .{ self.key_prefix, uid }) catch null;
    }

    fn clientVerKey(self: *const Keeper, alloc: std.mem.Allocator, uid: i64, client: []const u8) ?[]u8 {
        return std.fmt.allocPrint(alloc, "{s}userver:{d}:{s}", .{ self.key_prefix, uid, client }) catch null;
    }

    fn indexKey(self: *const Keeper, alloc: std.mem.Allocator, uid: i64) ?[]u8 {
        return std.fmt.allocPrint(alloc, "{s}sessions:{d}", .{ self.key_prefix, uid }) catch null;
    }

    fn version(self: *const Keeper, store: Store, alloc: std.mem.Allocator, key: []u8, now: i64) i64 {
        _ = self;
        defer alloc.free(key);
        const text = store.get(alloc, key, now) orelse return 0;
        defer alloc.free(text);
        return std.fmt.parseInt(i64, std.mem.trim(u8, text, " \t\r\n"), 10) catch 0;
    }

    fn tokenUid(self: *const Keeper, store: Store, alloc: std.mem.Allocator, key: []const u8, now: i64) ?i64 {
        _ = self;
        const text = store.get(alloc, key, now) orelse return null;
        defer alloc.free(text);

        var arena = std.heap.ArenaAllocator.init(alloc);
        defer arena.deinit();
        const a = arena.allocator();
        const parsed = std.json.parseFromSliceLeaky(std.json.Value, a, text, .{}) catch return null;
        const obj = switch (parsed) {
            .object => |m| m,
            else => return null,
        };
        const uid = jsonInt(obj, "uid");
        return if (uid > 0) uid else null;
    }

    fn bump(self: *const Keeper, key: []u8, uid: i64, now: i64) bool {
        const store = self.store orelse return false;
        if (!store.available() or uid <= 0) return false;

        const alloc = self.allocator;
        const next = self.version(store, alloc, alloc.dupe(u8, key) catch return false, now) + 1;
        const text = std.fmt.allocPrint(alloc, "{d}", .{next}) catch return false;
        defer alloc.free(text);

        const ttl: i64 = if (self.policy.max_secs > 0) self.policy.max_secs else @max(self.policy.idle_secs, 3600);
        return store.set(key, text, ttl, now);
    }
};

fn jsonInt(map: std.json.ObjectMap, name: []const u8) i64 {
    const v = map.get(name) orelse return 0;
    return switch (v) {
        .integer => |i| i,
        .float => |f| @intFromFloat(f),
        .number_string => |s| std.fmt.parseInt(i64, s, 10) catch 0,
        else => 0,
    };
}

fn jsonStr(map: std.json.ObjectMap, name: []const u8) []const u8 {
    const v = map.get(name) orelse return "";
    return switch (v) {
        .string => |s| s,
        else => "",
    };
}

/// JSON 字符串转义（只需处理 `\` 与 `"`；口令指纹/客户端标识都是 ASCII）。
fn escaped(alloc: std.mem.Allocator, s: []const u8) ?[]u8 {
    var out = std.ArrayList(u8).empty;
    for (s) |c| {
        switch (c) {
            '\\' => out.appendSlice(alloc, "\\\\") catch return null,
            '"' => out.appendSlice(alloc, "\\\"") catch return null,
            else => out.append(alloc, c) catch return null,
        }
    }
    return out.toOwnedSlice(alloc) catch null;
}

// ---------- 内存后端（默认；重启即丢失） ----------

pub const MemoryStore = struct {
    allocator: std.mem.Allocator,
    mutex: SpinLock = .{},
    map: std.StringHashMap(Entry),
    sets: std.StringHashMap(StringSet),
    up: bool = true,

    const Entry = struct { value: []u8, expire_at: i64 };
    const StringSet = std.StringHashMap(void);

    pub fn init(allocator: std.mem.Allocator) MemoryStore {
        return .{
            .allocator = allocator,
            .map = std.StringHashMap(Entry).init(allocator),
            .sets = std.StringHashMap(StringSet).init(allocator),
        };
    }

    pub fn deinit(self: *MemoryStore) void {
        var it = self.map.iterator();
        while (it.next()) |e| {
            self.allocator.free(e.key_ptr.*);
            self.allocator.free(e.value_ptr.value);
        }
        self.map.deinit();

        var sit = self.sets.iterator();
        while (sit.next()) |e| {
            self.allocator.free(e.key_ptr.*);
            var mit = e.value_ptr.iterator();
            while (mit.next()) |m| self.allocator.free(m.key_ptr.*);
            e.value_ptr.deinit();
        }
        self.sets.deinit();
    }

    /// 模拟存储故障（测试用）。
    pub fn setUp(self: *MemoryStore, up: bool) void {
        self.up = up;
    }

    pub fn store(self: *MemoryStore) Store {
        return .{ .ptr = self, .vtable = &vtable };
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
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));
        return self.up;
    }

    fn getFn(ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8, now: i64) ?[]u8 {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return null;

        const entry = self.map.get(key) orelse return null;
        if (entry.expire_at > 0 and entry.expire_at <= now) {
            _ = self.removeKey(key);
            return null;
        }
        return allocator.dupe(u8, entry.value) catch null;
    }

    fn setFn(ptr: *anyopaque, key: []const u8, value: []const u8, ttl_secs: i64, now: i64) bool {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return false;

        const expire_at: i64 = if (ttl_secs > 0) now + ttl_secs else 0;
        const key_copy = self.allocator.dupe(u8, key) catch return false;
        const value_copy = self.allocator.dupe(u8, value) catch {
            self.allocator.free(key_copy);
            return false;
        };

        if (self.map.fetchPut(key_copy, .{ .value = value_copy, .expire_at = expire_at }) catch {
            self.allocator.free(key_copy);
            self.allocator.free(value_copy);
            return false;
        }) |old| {
            // 命中已存在：map **保留旧键**（不替换），新键未被采用 → 释放新键；旧值不再被持有 → 释放
            self.allocator.free(key_copy);
            self.allocator.free(old.value.value);
        }
        return true;
    }

    fn delFn(ptr: *anyopaque, key: []const u8) bool {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return false;
        return self.removeKey(key);
    }

    fn removeKey(self: *MemoryStore, key: []const u8) bool {
        if (self.map.fetchRemove(key)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value.value);
            return true;
        }
        return false;
    }

    fn saddFn(ptr: *anyopaque, key: []const u8, member: []const u8, ttl_secs: i64, now: i64) bool {
        _ = ttl_secs;
        _ = now;
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return false;

        const gop = self.sets.getOrPut(key) catch return false;
        if (!gop.found_existing) {
            const key_copy = self.allocator.dupe(u8, key) catch return false;
            gop.key_ptr.* = key_copy;
            gop.value_ptr.* = StringSet.init(self.allocator);
        }
        const member_copy = self.allocator.dupe(u8, member) catch return false;
        const mgop = gop.value_ptr.getOrPut(member_copy) catch {
            self.allocator.free(member_copy);
            return false;
        };
        if (mgop.found_existing) self.allocator.free(member_copy);
        return true;
    }

    fn sremFn(ptr: *anyopaque, key: []const u8, member: []const u8) bool {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return false;

        const set = self.sets.getPtr(key) orelse return false;
        if (set.fetchRemove(member)) |kv| {
            self.allocator.free(kv.key);
            return true;
        }
        return false;
    }

    fn smembersFn(ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8) ?[][]u8 {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return null;

        const set = self.sets.getPtr(key) orelse return null;
        var out = std.ArrayList([]u8).empty;
        var it = set.iterator();
        while (it.next()) |e| {
            const copy = allocator.dupe(u8, e.key_ptr.*) catch {
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
        return out.toOwnedSlice(allocator) catch null;
    }
};

// ---------- 文件后端（零依赖的持久化；重启不丢） ----------

/// JSON 快照 + 原子替换（写 `.tmp` → rename），单实例使用。
///
/// 每次写操作都落盘（会话写频率远低于业务请求：登录 / 登出 / 滑动续期各一次），
/// 因此进程重启后记录仍在 —— 这正是「重启不用重新登录」的关键。
pub const FileStore = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,
    mutex: SpinLock = .{},
    map: std.StringHashMap(Entry),
    sets: std.StringHashMap(StringSet),
    up: bool = true,

    const Entry = struct { value: []u8, expire_at: i64 };
    const StringSet = std.StringHashMap(void);

    /// 打开（或创建）持久化文件；已有内容会被加载到内存。
    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        name: []const u8,
    ) FileStore {
        var self = FileStore{
            .allocator = allocator,
            .io = io,
            .dir = dir,
            .name = name,
            .map = std.StringHashMap(Entry).init(allocator),
            .sets = std.StringHashMap(StringSet).init(allocator),
        };
        self.load();
        return self;
    }

    pub fn deinit(self: *FileStore) void {
        var it = self.map.iterator();
        while (it.next()) |e| {
            self.allocator.free(e.key_ptr.*);
            self.allocator.free(e.value_ptr.value);
        }
        self.map.deinit();

        var sit = self.sets.iterator();
        while (sit.next()) |e| {
            self.allocator.free(e.key_ptr.*);
            var mit = e.value_ptr.iterator();
            while (mit.next()) |m| self.allocator.free(m.key_ptr.*);
            e.value_ptr.deinit();
        }
        self.sets.deinit();
    }

    pub fn store(self: *FileStore) Store {
        return .{ .ptr = self, .vtable = &vtable };
    }

    /// 立即落盘（`deinit` 前也可显式调用；写操作已自动落盘）。
    pub fn flush(self: *FileStore) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.writeLocked();
    }

    // ---------- 持久化 ----------

    fn load(self: *FileStore) void {
        const data = self.dir.readFileAlloc(self.io, self.name, self.allocator, .limited(16 * 1024 * 1024)) catch |e| {
            // 首次启动：文件不存在 → 正常的空存储
            if (e == error.FileNotFound) return;
            // 读不了（权限/磁盘）→ 退化放行，**绝不把所有人当成已登出**
            self.up = false;
            return;
        };
        defer self.allocator.free(data);

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();

        // 文件损坏同理：宁可放宽（纯 JWT），也不要让全站重启登录
        const parsed = std.json.parseFromSliceLeaky(std.json.Value, a, data, .{}) catch {
            self.up = false;
            return;
        };
        const root = switch (parsed) {
            .object => |m| m,
            else => {
                self.up = false;
                return;
            },
        };

        if (root.get("entries")) |v| {
            if (v == .object) {
                var it = v.object.iterator();
                while (it.next()) |e| {
                    const rec = switch (e.value_ptr.*) {
                        .object => |m| m,
                        else => continue,
                    };
                    const value = switch (rec.get("v") orelse continue) {
                        .string => |s| s,
                        else => continue,
                    };
                    const expire_at: i64 = switch (rec.get("e") orelse continue) {
                        .integer => |i| i,
                        else => continue,
                    };
                    const key = self.allocator.dupe(u8, e.key_ptr.*) catch continue;
                    const val = self.allocator.dupe(u8, value) catch {
                        self.allocator.free(key);
                        continue;
                    };
                    self.map.put(key, .{ .value = val, .expire_at = expire_at }) catch {
                        self.allocator.free(key);
                        self.allocator.free(val);
                    };
                }
            }
        }

        if (root.get("sets")) |v| {
            if (v == .object) {
                var it = v.object.iterator();
                while (it.next()) |e| {
                    const items = switch (e.value_ptr.*) {
                        .array => |arr| arr,
                        else => continue,
                    };
                    const key = self.allocator.dupe(u8, e.key_ptr.*) catch continue;
                    var set = StringSet.init(self.allocator);
                    for (items.items) |item| {
                        const member = switch (item) {
                            .string => |s| s,
                            else => continue,
                        };
                        const copy = self.allocator.dupe(u8, member) catch continue;
                        set.put(copy, {}) catch self.allocator.free(copy);
                    }
                    self.sets.put(key, set) catch self.allocator.free(key);
                }
            }
        }
    }

    fn writeLocked(self: *FileStore) void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var out = std.ArrayList(u8).empty;
        defer out.deinit(self.allocator);

        out.appendSlice(self.allocator, "{\"entries\":{") catch return;

        var first = true;
        var it = self.map.iterator();
        while (it.next()) |e| {
            if (!first) out.append(self.allocator, ',') catch return;
            first = false;
            out.append(self.allocator, '"') catch return;
            appendEscaped(&out, self.allocator, e.key_ptr.*) catch return;
            out.appendSlice(self.allocator, "\":{\"v\":\"") catch return;
            appendEscaped(&out, self.allocator, e.value_ptr.value) catch return;
            const tail = std.fmt.allocPrint(a, "\",\"e\":{d}}}", .{e.value_ptr.expire_at}) catch return;
            out.appendSlice(self.allocator, tail) catch return;
        }

        out.appendSlice(self.allocator, "},\"sets\":{") catch return;

        var sfirst = true;
        var sit = self.sets.iterator();
        while (sit.next()) |e| {
            if (!sfirst) out.append(self.allocator, ',') catch return;
            sfirst = false;
            out.append(self.allocator, '"') catch return;
            appendEscaped(&out, self.allocator, e.key_ptr.*) catch return;
            out.appendSlice(self.allocator, "\":[") catch return;

            var mfirst = true;
            var mit = e.value_ptr.iterator();
            while (mit.next()) |m| {
                if (!mfirst) out.append(self.allocator, ',') catch return;
                mfirst = false;
                out.append(self.allocator, '"') catch return;
                appendEscaped(&out, self.allocator, m.key_ptr.*) catch return;
                out.append(self.allocator, '"') catch return;
            }
            out.append(self.allocator, ']') catch return;
        }

        out.appendSlice(self.allocator, "}}") catch return;

        // 原子替换：写 .tmp → rename
        const tmp_name = std.fmt.allocPrint(self.allocator, "{s}.tmp", .{self.name}) catch return;
        defer self.allocator.free(tmp_name);

        self.dir.writeFile(self.io, .{ .sub_path = tmp_name, .data = out.items }) catch {
            self.up = false;
            return;
        };
        std.Io.Dir.rename(self.dir, tmp_name, self.dir, self.name, self.io) catch {
            self.up = false;
            return;
        };
        self.up = true;
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
        const self: *FileStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.up;
    }

    fn getFn(ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8, now: i64) ?[]u8 {
        const self: *FileStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return null;

        const entry = self.map.get(key) orelse return null;
        if (entry.expire_at > 0 and entry.expire_at <= now) {
            _ = self.removeKeyLocked(key);
            self.writeLocked();
            return null;
        }
        return allocator.dupe(u8, entry.value) catch null;
    }

    fn setFn(ptr: *anyopaque, key: []const u8, value: []const u8, ttl_secs: i64, now: i64) bool {
        const self: *FileStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return false;

        const expire_at: i64 = if (ttl_secs > 0) now + ttl_secs else 0;
        const key_copy = self.allocator.dupe(u8, key) catch return false;
        const new_value = self.allocator.dupe(u8, value) catch {
            self.allocator.free(key_copy);
            return false;
        };

        if (self.map.fetchPut(key_copy, .{ .value = new_value, .expire_at = expire_at }) catch {
            self.allocator.free(key_copy);
            self.allocator.free(new_value);
            return false;
        }) |old| {
            // 命中已存在：map 保留旧键，新键未被采用 → 释放新键；旧值不再被持有 → 释放
            self.allocator.free(key_copy);
            self.allocator.free(old.value.value);
        }
        self.writeLocked();
        return self.up;
    }

    fn delFn(ptr: *anyopaque, key: []const u8) bool {
        const self: *FileStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return false;
        const removed = self.removeKeyLocked(key);
        if (removed) self.writeLocked();
        return removed;
    }

    fn removeKeyLocked(self: *FileStore, key: []const u8) bool {
        if (self.map.fetchRemove(key)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value.value);
            return true;
        }
        return false;
    }

    fn saddFn(ptr: *anyopaque, key: []const u8, member: []const u8, ttl_secs: i64, now: i64) bool {
        _ = ttl_secs;
        _ = now;
        const self: *FileStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return false;

        const gop = self.sets.getOrPut(key) catch return false;
        if (!gop.found_existing) {
            const key_copy = self.allocator.dupe(u8, key) catch return false;
            gop.key_ptr.* = key_copy;
            gop.value_ptr.* = StringSet.init(self.allocator);
        }
        const member_copy = self.allocator.dupe(u8, member) catch return false;
        const mgop = gop.value_ptr.getOrPut(member_copy) catch {
            self.allocator.free(member_copy);
            return false;
        };
        if (mgop.found_existing) self.allocator.free(member_copy);
        self.writeLocked();
        return self.up;
    }

    fn sremFn(ptr: *anyopaque, key: []const u8, member: []const u8) bool {
        const self: *FileStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return false;

        const set = self.sets.getPtr(key) orelse return false;
        if (set.fetchRemove(member)) |kv| {
            self.allocator.free(kv.key);
            self.writeLocked();
            return true;
        }
        return false;
    }

    fn smembersFn(ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8) ?[][]u8 {
        const self: *FileStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return null;

        const set = self.sets.getPtr(key) orelse return null;
        var out = std.ArrayList([]u8).empty;
        var it = set.iterator();
        while (it.next()) |e| {
            const copy = allocator.dupe(u8, e.key_ptr.*) catch {
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
        return out.toOwnedSlice(allocator) catch null;
    }
};

fn appendEscaped(out: *std.ArrayList(u8), allocator: std.mem.Allocator, text: []const u8) !void {
    for (text) |c| {
        switch (c) {
            '"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => try out.append(allocator, c),
        }
    }
}

// ---------- 测试 ----------

const testing = std.testing;

const TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9.sig";
const POLICY = Policy{ .idle_secs = 3600, .max_secs = 86400 };

fn expectActive(k: *const Keeper, token: []const u8, now: i64) !void {
    switch (k.check(token, now)) {
        .active => |a| a.deinit(k.allocator),
        .invalid => return error.ExpectedActiveGotInvalid,
        .untracked => return error.ExpectedActiveGotUntracked,
    }
}

fn expectInvalid(k: *const Keeper, token: []const u8, now: i64) !void {
    switch (k.check(token, now)) {
        .active => |a| {
            a.deinit(k.allocator);
            return error.ExpectedInvalidGotActive;
        },
        .invalid => {},
        .untracked => return error.ExpectedInvalidGotUntracked,
    }
}

test "session: 登记 / 校验 / 登出" {
    const alloc = testing.allocator;
    var mem = MemoryStore.init(alloc);
    defer mem.deinit();

    const store = mem.store();
    const k = Keeper.init(alloc, store, "t:", POLICY);

    try testing.expect(k.register(TOKEN, 42, "pwd1", "web", 1000));
    try expectActive(&k, TOKEN, 1001);

    try testing.expect(k.revoke(TOKEN, 1002));
    try expectInvalid(&k, TOKEN, 1003);
}

test "session: 过期与绝对上限" {
    const alloc = testing.allocator;
    var mem = MemoryStore.init(alloc);
    defer mem.deinit();

    const store = mem.store();
    const k = Keeper.init(alloc, store, "t:", POLICY);

    // ① 空闲过期：exp = 1000 + 3600 = 4600。
    //    注意**中间不能访问**（剩余不足一半会触发滑动续期），直接到点验证
    try testing.expect(k.register(TOKEN, 42, "", "web", 1000));
    try expectActive(&k, TOKEN, 1900); // 剩余 2700 > 1800 → 不续期
    try expectInvalid(&k, TOKEN, 4600); // exp <= now 失效

    // ② 绝对上限：持续访问会滑动续期，但**永不越过 abs**（idle=100 / max=250）
    var mem2 = MemoryStore.init(alloc);
    defer mem2.deinit();
    const store2 = mem2.store();
    const k2 = Keeper.init(alloc, store2, "t:", .{ .idle_secs = 100, .max_secs = 250 });

    try testing.expect(k2.register(TOKEN, 42, "", "web", 1000)); // exp=1100, abs=1250
    // 注意：`exp <= now` 会先判失效，所以访问时刻必须严格早于 exp；
    // 每次「剩余不足一半」都会续期，但 next 被 abs 截断
    const visits = [_]i64{ 1050, 1075, 1150, 1249 };
    for (visits) |t| {
        try expectActive(&k2, TOKEN, t);
    }
    // abs 到点即失效（即便一直在访问）
    try expectInvalid(&k2, TOKEN, 1250);
}

test "session: 滑动续期（剩余不足一半才写，且不越上限）" {
    const alloc = testing.allocator;
    var mem = MemoryStore.init(alloc);
    defer mem.deinit();

    const store = mem.store();
    const policy = Policy{ .idle_secs = 100, .max_secs = 250 };
    const k = Keeper.init(alloc, store, "t:", policy);

    try testing.expect(k.register(TOKEN, 7, "", "web", 1000)); // exp=1100, abs=1250

    // 剩余 60 > 50（一半）→ 不续期，exp 仍为 1100
    try expectActive(&k, TOKEN, 1040);
    try expectInvalid(&k, TOKEN, 1101);

    // 重新登记，剩余 40 < 50 → 续期到 now+100，但不超过 abs=1250
    try testing.expect(k.register(TOKEN, 7, "", "web", 1000));
    try expectActive(&k, TOKEN, 1060); // exp=1100 → 1060+40 → 续期 next=1160，abs=1250 不越界
    try expectActive(&k, TOKEN, 1150); // 续期到 1250（abs）
    try expectInvalid(&k, TOKEN, 1251);
}

test "session: 按用户踢线 / 按端踢线" {
    const alloc = testing.allocator;
    var mem = MemoryStore.init(alloc);
    defer mem.deinit();

    const store = mem.store();
    const k = Keeper.init(alloc, store, "t:", POLICY);

    const web = "h.p.s-web";
    const app = "h.p.s-app";

    try testing.expect(k.register(web, 9, "", "web", 1000));
    try testing.expect(k.register(app, 9, "", "app", 1000));
    try expectActive(&k, web, 1001);
    try expectActive(&k, app, 1001);

    // 只踢 web 端
    try testing.expect(k.revokeClient(9, "web", 1002));
    try expectInvalid(&k, web, 1003);
    try expectActive(&k, app, 1003);

    // 踢掉全部端
    try testing.expect(k.revokeUser(9, 1004));
    try expectInvalid(&k, app, 1005);
}

test "session: 存储不可用 → 纯 JWT 放行（untracked）" {
    const alloc = testing.allocator;
    var mem = MemoryStore.init(alloc);
    defer mem.deinit();

    const store = mem.store();
    const k = Keeper.init(alloc, store, "t:", POLICY);

    try testing.expect(k.register(TOKEN, 42, "", "web", 1000));
    mem.setUp(false); // 模拟 Redis 挂了
    switch (k.check(TOKEN, 1001)) {
        .untracked => {},
        else => return error.ExpectedUntracked,
    }
}

test "session: 未配置存储 → untracked（当前默认行为，重启不掉线）" {
    const alloc = testing.allocator;
    const k = Keeper.init(alloc, null, "t:", POLICY);
    try testing.expect(!k.register(TOKEN, 42, "", "web", 1000));
    switch (k.check(TOKEN, 1001)) {
        .untracked => {},
        else => return error.ExpectedUntracked,
    }
}

test "session: 在线会话列表" {
    const alloc = testing.allocator;
    var mem = MemoryStore.init(alloc);
    defer mem.deinit();

    const store = mem.store();
    const k = Keeper.init(alloc, store, "t:", POLICY);

    try testing.expect(k.register("h.p.s1", 5, "", "web", 1000));
    try testing.expect(k.register("h.p.s2", 5, "", "app", 1100));

    const list = k.sessions(5, 1200) orelse return error.ExpectedSessions;
    defer {
        for (list) |item| item.deinit(alloc);
        alloc.free(list);
    }
    try testing.expectEqual(@as(usize, 2), list.len);
    // 按登录时间倒序：app(1100) 在前
    try testing.expectEqualStrings("app", list[0].client);
    try testing.expectEqualStrings("web", list[1].client);
}

test "session: FileStore 重启后记录仍在（重启不用重新登录）" {
    const alloc = testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // 第一次：登录并落盘
    {
        var fs = FileStore.init(alloc, io, tmp.dir, "sessions.json");
        defer fs.deinit();
        const store = fs.store();
        const k = Keeper.init(alloc, store, "t:", POLICY);
        try testing.expect(k.register(TOKEN, 42, "pwd", "web", 1000));
        try expectActive(&k, TOKEN, 1001);
    }

    // 第二次：模拟进程重启（重新打开同一文件）
    {
        var fs = FileStore.init(alloc, io, tmp.dir, "sessions.json");
        defer fs.deinit();
        const store = fs.store();
        const k = Keeper.init(alloc, store, "t:", POLICY);
        try expectActive(&k, TOKEN, 1002);
    }
}

test "session: authorize 默认全放行（不配存储 / 存储故障 / 文件损坏）" {
    const alloc = testing.allocator;
    const io = std.testing.io;

    // ① 不配存储：纯 JWT，重启也不掉线（默认口径）
    const k_null = Keeper.init(alloc, null, "t:", POLICY);
    try testing.expect(k_null.authorize(TOKEN, 1000));
    try testing.expectEqualStrings("jwt", k_null.storeKind());

    // ② 存储故障：按纯 JWT 放行（Redis 挂了不能把所有人挡在外面）
    var mem = MemoryStore.init(alloc);
    defer mem.deinit();
    const k_mem = Keeper.init(alloc, mem.store(), "t:", POLICY);
    try testing.expect(k_mem.register(TOKEN, 42, "", "web", 1000));
    try testing.expect(k_mem.authorize(TOKEN, 1001));
    mem.setUp(false);
    try testing.expect(k_mem.authorize(TOKEN, 1002));

    // ③ 快照文件损坏：退化为放行，而不是把所有人判成已登出
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "broken.json", .data = "{not-json" });

    var fs = FileStore.init(alloc, io, tmp.dir, "broken.json");
    defer fs.deinit();
    try testing.expect(!fs.store().available());
    const k_file = Keeper.init(alloc, fs.store(), "t:", POLICY);
    try testing.expect(k_file.authorize(TOKEN, 1000));
}

test "session: authorize 只在明确失效时拒绝（登出 / 到期）" {
    const alloc = testing.allocator;
    var mem = MemoryStore.init(alloc);
    defer mem.deinit();
    const k = Keeper.init(alloc, mem.store(), "t:", POLICY);

    try testing.expect(k.register(TOKEN, 42, "", "web", 1000));
    try testing.expect(k.authorize(TOKEN, 1001));

    try testing.expect(k.revoke(TOKEN, 1002));
    try testing.expect(!k.authorize(TOKEN, 1003)); // 登出 → 拒绝

    try testing.expect(k.register(TOKEN, 42, "", "web", 2000));
    try testing.expect(!k.authorize(TOKEN, 2000 + 3600)); // 到期 → 拒绝
}
