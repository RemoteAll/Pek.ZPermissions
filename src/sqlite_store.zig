//! SQLite 后端（**默认推荐**）：经 `Pek.ZCode` 的 `Dal` + 仓库内 `Entity/Model.xml`。
//!
//! # 建表链路（重要：**不是解析 XML 文本拼 SQL**）
//!
//! ```text
//! Entity/Model.xml  --解析-->  EntityModel / TableMeta / ColumnMeta（模型对象）
//!                                  |
//!                                  v  dialect（SQLite provider）.createTableAlloc
//!                             DDL 语句（类型/长度/自增/主键/索引 均由方言规则映射）
//!                                  |
//!                                  v  Dal.syncSchema（幂等增量）
//!                             实际库表
//! ```
//!
//! - XML 只是模型的**输入载体**，可以手写；
//! - 建表实际取决于「**模型对象 + 方言规则**」：`String(512)` → `nvarchar(512)`、
//!   `Int64` → `INTEGER`、`DateTime` → `datetime`（实测值，见下方测试）；
//! - **禁止**手写 DDL、**禁止**运行时改模型；结构变更改模型后重跑 `syncSchema`
//!   （缺表建表 / 缺列补列 / 缺索引补索引）。
//!
//! 存储形态：单表 KV（`SessionKey` 唯一索引），集合能力用键编码 `{setKey}\x1f{member}` 模拟，
//! 因此 `Store` 的全部能力（含 `smembers`）都可实现。
//!
//! 取舍：SQLite 是**单机文件库**，天然持久化（重启不丢），但不支持多实例共享；
//! 多实例共享用 `redis_store.RedisStore`。

const std = @import("std");
const zcode = @import("zcode");
const session = @import("session.zig");

pub const Store = session.Store;

/// 物理表名（与 `Entity/Model.xml` 一致）
pub const TABLE = "ZPermissions_Session";

/// 模型默认路径（相对项目根）
pub const DEFAULT_MODEL_PATH = "Entity/Model.xml";

/// 集合成员的键分隔符（0x1F = Unit Separator，正常令牌/键不会包含）
pub const SET_SEP: u8 = 0x1f;

pub const OpenError = error{
    Model,
    Open,
    Sync,
    OutOfMemory,
};

pub const SqliteStore = struct {
    allocator: std.mem.Allocator,
    dal: zcode.Dal,
    mutex: session.SpinLock = .{},
    up: bool = true,

    /// 打开（或创建）SQLite 文件，并按 `model_path` 中的模型幂等建表。
    ///
    /// `conn_str` 用 Pek.ZCode 的连接串口径，例如：
    /// - `Data Source=Data\\sessions.db`
    ///
    /// `model_path` 一般就是仓库内 `Entity/Model.xml`（见 `DEFAULT_MODEL_PATH`）。
    pub fn open(allocator: std.mem.Allocator, conn_str: []const u8, model_path: []const u8) OpenError!SqliteStore {
        const dal = zcode.Dal.open(allocator, conn_str, model_path) catch return error.Open;

        var instance = SqliteStore{ .allocator = allocator, .dal = dal };

        var s = instance.dal.openSession() catch {
            instance.dal.deinit();
            return error.Open;
        };
        defer s.deinit();
        _ = instance.dal.syncSchema(&s) catch {
            instance.dal.deinit();
            return error.Sync;
        };

        return instance;
    }

    /// 便捷：用默认模型路径 `Entity/Model.xml`（相对项目根）打开。
    pub fn openDefault(allocator: std.mem.Allocator, conn_str: []const u8) OpenError!SqliteStore {
        return open(allocator, conn_str, DEFAULT_MODEL_PATH);
    }

    pub fn deinit(self: *SqliteStore) void {
        self.dal.deinit();
        self.* = undefined;
    }

    pub fn store(self: *SqliteStore) Store {
        return .{ .ptr = self, .vtable = &vtable };
    }

    /// 探活：能查一次表即视为可用。
    pub fn ping(self: *SqliteStore) bool {
        const rows = self.dal.queryAlloc(self.allocator, "SELECT 1 FROM " ++ TABLE ++ " LIMIT 1", &.{}) catch {
            self.setUp(false);
            return false;
        };
        zcode.session.freeRows(self.allocator, rows);
        self.setUp(true);
        return true;
    }

    fn setUp(self: *SqliteStore, up: bool) void {
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
        const self: *SqliteStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.up;
    }

    fn getFn(ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8, now: i64) ?[]u8 {
        const self: *SqliteStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return null;

        const rows = self.dal.queryAlloc(
            self.allocator,
            "SELECT SessionValue, ExpireAt FROM " ++ TABLE ++ " WHERE SessionKey = ?",
            &.{.{ .text = key }},
        ) catch {
            self.up = false;
            return null;
        };
        defer zcode.session.freeRows(self.allocator, rows);

        if (rows.len == 0) return null;
        const row = rows[0];

        const expire_at = if (row.get("ExpireAt")) |v| (v.asI64() orelse 0) else 0;
        if (expire_at > 0 and expire_at <= now) {
            _ = self.dal.exec("DELETE FROM " ++ TABLE ++ " WHERE SessionKey = ?", &.{.{ .text = key }}) catch {};
            return null;
        }

        const value = if (row.get("SessionValue")) |v| switch (v) {
            .text => |t| t,
            else => "",
        } else "";
        return allocator.dupe(u8, value) catch null;
    }

    fn setFn(ptr: *anyopaque, key: []const u8, value: []const u8, ttl_secs: i64, now: i64) bool {
        const self: *SqliteStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return false;

        const expire_at: i64 = if (ttl_secs > 0) now + ttl_secs else 0;
        _ = self.dal.exec(
            "INSERT INTO " ++ TABLE ++ " (SessionKey, SessionValue, ExpireAt) VALUES (?, ?, ?) " ++
                "ON CONFLICT(SessionKey) DO UPDATE SET SessionValue = excluded.SessionValue, ExpireAt = excluded.ExpireAt",
            &.{ .{ .text = key }, .{ .text = value }, .{ .int = expire_at } },
        ) catch {
            self.up = false;
            return false;
        };
        return true;
    }

    fn delFn(ptr: *anyopaque, key: []const u8) bool {
        const self: *SqliteStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return false;

        const n = self.dal.exec("DELETE FROM " ++ TABLE ++ " WHERE SessionKey = ?", &.{.{ .text = key }}) catch {
            self.up = false;
            return false;
        };
        return n > 0;
    }

    fn saddFn(ptr: *anyopaque, key: []const u8, member: []const u8, ttl_secs: i64, now: i64) bool {
        const self: *SqliteStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return false;

        const full = memberKey(self.allocator, key, member) orelse return false;
        defer self.allocator.free(full);

        const expire_at: i64 = if (ttl_secs > 0) now + ttl_secs else 0;
        _ = self.dal.exec(
            "INSERT OR IGNORE INTO " ++ TABLE ++ " (SessionKey, SessionValue, ExpireAt) VALUES (?, '', ?)",
            &.{ .{ .text = full }, .{ .int = expire_at } },
        ) catch {
            self.up = false;
            return false;
        };
        return true;
    }

    fn sremFn(ptr: *anyopaque, key: []const u8, member: []const u8) bool {
        const self: *SqliteStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return false;

        const full = memberKey(self.allocator, key, member) orelse return false;
        defer self.allocator.free(full);

        const n = self.dal.exec("DELETE FROM " ++ TABLE ++ " WHERE SessionKey = ?", &.{.{ .text = full }}) catch {
            self.up = false;
            return false;
        };
        return n > 0;
    }

    fn smembersFn(ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8) ?[][]u8 {
        const self: *SqliteStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.up) return null;

        const prefix = std.fmt.allocPrint(self.allocator, "{s}{c}", .{ key, SET_SEP }) catch return null;
        defer self.allocator.free(prefix);

        const pattern = likePrefix(self.allocator, prefix) orelse return null;
        defer self.allocator.free(pattern);

        const rows = self.dal.queryAlloc(
            self.allocator,
            "SELECT SessionKey FROM " ++ TABLE ++ " WHERE SessionKey LIKE ? ESCAPE '\\'",
            &.{.{ .text = pattern }},
        ) catch {
            self.up = false;
            return null;
        };
        defer zcode.session.freeRows(self.allocator, rows);

        var out = std.ArrayList([]u8).empty;
        for (rows) |row| {
            const raw = if (row.get("SessionKey")) |v| switch (v) {
                .text => |t| t,
                else => continue,
            } else continue;
            if (raw.len <= prefix.len) continue;

            const copy = allocator.dupe(u8, raw[prefix.len..]) catch {
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

fn memberKey(allocator: std.mem.Allocator, set_key: []const u8, member: []const u8) ?[]u8 {
    return std.fmt.allocPrint(allocator, "{s}{c}{s}", .{ set_key, SET_SEP, member }) catch null;
}

/// 把前缀转成 `LIKE` 模式（转义 `\` `%` `_`），再追加 `%`。
fn likePrefix(allocator: std.mem.Allocator, prefix: []const u8) ?[]u8 {
    var out = std.ArrayList(u8).empty;
    for (prefix) |c| {
        switch (c) {
            '\\', '%', '_' => {
                out.append(allocator, '\\') catch {
                    out.deinit(allocator);
                    return null;
                };
                out.append(allocator, c) catch {
                    out.deinit(allocator);
                    return null;
                };
            },
            else => out.append(allocator, c) catch {
                out.deinit(allocator);
                return null;
            },
        }
    }
    out.append(allocator, '%') catch {
        out.deinit(allocator);
        return null;
    };
    return out.toOwnedSlice(allocator) catch null;
}

// ---------- 测试 ----------

const testing = std.testing;

test "sqlite: Entity/Model.xml 可解析且表名正确" {
    var m = try zcode.EntityModel.load(testing.allocator, DEFAULT_MODEL_PATH);
    defer m.deinit();
    try testing.expectEqual(@as(usize, 1), m.tables.len);
    const t = m.table("ZSession").?;
    try testing.expectEqualStrings(TABLE, t.effectiveTableName());
    try testing.expect(t.column("SessionKey") != null);
    try testing.expect(t.column("SessionValue") != null);
    try testing.expect(t.column("ExpireAt") != null);
    // 连接名按规范写在 Option 里（不要求在代码里自创）
    try testing.expectEqualStrings("Permissions", m.options.connName().?);
}

test "sqlite: 建表按模型 + 方言规则生成（非照抄 XML）且幂等" {
    const alloc = testing.allocator;
    const io = std.testing.io;
    const db_file = "zperm-sqlite-ddl-test.db";
    defer std.Io.Dir.cwd().deleteFile(io, db_file) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, db_file ++ "-wal") catch {};
    defer std.Io.Dir.cwd().deleteFile(io, db_file ++ "-shm") catch {};

    // 用模型对象（不是 XML 文本）+ 方言（SQLite provider）建表
    const m = try zcode.EntityModel.load(alloc, DEFAULT_MODEL_PATH);
    var dal = try zcode.Dal.initWithModel(alloc, "Data Source=" ++ db_file, m);
    defer dal.deinit();

    var s = try dal.openSession();
    defer s.deinit();

    // 首次：建表 + 建唯一索引
    const r1 = try dal.syncSchema(&s);
    try testing.expectEqual(@as(usize, 1), r1.tables_created);
    try testing.expectEqual(@as(usize, 1), r1.indexes_created);

    // 方言映射后的**实际**列类型（实测值；不是 Model.xml 里的 DataType 原文）
    const rows = try dal.queryAlloc(alloc, "PRAGMA table_info(" ++ TABLE ++ ")", &.{});
    defer zcode.session.freeRows(alloc, rows);

    var saw_key = false;
    var saw_expire = false;
    for (rows) |r| {
        const name = columnText(r, "name");
        const ty = columnText(r, "type");
        if (std.mem.eql(u8, name, "SessionKey")) {
            // DataType="String" Length="512" → 方言映射为 nvarchar(512)
            try testing.expectEqualStrings("nvarchar(512)", ty);
            saw_key = true;
        } else if (std.mem.eql(u8, name, "ExpireAt")) {
            // DataType="Int64" → INTEGER
            try testing.expectEqualStrings("INTEGER", ty);
            // DefaultValue="0" → DEFAULT 0（默认值也由方言渲染，不是原样拼 XML）
            try testing.expectEqualStrings("0", columnText(r, "dflt_value"));
            saw_expire = true;
        }
    }
    try testing.expect(saw_key and saw_expire);

    // 幂等：原模型再跑一次，不产生任何变更
    const r2 = try dal.syncSchema(&s);
    try testing.expectEqual(@as(usize, 0), r2.tables_created);
    try testing.expectEqual(@as(usize, 0), r2.indexes_created);
    try testing.expectEqual(@as(usize, 0), r2.columns_added);
}

fn columnText(r: zcode.session.Row, name: []const u8) []const u8 {
    const v = r.get(name) orelse return "";
    return switch (v) {
        .text => |x| x,
        else => "",
    };
}

test "sqlite: 启动时按需建表（表不存在才建；被删后重启自动重建）" {
    const alloc = testing.allocator;
    const io = std.testing.io;
    const db_file = "zperm-sqlite-bootstrap-test.db";
    defer std.Io.Dir.cwd().deleteFile(io, db_file) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, db_file ++ "-wal") catch {};
    defer std.Io.Dir.cwd().deleteFile(io, db_file ++ "-shm") catch {};

    const conn = "Data Source=" ++ db_file;
    const policy = session.Policy{ .idle_secs = 3600, .max_secs = 86400 };

    // ① 首次启动：库文件为空 → 按模型 + 方言建表，可正常写入
    {
        var st = try SqliteStore.openDefault(alloc, conn);
        defer st.deinit();
        const k = session.Keeper.init(alloc, st.store(), "t:", policy);
        try testing.expect(k.register("h.p.bootstrap", 1, "", "web", 1000));
        try testing.expect(k.authorize("h.p.bootstrap", 1001));
    }

    // ② 模拟「库文件在、表不在」（首个部署常见形态）：删掉表
    {
        var st = try SqliteStore.openDefault(alloc, conn);
        defer st.deinit();
        _ = try st.dal.exec("DROP TABLE " ++ TABLE, &.{});
    }

    // ③ 再次启动：检测到表不存在 → 自动重建（不需要人工建表）
    {
        var st = try SqliteStore.openDefault(alloc, conn);
        defer st.deinit();

        const rows = try st.dal.queryAlloc(
            alloc,
            "SELECT name FROM sqlite_master WHERE type='table' AND name='" ++ TABLE ++ "'",
            &.{},
        );
        defer zcode.session.freeRows(alloc, rows);
        try testing.expectEqual(@as(usize, 1), rows.len);

        // 重建后表可用（旧数据随 DROP 消失是预期的：仅为验证「按需建表」）
        const s = st.store();
        try testing.expect(s.set("t.after-rebuild", "v", 0, 1000));
        if (s.get(alloc, "t.after-rebuild", 1001)) |v| {
            defer alloc.free(v);
            try testing.expectEqualStrings("v", v);
        } else return error.ExpectedValue;
    }
}

test "sqlite: 建表 + 读写 + 重启后记录仍在" {
    const alloc = testing.allocator;
    const io = std.testing.io;

    // 测试库放在当前工作目录（`zig build test` 的 cwd = 项目根），用完即删
    const db_file = "zperm-sqlite-test.db";
    defer std.Io.Dir.cwd().deleteFile(io, db_file) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, db_file ++ "-wal") catch {};
    defer std.Io.Dir.cwd().deleteFile(io, db_file ++ "-shm") catch {};

    const conn = "Data Source=" ++ db_file;

    const policy = session.Policy{ .idle_secs = 3600, .max_secs = 86400 };
    const token = "h.p.s-sqlite";

    // 第一次：登记
    {
        var st = try SqliteStore.openDefault(alloc, conn);
        defer st.deinit();
        const k = session.Keeper.init(alloc, st.store(), "t:", policy);
        try testing.expect(k.register(token, 42, "pwd", "web", 1000));
        try testing.expect(k.authorize(token, 1001));
    }

    // 第二次：模拟重启（重新打开同一个库）
    {
        var st = try SqliteStore.openDefault(alloc, conn);
        defer st.deinit();
        const k = session.Keeper.init(alloc, st.store(), "t:", policy);
        try testing.expect(k.authorize(token, 1002));

        // 踢线后立即失效
        try testing.expect(k.revokeUser(42, 1003));
        try testing.expect(!k.authorize(token, 1004));
    }
}

test "sqlite: 集合能力与过期" {
    const alloc = testing.allocator;
    const io = std.testing.io;

    // 注意：`:memory:` 对本后端不适用 —— `Dal` 每次操作用独立连接，内存库不共享；
    // 这里同样用文件库，用完即删。
    const db_file = "zperm-sqlite-set-test.db";
    defer std.Io.Dir.cwd().deleteFile(io, db_file) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, db_file ++ "-wal") catch {};
    defer std.Io.Dir.cwd().deleteFile(io, db_file ++ "-shm") catch {};

    var st = try SqliteStore.openDefault(alloc, "Data Source=" ++ db_file);
    defer st.deinit();

    const s = st.store();
    try testing.expect(s.available());

    try testing.expect(s.sadd("k.sessions", "a", 0, 100));
    try testing.expect(s.sadd("k.sessions", "b", 0, 100));
    try testing.expect(s.sadd("k.sessions", "a", 0, 100)); // 幂等

    const members = s.smembers(alloc, "k.sessions") orelse return error.ExpectedMembers;
    defer {
        for (members) |m| alloc.free(m);
        alloc.free(members);
    }
    try testing.expectEqual(@as(usize, 2), members.len);

    try testing.expect(s.srem("k.sessions", "a"));
    const left = s.smembers(alloc, "k.sessions") orelse return error.ExpectedMembers;
    defer {
        for (left) |m| alloc.free(m);
        alloc.free(left);
    }
    try testing.expectEqual(@as(usize, 1), left.len);

    // TTL：100 秒写入、now=101 读不到（并顺手删除）
    try testing.expect(s.set("t.tmp", "v", 100, 1000));
    if (s.get(alloc, "t.tmp", 1099)) |got| {
        defer alloc.free(got);
        try testing.expectEqualStrings("v", got);
    } else return error.ExpectedValue;
    try testing.expect(s.get(alloc, "t.tmp", 1100) == null);
}
