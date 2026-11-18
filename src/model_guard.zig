//! 模型守卫：断言 `Entity/Model.xml` 与本库代码的期望一致（**防漂移**）。
//!
//! # 为什么是「守卫」而不是「同步脚本」
//!
//! 本仓库的会话表是**本项目自建**的（C# `Pek.Permissions` 的令牌存在 Redis 的
//! `jwt:token:access:*`，没有任何对应实体），因此**不存在可同步的上游权威模型**。
//! 生态里唯一的 `sync-model.ps1`（`HlktechIoT/Tools/`）是从
//! `YRY.Framework/src/HlktechIoT.Data/Model.xml` 裁到 Rust 侧的专用脚本，与本项目无关。
//!
//! 所以这里守的是「**代码与模型不许悄悄漂移**」：
//! 少一列、丢唯一索引、默认值被删——`zperm model check` 与单测立刻红，
//! 而不是等到运行时才发现会话读不出来。
//!
//! # 用法
//!
//! ```text
//! zperm model check [modelPath]     # 默认 Entity/Model.xml
//! ```
//!
//! 退出码：0 = 全部检查通过；1 = 有 `PROBLEM=`；2 = 用法/读取错误。

const std = @import("std");
const zcode = @import("zcode");

/// 模型里的表名（`<Table Name="...">`）。
pub const EXPECTED_MODEL_NAME = "ZSession";

/// 数据库物理表名（`<Table TableName="...">`）。
pub const EXPECTED_TABLE = "ZPermissions_Session";

/// 模型级连接名（`<Option><ConnName>`）。
pub const EXPECTED_CONN = "Permissions";

/// 代码依赖的列（少一列就会出现「读不出会话」的运行期故障）。
pub const EXPECTED_COLUMNS = [_][]const u8{
    "Id",
    "SessionKey",
    "SessionValue",
    "ExpireAt",
    "CreateTime",
    "UpdateTime",
};

/// 必须有唯一索引的列（`SessionKey` 唯一：同一令牌只允许一条会话记录）。
pub const EXPECTED_UNIQUE_COLUMN = "SessionKey";

/// 必须有数据库默认值的列（`ExpireAt` = 0，历史库补列时不留 NULL）。
pub const EXPECTED_DEFAULT_COLUMN = "ExpireAt";

const MAX_PROBLEMS = 8;

pub const Report = struct {
    arena: std.heap.ArenaAllocator,
    problems: [MAX_PROBLEMS][]const u8 = undefined,
    problem_count: usize = 0,
    conn_name: ?[]const u8 = null,
    columns: usize = 0,
    indexes: usize = 0,

    pub fn ok(self: *const Report) bool {
        return self.problem_count == 0;
    }

    pub fn deinit(self: *Report) void {
        self.arena.deinit();
    }

    fn add(self: *Report, comptime fmt: []const u8, args: anytype) void {
        if (self.problem_count >= MAX_PROBLEMS) return;
        const text = std.fmt.allocPrint(self.arena.allocator(), fmt, args) catch return;
        self.problems[self.problem_count] = text;
        self.problem_count += 1;
    }
};

/// 解析模型并逐项核对期望结构。**不抛错**：一切异常都记进 `problems`（便于 CLI 一次性列全）。
pub fn check(gpa: std.mem.Allocator, model_path: []const u8) Report {
    var report = Report{ .arena = std.heap.ArenaAllocator.init(gpa) };

    var model = zcode.EntityModel.load(gpa, model_path) catch |e| {
        report.add("模型无法解析：{s}（路径 {s}）", .{ @errorName(e), model_path });
        return report;
    };
    defer model.deinit();

    // 连接名必须**复制**进 report 自己的 arena：`model` 在函数返回时 deinit，
    // 直接持有 `model.options.connName()` 会变成悬垂指针（实测读到 `UUUU...`）。
    report.conn_name = if (model.options.connName()) |c|
        (report.arena.allocator().dupe(u8, c) catch null)
    else
        null;

    const t = model.table(EXPECTED_MODEL_NAME) orelse {
        report.add("缺少表 {s}（模型里有 {d} 张表）", .{ EXPECTED_MODEL_NAME, model.tables.len });
        return report;
    };
    report.columns = t.columns.len;
    report.indexes = t.indexes.len;

    // ① 物理表名
    const phys = t.effectiveTableName();
    if (!std.mem.eql(u8, phys, EXPECTED_TABLE)) {
        report.add("表 {s} 的物理名是 {s}，期望 {s}", .{ EXPECTED_MODEL_NAME, phys, EXPECTED_TABLE });
    }

    // ② 连接名（表级优先、模型级兜底——与 Dal 的路由规则同一口径）
    const conn = model.tableConn(t) orelse "";
    if (conn.len == 0) {
        report.add("表 {s} 没有连接名（模型级 <Option><ConnName> 也缺失）", .{EXPECTED_MODEL_NAME});
    } else if (!std.ascii.eqlIgnoreCase(conn, EXPECTED_CONN)) {
        report.add("表 {s} 归属连接 {s}，期望 {s}", .{ EXPECTED_MODEL_NAME, conn, EXPECTED_CONN });
    }

    // ③ 列齐全
    for (EXPECTED_COLUMNS) |name| {
        if (t.column(name) == null) {
            report.add("表 {s} 缺少列 {s}", .{ EXPECTED_MODEL_NAME, name });
        }
    }

    // ④ SessionKey 唯一索引
    var has_unique = false;
    for (t.indexes) |idx| {
        if (!idx.unique) continue;
        for (idx.columns) |c| {
            if (std.ascii.eqlIgnoreCase(c, EXPECTED_UNIQUE_COLUMN)) has_unique = true;
        }
    }
    if (!has_unique) {
        report.add("表 {s} 缺少 {s} 的唯一索引（同一令牌会写入多条会话记录）", .{ EXPECTED_MODEL_NAME, EXPECTED_UNIQUE_COLUMN });
    }

    // ⑤ ExpireAt 必须有数据库默认值
    if (t.column(EXPECTED_DEFAULT_COLUMN)) |col| {
        if (col.default_value == null) {
            report.add("列 {s} 缺少 DefaultValue（补列时历史行会是 NULL）", .{EXPECTED_DEFAULT_COLUMN});
        }
    }

    return report;
}

test "模型守卫：仓库内 Entity/Model.xml 通过全部检查" {
    var report = check(std.testing.allocator, "Entity/Model.xml");
    defer report.deinit();

    if (!report.ok()) {
        for (report.problems[0..report.problem_count]) |p| {
            std.debug.print("[model] PROBLEM: {s}\n", .{p});
        }
    }
    try std.testing.expect(report.ok());
    try std.testing.expectEqualStrings(EXPECTED_CONN, report.conn_name.?);
}

test "模型守卫：模型被改坏时逐项报出（缺表 / 缺列 / 丢唯一索引 / 缺默认值）" {
    const broken =
        \\<?xml version="1.0" encoding="utf-8"?>
        \\<EntityModel xmlns="https://newlifex.com/Model202509.xsd" Version="1.0">
        \\  <Option><ConnName>Permissions</ConnName></Option>
        \\  <Tables>
        \\    <Table Name="ZSession" TableName="ZPermissions_Session">
        \\      <Columns>
        \\        <Column Name="Id" DataType="Int64" Identity="True" PrimaryKey="True" />
        \\        <Column Name="SessionKey" DataType="String" Length="512" />
        \\        <Column Name="ExpireAt" DataType="Int64" />
        \\      </Columns>
        \\      <Indexes><Index Columns="SessionKey" /></Indexes>
        \\    </Table>
        \\  </Tables>
        \\</EntityModel>
    ;

    const a = std.testing.allocator;

    // 写临时模型文件（用项目已有的临时名工具，避免并行时互相覆盖）
    const path = try zcode.File.UniqueTempName(a, "model-guard", ".xml");
    defer a.free(path);
    defer zcode.File.DeleteQuiet(path);

    {
        const io = std.testing.io;
        var file = try std.Io.Dir.cwd().createFile(io, path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, broken);
    }

    var report = check(a, path);
    defer report.deinit();

    try std.testing.expect(!report.ok());
    // 期望至少报出：缺列（SessionValue/CreateTime/UpdateTime）、唯一索引不唯一、ExpireAt 无默认值
    try std.testing.expect(report.problem_count >= 3);

    var saw_missing_column = false;
    var saw_non_unique = false;
    var saw_default = false;
    for (report.problems[0..report.problem_count]) |p| {
        if (std.mem.indexOf(u8, p, "缺少列") != null) saw_missing_column = true;
        if (std.mem.indexOf(u8, p, "唯一索引") != null) saw_non_unique = true;
        if (std.mem.indexOf(u8, p, "DefaultValue") != null) saw_default = true;
    }
    try std.testing.expect(saw_missing_column);
    try std.testing.expect(saw_non_unique);
    try std.testing.expect(saw_default);
}
