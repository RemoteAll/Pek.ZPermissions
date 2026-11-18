//! 标准 claims（Pek 生态约定；对齐 C# Pek 平台 payload 与 Rust `Pek.RPermissions::claims`）。
//!
//! 字段：`sub`（主体/用户标识）、`name`（显示名）、`from`（来源：`panel` 管理端 / `app` 用户端）、
//! `clientType`（客户端类型：`admin` / `app`）。

const std = @import("std");

pub const Claims = struct {
    /// 主体（用户标识；始终为字符串 —— 与 C# 端 `sub` 形态一致）
    sub: []const u8,
    name: []const u8 = "",
    from: []const u8 = "",
    client_type: []const u8 = "",

    /// 管理端 claims（`from=panel`、`clientType=admin`；sub/name 均为用户名）。
    pub fn admin(user: []const u8) Claims {
        return .{ .sub = user, .name = user, .from = "panel", .client_type = "admin" };
    }

    /// 用户端 claims（`from=app`、`clientType=app`）。
    pub fn app(user_id: []const u8, name: []const u8) Claims {
        return .{ .sub = user_id, .name = name, .from = "app", .client_type = "app" };
    }

    /// 转 JSON 负载（键序：sub / name / from / clientType —— 与 Rust 端一致）。
    pub fn toMap(self: Claims, allocator: std.mem.Allocator) std.mem.Allocator.Error!std.json.ObjectMap {
        var map: std.json.ObjectMap = .{};
        try map.put(allocator, "sub", .{ .string = self.sub });
        try map.put(allocator, "name", .{ .string = self.name });
        try map.put(allocator, "from", .{ .string = self.from });
        try map.put(allocator, "clientType", .{ .string = self.client_type });
        return map;
    }

    /// 从负载解析（`sub` 必填；其余缺失时为空串 —— 宽容解析，便于跨系统对接）。
    pub fn fromMap(map: *const std.json.ObjectMap) error{MissingSubject}!Claims {
        const field = struct {
            fn get(m: *const std.json.ObjectMap, k: []const u8) []const u8 {
                const v = m.get(k) orelse return "";
                return switch (v) {
                    .string => |s| s,
                    else => "",
                };
            }
        };
        const sub = field.get(map, "sub");
        if (sub.len == 0) return error.MissingSubject;

        return .{
            .sub = sub,
            .name = field.get(map, "name"),
            .from = field.get(map, "from"),
            .client_type = field.get(map, "clientType"),
        };
    }
};

test "claims: admin / app 与往返" {
    const admin = Claims.admin("alice");
    try std.testing.expectEqualStrings("panel", admin.from);
    try std.testing.expectEqualStrings("admin", admin.client_type);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const map = try admin.toMap(arena.allocator());
    const back = try Claims.fromMap(&map);
    try std.testing.expectEqualStrings("alice", back.sub);
    try std.testing.expectEqualStrings("alice", back.name);

    const app = Claims.app("42", "bob");
    const map2 = try app.toMap(arena.allocator());
    const back2 = try Claims.fromMap(&map2);
    try std.testing.expectEqualStrings("42", back2.sub);
    try std.testing.expectEqualStrings("bob", back2.name);
}

test "claims: 仅 sub 必填（宽容解析）" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var map: std.json.ObjectMap = .{};
    try map.put(arena.allocator(), "sub", .{ .string = "7" });

    const c = try Claims.fromMap(&map);
    try std.testing.expectEqualStrings("", c.name);

    const empty: std.json.ObjectMap = .{};
    try std.testing.expectError(error.MissingSubject, Claims.fromMap(&empty));
}
