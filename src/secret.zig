//! JWT 密钥配置解析：`算法:密钥`。
//!
//! 严格对齐 C# `Pek.Permissions` / `NewLife.Web.JwtBuilder` 的取值口径：
//! `var ss = options.Secret.Split(':'); Algorithm = ss[0]; Secret = ss[1];`
//! —— 只取**第一个冒号后的第二段**，因此密钥本身不要包含冒号（`HS256:a:b` 的密钥是 `a`）。
//!
//! 算法比较大小写不敏感（C# 算法表是 `StringComparer.OrdinalIgnoreCase`；
//! Rust 端 `Pek.RPermissions` 同为 `eq_ignore_ascii_case`）。

const std = @import("std");

pub const ParseError = error{
    /// 没有冒号（C# `parts.Length < 2` → 配置无效）
    MissingSeparator,
    /// 非 HS256（三语言交集算法；Rust 端同样只支持 HS256）
    UnsupportedAlgorithm,
    /// 密钥为空（对齐 C# `Secret.IsNullOrEmpty()` 与 Rust 端「密钥不能为空」）
    EmptyKey,
};

pub const Secret = struct {
    /// 算法原文（比较用 `std.ascii.eqlIgnoreCase`）
    algorithm: []const u8,
    /// 密钥原文（即 HMAC 的 key 字节）
    key: []const u8,
};

/// 解析 `算法:密钥`。
pub fn parse(raw: []const u8) ParseError!Secret {
    const first = std.mem.indexOfScalar(u8, raw, ':') orelse return error.MissingSeparator;
    const rest = raw[first + 1 ..];

    // C# `Split(':')[1]`：只取第二段，后面的冒号丢弃
    const key = if (std.mem.indexOfScalar(u8, rest, ':')) |second| rest[0..second] else rest;
    const algorithm = raw[0..first];

    if (!std.ascii.eqlIgnoreCase(algorithm, "HS256")) return error.UnsupportedAlgorithm;
    if (key.len == 0) return error.EmptyKey;

    return .{ .algorithm = algorithm, .key = key };
}

/// 与 Rust 端 `Jwt::new` 完全一致的中文错误文案。
pub fn describe(err: ParseError) []const u8 {
    return switch (err) {
        error.MissingSeparator => "Jwt 密钥格式需为「算法:密钥」（如 HS256:xxxx）",
        error.UnsupportedAlgorithm => "暂不支持的 JWT 算法（当前仅 HS256）",
        error.EmptyKey => "JWT 密钥不能为空（对齐 C#「未设置密钥」）",
    };
}

test "secret: 正常解析与算法大小写不敏感" {
    const s = try parse("HS256:rcard-interop-key-2026");
    try std.testing.expectEqualStrings("HS256", s.algorithm);
    try std.testing.expectEqualStrings("rcard-interop-key-2026", s.key);

    const lower = try parse("hs256:key123");
    try std.testing.expectEqualStrings("key123", lower.key);
}

test "secret: 只取第二段（对齐 C# Split(':')[1]）" {
    const s = try parse("HS256:part1:part2");
    try std.testing.expectEqualStrings("part1", s.key);
}

test "secret: 非法输入" {
    try std.testing.expectError(error.MissingSeparator, parse("no-colon"));
    try std.testing.expectError(error.UnsupportedAlgorithm, parse("RS256:key123"));
    try std.testing.expectError(error.EmptyKey, parse("HS256:"));
}
