//! 互操作测试：以 C# / Rust 实测产出的黄金样本为基准，证明三语言 JWT 可互相解析。

const std = @import("std");
const jwt = @import("jwt.zig");
const claims_mod = @import("claims.zig");

const testing = std.testing;

const INTEROP_SECRET = "HS256:rcard-interop-key-2026";

/// C#（`NewLife.Web.JwtBuilder`）实测生成的黄金样本
/// （2026-10-10 `Pek.RCard/tools/csharp/JwtInterop`，同一样本已固化在 Rust
/// `Pek.RPermissions::jwt` 测试中）。
///
/// payload = {"sub":"42","name":"alice","from":"rcard","clientType":"app",
///            "iss":"Pek.RCard","exp":1791600338,"iat":1791593138,"jti":"42"}
const CSHARP_GOLDEN_TOKEN = "eyJhbGciOiJIUzI1NiJ9." ++
    "eyJzdWIiOiI0MiIsIm5hbWUiOiJhbGljZSIsImZyb20iOiJyY2FyZCIsImNsaWVudFR5cGUiOiJhcHAiLCJpc3MiOiJQZWsuUkNhcmQiLCJleHAiOjE3OTE2MDAzMzgsImlhdCI6MTc5MTU5MzEzOCwianRpIjoiNDIifQ." ++
    "4fiepkRzWbMCix2zjk3TxRnvQfvwO0hzIGzPCSyxv6M";

const GOLDEN_IAT: i64 = 1791593138;
const GOLDEN_EXP: i64 = 1791600338;

fn str(map: *const std.json.ObjectMap, key: []const u8) []const u8 {
    const v = map.get(key) orelse return "";
    return switch (v) {
        .string => |s| s,
        else => "",
    };
}

fn int(map: *const std.json.ObjectMap, key: []const u8) ?i64 {
    const v = map.get(key) orelse return null;
    return switch (v) {
        .integer => |i| i,
        else => null,
    };
}

test "C# 黄金令牌：Zig 验签 + 解析（C# 签发 → Zig 验证）" {
    var builder = try jwt.Builder.fromSecret(INTEROP_SECRET);

    var decoded = try builder.validate(testing.allocator, CSHARP_GOLDEN_TOKEN, GOLDEN_IAT + 60);
    defer decoded.deinit();

    try testing.expectEqualStrings("42", str(&decoded.payload, "sub"));
    try testing.expectEqualStrings("alice", str(&decoded.payload, "name"));
    try testing.expectEqualStrings("rcard", str(&decoded.payload, "from"));
    try testing.expectEqualStrings("Pek.RCard", str(&decoded.payload, "iss"));
    try testing.expectEqual(@as(?i64, GOLDEN_EXP), int(&decoded.payload, "exp"));

    // header 必须是 C# 同款（紧凑、无 typ）
    try testing.expectEqualStrings("HS256", str(&decoded.header, "alg"));
    try testing.expect(decoded.header.get("typ") == null);
}

test "C# 黄金令牌：过期 / 篡改 / 换密钥" {
    var builder = try jwt.Builder.fromSecret(INTEROP_SECRET);

    try testing.expectError(error.Expired, builder.validate(testing.allocator, CSHARP_GOLDEN_TOKEN, GOLDEN_EXP + 1));

    const tampered = "eyJhbGciOiJIUzI1NiJ9." ++
        "eyJzdWIiOiI0MyIsIm5hbWUiOiJhbGljZSIsImZyb20iOiJyY2FyZCIsImNsaWVudFR5cGUiOiJhcHAiLCJpc3MiOiJQZWsuUkNhcmQiLCJleHAiOjE3OTE2MDAzMzgsImlhdCI6MTc5MTU5MzEzOCwianRpIjoiNDIifQ." ++
        "4fiepkRzWbMCix2zjk3TxRnvQfvwO0hzIGzPCSyxv6M";
    try testing.expectError(error.SignatureMismatch, builder.validate(testing.allocator, tampered, GOLDEN_IAT + 60));

    var other = try jwt.Builder.fromSecret("HS256:another-key");
    try testing.expectError(error.SignatureMismatch, other.validate(testing.allocator, CSHARP_GOLDEN_TOKEN, GOLDEN_IAT + 60));
}

test "签发往返：header 恰为 C# 同款，claims 与时间正确" {
    var builder = try jwt.Builder.fromSecret(INTEROP_SECRET);
    builder.expire = GOLDEN_IAT + 7200;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var payload: std.json.ObjectMap = .{};
    try payload.put(arena.allocator(), "sub", .{ .string = "42" });
    try payload.put(arena.allocator(), "name", .{ .string = "alice" });
    try payload.put(arena.allocator(), "from", .{ .string = "rcard" });

    const token = try builder.encodeObject(testing.allocator, &payload, GOLDEN_IAT);
    defer testing.allocator.free(token);

    var segs = std.mem.splitScalar(u8, token, '.');
    const header_seg = segs.next().?;
    _ = segs.next().?;
    _ = segs.next().?;
    try testing.expect(segs.next() == null);

    // header 段解码后必须字节级等于 `{"alg":"HS256"}`
    const hdr_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(header_seg) catch unreachable;
    try testing.expectEqual(@as(usize, 15), hdr_len);

    var decoded_header = try builder.parseUnverified(testing.allocator, token);
    defer decoded_header.deinit();
    try testing.expectEqualStrings("HS256", str(&decoded_header.header, "alg"));

    var decoded = try builder.validate(testing.allocator, token, GOLDEN_IAT + 60);
    defer decoded.deinit();
    try testing.expectEqualStrings("42", str(&decoded.payload, "sub"));
    try testing.expectEqual(@as(?i64, GOLDEN_IAT), int(&decoded.payload, "iat"));
    try testing.expectEqual(@as(?i64, GOLDEN_IAT + 7200), int(&decoded.payload, "exp"));

    // 过期（now > exp 才过期，等值仍有效 —— 对齐 C# `Expire < now`）
    var still_ok = try builder.validate(testing.allocator, token, GOLDEN_IAT + 7200);
    still_ok.deinit();
    try testing.expectError(
        error.Expired,
        builder.validate(testing.allocator, token, GOLDEN_IAT + 7200 + 1),
    );
}

test "已显式提供的声明不被覆盖（对齐 C# ContainsKey 规则）" {
    var builder = try jwt.Builder.fromSecret(INTEROP_SECRET);
    builder.issuer = "Pek.RCard";
    builder.expire = GOLDEN_EXP;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var payload: std.json.ObjectMap = .{};
    try payload.put(arena.allocator(), "exp", .{ .integer = 1234567890 });
    try payload.put(arena.allocator(), "iss", .{ .string = "custom-iss" });

    const token = try builder.encodeObject(testing.allocator, &payload, GOLDEN_IAT);
    defer testing.allocator.free(token);

    var decoded = try builder.parseUnverified(testing.allocator, token);
    defer decoded.deinit();
    try testing.expectEqual(@as(?i64, 1234567890), int(&decoded.payload, "exp"));
    try testing.expectEqualStrings("custom-iss", str(&decoded.payload, "iss"));
}

test "签名段必须是规范形态（对齐 C# 字符串精确比较）" {
    var builder = try jwt.Builder.fromSecret(INTEROP_SECRET);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var payload: std.json.ObjectMap = .{};
    try payload.put(arena.allocator(), "sub", .{ .string = "42" });

    const token = try builder.encodeObject(testing.allocator, &payload, GOLDEN_IAT);
    defer testing.allocator.free(token);

    // 末尾补 `=` → 拒绝
    const padded = try std.fmt.allocPrint(testing.allocator, "{s}=", .{token});
    defer testing.allocator.free(padded);
    try testing.expectError(error.SignatureMismatch, builder.validate(testing.allocator, padded, GOLDEN_IAT + 1));

    // 签名段插入换行 → 拒绝
    const last_dot = std.mem.lastIndexOfScalar(u8, token, '.').?;
    const head = token[0 .. last_dot + 1];
    const sig = token[last_dot + 1 ..];
    const spaced = try std.fmt.allocPrint(testing.allocator, "{s}{s}\n{s}", .{ head, sig[0..5], sig[5..] });
    defer testing.allocator.free(spaced);
    try testing.expectError(error.SignatureMismatch, builder.validate(testing.allocator, spaced, GOLDEN_IAT + 1));
}

test "格式错误与未设置密钥" {
    var builder = try jwt.Builder.fromSecret(INTEROP_SECRET);
    try testing.expectError(error.InvalidFormat, builder.validate(testing.allocator, "a.b", 0));
    try testing.expectError(error.InvalidFormat, builder.validate(testing.allocator, "a.b.c.d", 0));

    var empty = jwt.Builder{};
    try testing.expectError(error.MissingSecret, empty.validate(testing.allocator, CSHARP_GOLDEN_TOKEN, 0));
}

test "nbf 未生效（对齐 C# `now < NotBefore`）" {
    var builder = try jwt.Builder.fromSecret(INTEROP_SECRET);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var payload: std.json.ObjectMap = .{};
    try payload.put(arena.allocator(), "nbf", .{ .integer = GOLDEN_IAT + 3600 });

    const token = try builder.encodeObject(testing.allocator, &payload, GOLDEN_IAT);
    defer testing.allocator.free(token);

    try testing.expectError(error.NotYetValid, builder.validate(testing.allocator, token, GOLDEN_IAT + 60));
    var ok = try builder.validate(testing.allocator, token, GOLDEN_IAT + 3600);
    ok.deinit();
}

test "Jwt 便捷层：注入 iss/aud/exp/iat（对齐 Rust encode_at）" {
    var j = try jwt.Jwt.init(.{
        .secret = "HS256:opt-key",
        .issuer = "Pek.RCard",
        .audience = "rcard-clients",
        .access_expire_minutes = 60,
    });

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var payload: std.json.ObjectMap = .{};
    const token = try j.encodeWith(testing.allocator, &payload, 60, GOLDEN_IAT);
    defer testing.allocator.free(token);

    var decoded = try j.validate(testing.allocator, token, GOLDEN_IAT + 1);
    defer decoded.deinit();
    try testing.expectEqualStrings("Pek.RCard", str(&decoded.payload, "iss"));
    try testing.expectEqualStrings("rcard-clients", str(&decoded.payload, "aud"));
    try testing.expectEqual(@as(?i64, GOLDEN_IAT + 3600), int(&decoded.payload, "exp"));
    try testing.expectEqual(@as(?i64, GOLDEN_IAT), int(&decoded.payload, "iat"));
}

test "exp 溢出饱和" {
    var j = try jwt.Jwt.init(.{ .secret = INTEROP_SECRET });
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var payload: std.json.ObjectMap = .{};
    const token = try j.encodeWith(testing.allocator, &payload, std.math.maxInt(i64), GOLDEN_IAT);
    defer testing.allocator.free(token);

    var decoded = try j.validate(testing.allocator, token, GOLDEN_IAT + 1);
    defer decoded.deinit();
    try testing.expectEqual(@as(?i64, std.math.maxInt(i64)), int(&decoded.payload, "exp"));
}

test "Claims 标准负载往返" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const c = claims_mod.Claims.admin("alice");
    const map = try c.toMap(arena.allocator());

    var builder = try jwt.Builder.fromSecret(INTEROP_SECRET);
    const token = try builder.encodeObject(testing.allocator, &map, GOLDEN_IAT);
    defer testing.allocator.free(token);

    var decoded = try builder.validate(testing.allocator, token, GOLDEN_IAT + 1);
    defer decoded.deinit();

    const back = try claims_mod.Claims.fromMap(&decoded.payload);
    try testing.expectEqualStrings("alice", back.sub);
    try testing.expectEqualStrings("panel", back.from);
    try testing.expectEqualStrings("admin", back.client_type);
}

/// Rust `Pek.RPermissions` 实产令牌（2026-11-18，
/// `cargo run --example jwt_tool -- gen HS256:rcard-interop-key-2026 @claims.json 120`）。
/// payload = {"sub":"42","name":"alice","from":"rcard","clientType":"app",
///            "exp":1794999809,"iat":1794992609}
const RUST_GOLDEN_TOKEN = "eyJhbGciOiJIUzI1NiJ9." ++
    "eyJzdWIiOiI0MiIsIm5hbWUiOiJhbGljZSIsImZyb20iOiJyY2FyZCIsImNsaWVudFR5cGUiOiJhcHAiLCJleHAiOjE3OTQ5OTk4MDksImlhdCI6MTc5NDk5MjYwOX0." ++
    "vppHLGwYZCsXHPPBIKzbCr09BqFgZO9p_-wUItd2m4s";

const RUST_IAT: i64 = 1794992609;
const RUST_EXP: i64 = 1794999809;

test "Rust 实产令牌：Zig 验签 + 解析（Rust 签发 → Zig 验证）" {
    var builder = try jwt.Builder.fromSecret(INTEROP_SECRET);

    var decoded = try builder.validate(testing.allocator, RUST_GOLDEN_TOKEN, RUST_IAT + 60);
    defer decoded.deinit();

    try testing.expectEqualStrings("42", str(&decoded.payload, "sub"));
    try testing.expectEqualStrings("alice", str(&decoded.payload, "name"));
    try testing.expectEqualStrings("rcard", str(&decoded.payload, "from"));
    try testing.expectEqualStrings("app", str(&decoded.payload, "clientType"));
    try testing.expectEqual(@as(?i64, RUST_EXP), int(&decoded.payload, "exp"));
    try testing.expectEqual(@as(?i64, RUST_IAT), int(&decoded.payload, "iat"));

    try testing.expectError(error.Expired, builder.validate(testing.allocator, RUST_GOLDEN_TOKEN, RUST_EXP + 1));
}

test "字节级复现 Rust encode_with（同输入同时间 → 完全相同的令牌）" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var claims: std.json.ObjectMap = .{};
    try claims.put(arena.allocator(), "sub", .{ .string = "42" });
    try claims.put(arena.allocator(), "name", .{ .string = "alice" });
    try claims.put(arena.allocator(), "from", .{ .string = "rcard" });
    try claims.put(arena.allocator(), "clientType", .{ .string = "app" });

    var j = try jwt.Jwt.init(.{ .secret = INTEROP_SECRET });
    const token = try j.encodeWith(testing.allocator, &claims, 120, RUST_IAT);
    defer testing.allocator.free(token);

    try testing.expectEqualStrings(RUST_GOLDEN_TOKEN, token);
}

test "字节级复现 C# JwtBuilder（同输入同时间 → 完全相同的令牌）" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // C# 工具的 claims JSON 是 {sub,name,from,clientType}，
    // JwtBuilder{Issuer="Pek.RCard", Subject="42", Id="42", Expire=iat+7200}
    var payload: std.json.ObjectMap = .{};
    try payload.put(arena.allocator(), "sub", .{ .string = "42" });
    try payload.put(arena.allocator(), "name", .{ .string = "alice" });
    try payload.put(arena.allocator(), "from", .{ .string = "rcard" });
    try payload.put(arena.allocator(), "clientType", .{ .string = "app" });

    var builder = try jwt.Builder.fromSecret(INTEROP_SECRET);
    builder.issuer = "Pek.RCard";
    builder.subject = "42";
    builder.id = "42";
    builder.expire = GOLDEN_EXP;

    const token = try builder.encodeObject(testing.allocator, &payload, GOLDEN_IAT);
    defer testing.allocator.free(token);

    try testing.expectEqualStrings(CSHARP_GOLDEN_TOKEN, token);
}
