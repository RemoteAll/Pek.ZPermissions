//! NewLife `JwtBuilder`（C#）/ `Pek.RPermissions::jwt`（Rust）兼容 JWT（HS256）。
//!
//! # 字节级契约（三语言必须完全一致）
//!
//! - **Header**：紧凑 JSON，默认 `{"alg":"HS256"}`（不注入 `typ`；设置了 `typ` 时追加
//!   `{"alg":"HS256","typ":"JWT"}`）。键序固定 alg → typ（对齐 C# 字典插入序）。
//! - **Payload**：紧凑 JSON（无空格）；`exp` / `iat` / `nbf` 为 **Unix 秒**。
//!   C# 端 `JwtBuilder.Encode` 的注入顺序为 iss → sub → aud → exp → nbf → iat → jti，
//!   且**已存在的声明不被覆盖**；本实现同序同规则。
//! - **签名**：`HMAC-SHA256(key = 密钥的 UTF-8 字节, data = "header.payload")`，
//!   输出 **base64url 无填充**（`+`→`-`、`/`→`_`、去 `=`）。
//!   C# 依据是 `JwtBuilder` 注册的 `HS256 => d.SHA256(s.GetBytes())`，而 NewLife
//!   `SecurityHelper.SHA256(data, key)` 在 key 非 null 时就是 `HMACSHA256.HashData(key, data)`。
//! - **验签**：常量时间比较摘要，并且**签名段必须是规范形态**（URL 安全、无填充、无空白）——
//!   与 C# `enc(...).ToUrlBase64() == ts[2]` 的字符串精确比较一致（换拼写的同一令牌会被拒绝，
//!   否则吊销名单按令牌原文作键会对不上）。
//! - **时间检查**：`now > exp` → 过期；`now < nbf` → 未生效（仅当声明存在）。
//! - **算法**：只按固定 HS256 验签，**不读取 header 中的 alg 决定算法**（规避 `alg=none` 类攻击）；
//!   可选 `strict_header_alg` 额外校验 header 声明必须是 HS256。
//!
//! 注：Rust `serde_json` 默认 `Map` 为 BTreeMap（键按字典序），C# 与 Zig 为插入序，
//! 因此三方**生成的 payload 字节可能不同**；互操作依赖「各自用原文签名、对方按原文验签」，
//! 不依赖键序。需要绝对字节一致的对拍场景请使用 `encodeVerbatim`（原样签名）。

const std = @import("std");
const zzig = @import("zzig");
const secret_mod = @import("secret.zig");

pub const Secret = secret_mod.Secret;
pub const parseSecret = secret_mod.parse;
pub const SecretError = secret_mod.ParseError;

/// 编解码错误（`message()` 给出与 C# / Rust 一致的中文文案）。
pub const Error = error{
    /// "JWT格式不正确"
    InvalidFormat,
    /// "未设置密钥"
    MissingSecret,
    /// "暂不支持的 JWT 算法（当前仅 HS256）"
    UnsupportedAlgorithm,
    /// "签名解码失败"
    SignatureDecode,
    /// "签名验证失败"
    SignatureMismatch,
    /// "负载解码失败"
    PayloadDecode,
    /// "负载解析失败"
    PayloadParse,
    /// "令牌已过期"
    Expired,
    /// "令牌未生效"
    NotYetValid,
    OutOfMemory,
};

pub fn message(err: Error) []const u8 {
    return switch (err) {
        error.InvalidFormat => "JWT格式不正确",
        error.MissingSecret => "未设置密钥",
        error.UnsupportedAlgorithm => "暂不支持的 JWT 算法（当前仅 HS256）",
        error.SignatureDecode => "签名解码失败",
        error.SignatureMismatch => "签名验证失败",
        error.PayloadDecode => "负载解码失败",
        error.PayloadParse => "负载解析失败",
        error.Expired => "令牌已过期",
        error.NotYetValid => "令牌未生效",
        error.OutOfMemory => "内存不足",
    };
}

/// JWT 构建/校验器。字段语义对齐 C# `NewLife.Web.JwtBuilder`。
pub const Builder = struct {
    /// HMAC 密钥字节（原文的 UTF-8 字节）
    key: []const u8 = "",
    /// 算法（仅 HS256；大小写不敏感）
    algorithm: []const u8 = "HS256",
    /// 令牌类型（`typ`）；为 null 时 header 不写 typ（对齐 C# 默认）
    typ: ?[]const u8 = null,

    issuer: ?[]const u8 = null,
    subject: ?[]const u8 = null,
    audience: ?[]const u8 = null,
    /// 有效期（Unix 秒；null = 不注入 exp）
    expire: ?i64 = null,
    /// 生效时间（Unix 秒；null = 不注入 nbf）
    not_before: ?i64 = null,
    /// 颁发时间（Unix 秒；null = 使用调用方传入的 now）
    issued_at: ?i64 = null,
    /// 标识（`jti`）
    id: ?[]const u8 = null,

    /// 额外要求 header 的 `alg` 必须为 HS256（默认关闭，与 Rust 端一致）
    strict_header_alg: bool = false,

    /// 从 `算法:密钥` 配置构造。
    pub fn fromSecret(raw: []const u8) SecretError!Builder {
        const s = try secret_mod.parse(raw);
        return .{ .key = s.key, .algorithm = s.algorithm };
    }

    /// 签发令牌：按 C# 规则注入声明后签名。
    ///
    /// `payload` 的键保持调用方顺序；缺失的声明按 iss → sub → aud → exp → nbf → iat → jti 追加。
    pub fn encodeObject(
        self: *const Builder,
        allocator: std.mem.Allocator,
        payload: *const std.json.ObjectMap,
        now_ts: i64,
    ) Error![]u8 {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var map: std.json.ObjectMap = .{};
        var it = payload.iterator();
        while (it.next()) |entry| {
            try map.put(a, entry.key_ptr.*, entry.value_ptr.*);
        }

        try self.injectClaims(a, &map, now_ts);

        const payload_json = std.json.Stringify.valueAlloc(
            a,
            std.json.Value{ .object = map },
            .{},
        ) catch return error.OutOfMemory;

        return self.signParts(allocator, payload_json);
    }

    /// 签发令牌：从 JSON 文本解析负载后按 C# 规则注入声明。
    pub fn encodeJson(
        self: *const Builder,
        allocator: std.mem.Allocator,
        payload_json: []const u8,
        now_ts: i64,
    ) Error![]u8 {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        const parsed = std.json.parseFromSliceLeaky(std.json.Value, a, payload_json, .{}) catch
            return error.PayloadParse;
        const map = switch (parsed) {
            .object => |m| m,
            else => return error.PayloadParse,
        };

        return self.encodeObject(allocator, &map, now_ts);
    }

    /// 原样签名：不注入任何声明、不重排键序（跨语言对拍最稳的口径）。
    pub fn encodeVerbatim(
        self: *const Builder,
        allocator: std.mem.Allocator,
        payload_json: []const u8,
    ) Error![]u8 {
        return self.signParts(allocator, payload_json);
    }

    /// 校验令牌（验签 + 时间检查），返回解析后的 header / payload。
    ///
    /// 调用方负责 `Decoded.deinit()`。
    pub fn validate(
        self: *const Builder,
        allocator: std.mem.Allocator,
        token: []const u8,
        now_ts: i64,
    ) Error!Decoded {
        if (self.key.len == 0) return error.MissingSecret;
        if (!std.ascii.eqlIgnoreCase(self.algorithm, "HS256")) return error.UnsupportedAlgorithm;

        var segs_buf: [3][]const u8 = undefined;
        const segs = splitToken(token, &segs_buf) orelse return error.InvalidFormat;

        // 1) 验签（先验签再解析，避免把攻击者可控的 JSON 交给解析器做无用功）
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const a = arena.allocator();

        // 签名覆盖的原文是 `header.payload`（点号必须在内）
        const signed_data = std.fmt.allocPrint(a, "{s}.{s}", .{ segs[0], segs[1] }) catch
            return error.OutOfMemory;
        const expect = hmacSha256(self.key, signed_data, "");
        const given = base64DecodeLenient(a, segs[2]) catch return error.SignatureDecode;
        if (!zzig.hash.constantTimeEql(expect[0..], given)) return error.SignatureMismatch;

        // 签名段必须是规范形态（URL 安全、无填充、无空白）
        const canonical = base64UrlNoPad(a, given[0..]) catch return error.OutOfMemory;
        if (!std.mem.eql(u8, canonical, segs[2])) return error.SignatureMismatch;

        // 2) 解析 header（可选严格校验 alg）
        const header_value = std.json.parseFromSliceLeaky(std.json.Value, a, decodeSegment(a, segs[0]) catch
            return error.PayloadDecode, .{}) catch return error.PayloadParse;
        const header = switch (header_value) {
            .object => |m| m,
            else => return error.PayloadParse,
        };
        if (self.strict_header_alg) {
            const alg = header.get("alg") orelse return error.SignatureMismatch;
            const alg_text = switch (alg) {
                .string => |s| s,
                else => return error.SignatureMismatch,
            };
            if (!std.ascii.eqlIgnoreCase(alg_text, "HS256")) return error.SignatureMismatch;
        }

        // 3) 解析负载
        const payload_value = std.json.parseFromSliceLeaky(std.json.Value, a, decodeSegment(a, segs[1]) catch
            return error.PayloadDecode, .{}) catch return error.PayloadParse;
        const payload = switch (payload_value) {
            .object => |m| m,
            else => return error.PayloadParse,
        };

        // 4) 时间检查（对齐 C# `TryDecode`：仅当声明存在）
        if (payload.get("exp")) |exp| {
            if (jsonToInt(exp)) |exp_ts| {
                if (now_ts > exp_ts) return error.Expired;
            }
        }
        if (payload.get("nbf")) |nbf| {
            if (jsonToInt(nbf)) |nbf_ts| {
                if (now_ts < nbf_ts) return error.NotYetValid;
            }
        }

        return .{ .arena = arena, .header = header, .payload = payload };
    }

    /// 仅解析（**不验签**，仅用于调试 / `inspect`）。生产校验一律走 `validate`。
    pub fn parseUnverified(
        self: *const Builder,
        allocator: std.mem.Allocator,
        token: []const u8,
    ) Error!Decoded {
        _ = self;
        var segs_buf: [3][]const u8 = undefined;
        const segs = splitToken(token, &segs_buf) orelse return error.InvalidFormat;

        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const a = arena.allocator();

        const header_value = std.json.parseFromSliceLeaky(std.json.Value, a, decodeSegment(a, segs[0]) catch
            return error.PayloadDecode, .{}) catch return error.PayloadParse;
        const header = switch (header_value) {
            .object => |m| m,
            else => return error.PayloadParse,
        };

        const payload_value = std.json.parseFromSliceLeaky(std.json.Value, a, decodeSegment(a, segs[1]) catch
            return error.PayloadDecode, .{}) catch return error.PayloadParse;
        const payload = switch (payload_value) {
            .object => |m| m,
            else => return error.PayloadParse,
        };

        return .{ .arena = arena, .header = header, .payload = payload };
    }

    // ---------- 内部实现 ----------

    fn injectClaims(
        self: *const Builder,
        arena: std.mem.Allocator,
        map: *std.json.ObjectMap,
        now_ts: i64,
    ) Error!void {
        if (!std.ascii.eqlIgnoreCase(self.algorithm, "HS256")) return error.UnsupportedAlgorithm;

        if (self.issuer) |v| try putIfAbsent(arena, map, "iss", .{ .string = v });
        if (self.subject) |v| try putIfAbsent(arena, map, "sub", .{ .string = v });
        if (self.audience) |v| try putIfAbsent(arena, map, "aud", .{ .string = v });
        if (self.expire) |v| try putIfAbsent(arena, map, "exp", .{ .integer = v });
        if (self.not_before) |v| try putIfAbsent(arena, map, "nbf", .{ .integer = v });
        try putIfAbsent(arena, map, "iat", .{ .integer = self.issued_at orelse now_ts });
        if (self.id) |v| try putIfAbsent(arena, map, "jti", .{ .string = v });
    }

    fn signParts(
        self: *const Builder,
        allocator: std.mem.Allocator,
        payload_json: []const u8,
    ) Error![]u8 {
        if (self.key.len == 0) return error.MissingSecret;
        if (!std.ascii.eqlIgnoreCase(self.algorithm, "HS256")) return error.UnsupportedAlgorithm;

        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        // Header：紧凑 JSON，键序 alg → typ（对齐 C#）
        var hdr: std.json.ObjectMap = .{};
        try hdr.put(a, "alg", .{ .string = self.algorithm });
        if (self.typ) |t| try hdr.put(a, "typ", .{ .string = t });
        const header_json = std.json.Stringify.valueAlloc(a, std.json.Value{ .object = hdr }, .{}) catch
            return error.OutOfMemory;

        const header_b64 = try base64UrlNoPad(a, header_json);
        const payload_b64 = try base64UrlNoPad(a, payload_json);

        const data = std.fmt.allocPrint(a, "{s}.{s}", .{ header_b64, payload_b64 }) catch
            return error.OutOfMemory;
        const sig = hmacSha256(self.key, data, "");
        const sig_b64 = try base64UrlNoPad(a, sig[0..]);

        return std.fmt.allocPrint(allocator, "{s}.{s}", .{ data, sig_b64 }) catch error.OutOfMemory;
    }
};

/// 校验结果（header / payload 均指向同一 arena）。
pub const Decoded = struct {
    arena: std.heap.ArenaAllocator,
    header: std.json.ObjectMap,
    payload: std.json.ObjectMap,

    pub fn deinit(self: *Decoded) void {
        self.arena.deinit();
    }
};

// ---------- 便捷层（对齐 Rust `Pek.RPermissions` 的 Jwt / JwtOptions） ----------

pub const Options = struct {
    /// 密钥配置（`算法:密钥`）
    secret: []const u8,
    issuer: ?[]const u8 = null,
    audience: ?[]const u8 = null,
    /// 访问令牌有效期（分钟；默认 120 —— 对齐 NewLife `JwtBuilder` 默认 2 小时）
    access_expire_minutes: i64 = 120,
    /// 刷新令牌有效期（分钟；预留，对齐 Rust 端字段）
    refresh_expire_minutes: i64 = 120,
};

pub const Jwt = struct {
    options: Options,
    key: []const u8,

    pub fn init(options: Options) Error!Jwt {
        const s = secret_mod.parse(options.secret) catch |e| return switch (e) {
            error.MissingSeparator => error.InvalidFormat,
            error.UnsupportedAlgorithm => error.UnsupportedAlgorithm,
            error.EmptyKey => error.MissingSecret,
        };
        return .{ .options = options, .key = s.key };
    }

    /// 签发（有效期取 `options.access_expire_minutes`）。
    pub fn encode(
        self: *const Jwt,
        allocator: std.mem.Allocator,
        claims: *const std.json.ObjectMap,
        now_ts: i64,
    ) Error![]u8 {
        return self.encodeWith(allocator, claims, self.options.access_expire_minutes, now_ts);
    }

    /// 以指定有效期（分钟）签发。
    ///
    /// 注入规则对齐 Rust `Jwt::encode_at`：`iss` / `aud` / `exp = now + 分钟*60` / `iat = now`，
    /// 已存在的键不覆盖。
    pub fn encodeWith(
        self: *const Jwt,
        allocator: std.mem.Allocator,
        claims: *const std.json.ObjectMap,
        expire_minutes: i64,
        now_ts: i64,
    ) Error![]u8 {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var map: std.json.ObjectMap = .{};
        var it = claims.iterator();
        while (it.next()) |entry| {
            try map.put(a, entry.key_ptr.*, entry.value_ptr.*);
        }

        if (self.options.issuer) |v| try putIfAbsent(a, &map, "iss", .{ .string = v });
        if (self.options.audience) |v| try putIfAbsent(a, &map, "aud", .{ .string = v });
        try putIfAbsent(a, &map, "exp", .{ .integer = saturatingAdd(
            now_ts,
            saturatingMul(expire_minutes, 60),
        ) });
        try putIfAbsent(a, &map, "iat", .{ .integer = now_ts });

        const payload_json = std.json.Stringify.valueAlloc(a, std.json.Value{ .object = map }, .{}) catch
            return error.OutOfMemory;

        const builder = Builder{
            .key = self.key,
            .algorithm = "HS256",
            .issuer = null, // 已在上方注入
            .audience = null,
            .expire = null,
            .issued_at = now_ts,
        };
        return builder.encodeVerbatim(allocator, payload_json);
    }

    pub fn validate(
        self: *const Jwt,
        allocator: std.mem.Allocator,
        token: []const u8,
        now_ts: i64,
    ) Error!Decoded {
        const builder = Builder{ .key = self.key, .algorithm = "HS256" };
        return builder.validate(allocator, token, now_ts);
    }
};

// ---------- 基础工具 ----------

fn putIfAbsent(
    arena: std.mem.Allocator,
    map: *std.json.ObjectMap,
    name: []const u8,
    value: std.json.Value,
) Error!void {
    if (findKeyIgnoreCase(map, name) != null) return;
    const key = arena.dupe(u8, name) catch return error.OutOfMemory;
    map.put(arena, key, value) catch return error.OutOfMemory;
}

fn findKeyIgnoreCase(map: *const std.json.ObjectMap, name: []const u8) ?usize {
    const keys = map.keys();
    var i: usize = 0;
    while (i < keys.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(keys[i], name)) return i;
    }
    return null;
}

fn splitToken(token: []const u8, buf: *[3][]const u8) ?[3][]const u8 {
    var it = std.mem.splitScalar(u8, token, '.');
    var i: usize = 0;
    while (it.next()) |seg| {
        if (i == 3) return null; // 超过三段
        buf[i] = seg;
        i += 1;
    }
    if (i != 3) return null;
    return buf.*;
}

fn decodeSegment(arena: std.mem.Allocator, seg: []const u8) Error![]const u8 {
    return base64DecodeLenient(arena, seg) catch error.PayloadDecode;
}

fn hmacSha256(key: []const u8, a: []const u8, b: []const u8) [32]u8 {
    var mac = std.crypto.auth.hmac.sha2.HmacSha256.init(key);
    mac.update(a);
    mac.update(b);
    var out: [32]u8 = undefined;
    mac.final(&out);
    return out;
}

fn base64UrlNoPad(arena: std.mem.Allocator, data: []const u8) Error![]u8 {
    const enc = std.base64.url_safe_no_pad.Encoder;
    const size = enc.calcSize(data.len);
    const out = arena.alloc(u8, size) catch return error.OutOfMemory;
    return @constCast(enc.encode(out, data));
}

/// 宽容解码：URL / 标准字母表混用、容忍缺省填充、忽略空白（对齐 C# `ToBase64` 与 Rust
/// `dhrust::sign::base64_decode`）。
fn base64DecodeLenient(arena: std.mem.Allocator, text: []const u8) ![]u8 {
    var norm = try arena.alloc(u8, text.len + 4);
    var n: usize = 0;
    for (text) |c| {
        switch (c) {
            '-' => {
                norm[n] = '+';
                n += 1;
            },
            '_' => {
                norm[n] = '/';
                n += 1;
            },
            ' ', '\t', '\r', '\n', 0x0b, 0x0c => {},
            else => {
                norm[n] = c;
                n += 1;
            },
        }
    }
    // 补齐 '=' 到 4 的倍数
    while (n % 4 != 0) : (n += 1) norm[n] = '=';

    const padded = norm[0..n];
    const dec = std.base64.standard.Decoder;
    const size = try dec.calcSizeForSlice(padded);
    const out = try arena.alloc(u8, size);
    try dec.decode(out, padded);
    return out;
}

fn jsonToInt(v: std.json.Value) ?i64 {
    return switch (v) {
        .integer => |i| i,
        .float => |f| @intFromFloat(f),
        .number_string => |s| std.fmt.parseInt(i64, s, 10) catch null,
        else => null,
    };
}

fn saturatingAdd(a: i64, b: i64) i64 {
    const r = @addWithOverflow(a, b);
    return if (r[1] != 0) (if (b > 0) std.math.maxInt(i64) else std.math.minInt(i64)) else r[0];
}

fn saturatingMul(a: i64, b: i64) i64 {
    const r = @mulWithOverflow(a, b);
    return if (r[1] != 0) (if ((a > 0) == (b > 0)) std.math.maxInt(i64) else std.math.minInt(i64)) else r[0];
}
