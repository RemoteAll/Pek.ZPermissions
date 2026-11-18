//! Pek.ZPermissions —— Pek 生态 Zig 实现（JWT / 权限）。
//!
//! 当前提供与 C# `Pek.Permissions`（`NewLife.Web.JwtBuilder`）和
//! Rust `Pek.RPermissions`（`dhrust::sign`）**完全互相解析互用**的 HS256 JWT。

pub const jwt = @import("jwt.zig");
pub const claims = @import("claims.zig");
pub const secret = @import("secret.zig");
pub const session = @import("session.zig");
pub const redis = @import("redis.zig");
pub const redis_store = @import("redis_store.zig");

pub const Builder = jwt.Builder;
pub const Jwt = jwt.Jwt;
pub const Options = jwt.Options;
pub const Decoded = jwt.Decoded;
pub const Claims = claims.Claims;
pub const SessionStore = session.Store;
pub const SessionKeeper = session.Keeper;
pub const MemoryStore = session.MemoryStore;
pub const RedisStore = redis_store.RedisStore;
pub const CSharpMirror = redis_store.CSharpMirror;

test {
    _ = jwt;
    _ = claims;
    _ = secret;
    _ = session;
    _ = redis;
    _ = redis_store;
    _ = @import("jwt_test.zig");
}
