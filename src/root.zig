//! Pek.ZPermissions —— Pek 生态 Zig 实现（JWT / 权限）。
//!
//! 当前提供与 C# `Pek.Permissions`（`NewLife.Web.JwtBuilder`）和
//! Rust `Pek.RPermissions`（`dhrust::sign`）**完全互相解析互用**的 HS256 JWT，
//! 以及可持久化的会话登记/吊销（默认后端 = SQLite，经 `Pek.ZCode` 模型驱动建表）。

pub const jwt = @import("jwt.zig");
pub const claims = @import("claims.zig");
pub const secret = @import("secret.zig");
pub const session = @import("session.zig");
pub const sqlite_store = @import("sqlite_store.zig");
pub const redis_store = @import("redis_store.zig");
/// 模型守卫（防「代码 ↔ `Entity/Model.xml` 漂移」）
pub const model_guard = @import("model_guard.zig");
/// HTTP 鉴权中间件（接入 `zzig` 的 `web.App` / `router`）
pub const http_auth = @import("http_auth.zig");

pub const Builder = jwt.Builder;
pub const Jwt = jwt.Jwt;
pub const Options = jwt.Options;
pub const Decoded = jwt.Decoded;
pub const Claims = claims.Claims;
pub const SessionStore = session.Store;
pub const SessionKeeper = session.Keeper;
pub const MemoryStore = session.MemoryStore;
pub const FileStore = session.FileStore;
/// **默认推荐**的会话后端（SQLite；经 Pek.ZCode 的 Dal + 模型驱动建表）
pub const SqliteStore = sqlite_store.SqliteStore;
/// 多实例共享的会话后端（复用 Pek.ZRedis）
pub const RedisStore = redis_store.RedisStore;
/// C# `JsonWebTokenStore` 键空间镜像（与 C# 共用同一 Redis）
pub const CSharpMirror = redis_store.CSharpMirror;

test {
    _ = jwt;
    _ = claims;
    _ = secret;
    _ = session;
    _ = sqlite_store;
    _ = redis_store;
    _ = model_guard;
    _ = http_auth;
    _ = @import("jwt_test.zig");
}
