# Pek.ZPermissions

Pek 生态的 **Zig** 权限组件。当前提供与 **C#**（`Pek.Permissions` / `NewLife.Web.JwtBuilder`）和
**Rust**（`Pek.RPermissions`）**完全互相解析互用**的 **HS256 JWT** 实现。

> 三种语言的令牌不只是「能验签」：**同输入、同时间下生成的令牌逐字节相同**（见下方实测证据）。

## 快速开始

```powershell
zig build                          # 产出 zig-out\bin\zperm.exe
zig build test                     # 单元测试（含 C#/Rust 黄金样本与字节级复现）
powershell -File tools\interop.ps1  # 三语言双向对拍（Zig / C# / Rust）
```

## 库用法

```zig
const std = @import("std");
const perms = @import("pek_zpermissions");

// 1) 直接按 C# `JwtBuilder` 语义签发（自动注入 iss/sub/aud/exp/nbf/iat/jti，已存在则不覆盖）
var builder = try perms.Builder.fromSecret("HS256:your-key");
builder.issuer = "Pek.RCard";
builder.expire = now_ts + 7200;

var payload: std.json.ObjectMap = .{};
try payload.put(alloc, "sub", .{ .string = "42" });
const token = try builder.encodeObject(alloc, &payload, now_ts);
defer alloc.free(token);

// 2) 校验（验签 + 签名规范形态 + exp/nbf）
var decoded = try builder.validate(alloc, token, now_ts);
defer decoded.deinit();
const sub = decoded.payload.get("sub").?.string;

// 3) 便捷层（对齐 Rust `Jwt` / `JwtOptions`）
var jwt = try perms.Jwt.init(.{ .secret = "HS256:your-key", .access_expire_minutes = 120 });
const token2 = try jwt.encodeWith(alloc, &payload, 120, now_ts);
```

`Claims`（`sub` / `name` / `from` / `clientType`）与 Rust 端同名同义，见 `src/claims.zig`。

## CLI（跨语言对拍）

```
zperm jwt gen     <secret> <payloadJson|@file> [expireMinutes] [--iss=..] [--sub=..] [--jti=..]
zperm jwt genraw  <secret> <payloadJson|@file>   # 原样签名，不注入 exp/iat
zperm jwt verify  <secret> <token>               # RESULT=OK / RESULT=FAIL + MESSAGE=
zperm jwt inspect <token>                        # 不验签，仅解析
zperm jwt selfcheck                              # 内置 C# 黄金样本自检
```

输出为 `KEY=VALUE` 行，与 `Pek.RCard/examples/jwt_tool.rs`（Rust）和
`Pek.RCard/tools/csharp/JwtInterop`（C#）的命令格式对称，可直接串进脚本。

## 互通契约（要点）

| 项 | 口径 |
|---|---|
| Header | 紧凑 JSON，默认 `{"alg":"HS256"}`（无 `typ`） |
| Payload | 紧凑 JSON；`exp` / `iat` / `nbf` 为 Unix 秒；注入顺序 iss → sub → aud → exp → nbf → iat → jti，**已存在的键不覆盖** |
| 签名 | `HMAC-SHA256(key, "header.payload")` → **base64url 无填充** |
| 密钥配置 | `算法:密钥`，按 `:` 分割取**第二段**（对齐 C# `Split(':')[1]`；密钥不要含冒号） |
| 验签 | 常量时间比较 + **签名段必须是规范形态**（URL 安全、无填充、无空白） |
| 时间 | `now > exp` 过期；`now < nbf` 未生效（仅当声明存在） |
| 算法 | 只用固定 HS256 验签，不读 header 的 alg 决定算法（防 `alg=none`）；可选 `strict_header_alg` |

完整依据与实测证据见 `docs/互操作契约.md`。

## 边界

- **仅 HS256**：这是 C# / Rust / Zig 三端的算法交集（Rust 端同样只支持 HS256）。
- 三端生成的 payload **键序**可能不同（Rust `serde_json` 与 C#/Zig 都是插入序，但调用方传入顺序不同则不同）；
  互验不依赖键序，需要绝对字节一致时用 `genraw` / `encodeVerbatim` 原样签名。

## 会话存储（重启不掉线）

**默认后端 = SQLite**（经 `Pek.ZCode` 的 `Dal` + 内嵌模型驱动建表，不手写 DDL）。
**硬口径：任何存储问题都不能把用户挡在外面。**

1. **不配存储**（`Keeper.store = null`）→ 纯 JWT：验签 + 过期即放行，重启**不掉线**；
2. **存储挂了 / 读写失败** → `untracked` → **放行**；
3. **快照/库文件损坏** → 标记存储不可用 → **放行**（宁可暂时失去吊销能力，也不要全站重新登录）。

只有一种情况会拒绝：**存储可用且明确判为无效**（主动登出 / 过期 / 被踢线）。
推荐直接用 `Keeper.authorize(token, now)`：

```zig
if (!keeper.authorize(token, now)) return; // 只有明确的登出/过期/踢线才拒绝
```

| 后端 | 重启后 | 多实例共享 | 说明 |
|---|---|---|---|
| **`SqliteStore`（默认推荐）** | **保留** | 否（单机文件库） | 经 `Pek.ZCode` 建表；`ZPermissions_Session` 单表 KV |
| `RedisStore` | **保留** | **是** | 复用 **`Pek.ZRedis`**（对齐 C# `DH.NRedis` / Rust `Pek.RRedis`） |
| `FileStore` | 保留 | 否 | 零依赖 JSON 快照（无 ORM 依赖时可用） |
| `MemoryStore` | **丢失** | 否 | **仅测试**：重启清空会被当成「已登出」 |

```zig
const perms = @import("pek_zpermissions");

// 默认：SQLite（模型驱动建表，幂等）
var st = try perms.SqliteStore.open(alloc, "Data Source=Data\\sessions.db");
defer st.deinit();
var keeper = perms.SessionKeeper.init(alloc, st.store(), "app:", .{
    .idle_secs = 7 * 24 * 3600,   // 空闲有效期（不足一半才滑动续期）
    .max_secs = 30 * 24 * 3600,   // 绝对上限（到点必须重新登录）
});

// 多实例共享：Redis（复用 Pek.ZRedis）
var rs = try perms.RedisStore.open(alloc, io, "127.0.0.1:6379", null, 0);
defer rs.deinit();
var keeper2 = perms.SessionKeeper.init(alloc, rs.store(), "app:", .{});

// 登录后登记 / 请求时放行判断 / 登出 / 踢线
keeper.register(token, uid, pwd_tag, "web", now);
if (!keeper.authorize(token, now)) return;
_ = keeper.revoke(token, now);            // 登出
_ = keeper.revokeUser(uid, now);          // 踢掉该账号全部端
_ = keeper.revokeClient(uid, "web", now); // 只踢某一端
```

> 注意：`:memory:` 连接串**不适用**于 `SqliteStore` —— `Dal` 每次操作使用独立连接，内存库不共享。

**建表链路（不是「解析 XML 拼 SQL」）**：

```
Entity/Model.xml  --解析-->  EntityModel / TableMeta / ColumnMeta（模型对象）
                                 |
                                 v  dialect（SQLite provider）按方言规则生成 DDL
                            String(512) → nvarchar(512)
                            Int64       → INTEGER
                            DateTime    → datetime
                                 |
                                 v  Dal.syncSchema（幂等：缺表建表/缺列补列/缺索引补索引）
                            实际库表
```

模型 XML 只是**输入载体**（可以手写）；建表行为由「模型对象 + 方言规则」决定，并有测试锁定
（`sqlite: 建表按模型 + 方言规则生成（非照抄 XML）且幂等`）。


语义与 Rust `Pek.RPermissions::session` 逐项对齐：键前缀、JSON 字段、两级版本号踢线、滑动续期、绝对上限。
**存储不可用一律退回纯 JWT 放行**，绝不因为缓存挂了把所有人挡在外面。

### 与 C# 共用同一套 Redis

`redis_store.CSharpMirror` 按 C# `JsonWebTokenStore` 的键空间双写（键前缀与毫秒时间戳已对齐本地源码）：

```
jwt:token:access:{token}     -> {"UId":..,"AccessToken":..,"AccessTokenUtcExpires":<毫秒>,..}
jwt:token:bind:{refresh}     -> 同上（有刷新令牌时）
jwt:user:tokens:{uid}        -> ["token1","token2"]（普通字符串，不是 Redis SET —— C# 就是这么存的）
```

```zig
var mirror = perms.CSharpMirror.init(alloc, io, "127.0.0.1", 6379);
_ = mirror.saveAccess(token, uid, issued_unix, access_expires_unix, "", 0);
_ = mirror.exists(token);  // 对应 C# ExistsToken（只判键存在）
_ = mirror.remove(token);  // 对应 C# RemoveToken
```

> ⚠️ **C# 侧值格式按本地源码字段与单位构造，但未在「真实 Redis + 真实 C# 进程」上对拍过**
> （本机无 Redis）。首次接生产前请用真实环境验一次：C# 签发 → Zig `mirror.exists` 为真，
> Zig `saveAccess` → C# `ExistsToken`/`GetCompleteTokenInfo` 正常。

## 目录

```
src/jwt.zig          JWT 编解码（Builder / Jwt / validate）
src/claims.zig       标准 claims
src/secret.zig       「算法:密钥」解析
src/session.zig      会话登记/吊销（Store 抽象 + MemoryStore + FileStore + Keeper）
src/redis.zig        最小 RESP2 客户端（GET/SET/DEL/EXISTS/SADD/SMEMBERS/PING）
src/redis_store.zig  RedisStore（Rust 口径）+ CSharpMirror（C# 键空间镜像）
src/main.zig         zperm CLI
src/jwt_test.zig     互操作测试（C#/Rust 黄金样本 + 字节级复现）
tools/interop.ps1    三语言双向对拍脚本
tools/regression.ps1 一键回归（= interop.ps1）
docs/互操作契约.md   契约依据与实测记录
```

