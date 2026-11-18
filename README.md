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

## 目录

```
src/jwt.zig       JWT 编解码（Builder / Jwt / validate）
src/claims.zig    标准 claims
src/secret.zig    「算法:密钥」解析
src/main.zig      zperm CLI
src/jwt_test.zig  互操作测试（C#/Rust 黄金样本 + 字节级复现）
tools/interop.ps1 三语言双向对拍脚本
docs/互操作契约.md 契约依据与实测记录
```
