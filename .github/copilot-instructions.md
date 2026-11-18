# Pek.ZPermissions · 项目指令

> 全项目通用规则见用户级《跨项目接续协议》（本机 `%APPDATA%\Code\User\prompts\跨项目接续协议.instructions.md`；模板在 `tools/continuity/templates/`）。
> **开工先读（存在则读，按序）**：`.github/copilot-instructions.md` → `docs/项目接续指南.md` → `docs/用户档案.md` → `docs/项目记忆.md` → `docs/互操作契约.md` 最新节。

## 项目速览

- **定位**：Pek 生态权限组件的 **Zig** 实现。首个能力是与 C#（`Pek.Permissions` / `NewLife.Web.JwtBuilder`）和 Rust（`Pek.RPermissions`）**完全互相解析互用**的 HS256 JWT。
- **技术栈**：Zig 0.17.0（`build.zig` + `build.zig.zon`，无第三方依赖，全部用 std：`std.crypto.auth.hmac.sha2.HmacSha256` / `std.base64.url_safe_no_pad` / `std.json`）。
- **产物**：库模块 `pek_zpermissions`（`src/root.zig`）+ CLI `zperm`（`src/main.zig` → `zig-out\bin\zperm.exe`）。

## 关键约定（改动前必读）

- **互通是最高红线**：header `{"alg":"HS256"}` 紧凑 JSON（无 `typ`）；`exp`/`iat`/`nbf` 为 **Unix 秒**；签名 = `HMAC-SHA256(key, "header.payload")` → **base64url 无填充**；密钥格式「算法:密钥」（`Split(':')` 取第二段，**密钥不要含冒号**）。
- **声明注入序**：iss → sub → aud → exp → nbf → iat → jti，**已存在的键不覆盖**（对齐 C# `ContainsKey`）。
- **验签按规范形态**：签名段必须是 URL 安全、无填充、无空白原文（补 `=` / 插空白 / 换标准字母表一律拒绝）——对齐 C# `enc(...).ToUrlBase64() == ts[2]` 字符串精确比较。
- **算法固定 HS256**：不读 header 的 alg 决定算法（防 `alg=none`）；`strict_header_alg` 可选加固。三端算法交集只有 HS256（Rust 端同样只支持 HS256）。
- **`now` 由调用方传入**：核心库不读隐式时钟（便于测试与跨端复现）；CLI 用 `std.Io.Clock.real.now(io)`。
- 中文 `.ps1` 必须 **UTF-8 with BOM**；PS 5.1 下外部命令后用 `$LASTEXITCODE` 判定，不写 `2>&1 |`。

## 构建与验证

```powershell
zig build                                   # 出 CLI
zig build test                              # 19 项单测（含 C#/Rust 黄金样本 + 字节级复现）
zig test src\root.zig                       # 直接跑测试，可看 "All N tests passed"
zig fmt --check src build.zig               # 格式
powershell -NoProfile -ExecutionPolicy Bypass -File tools\regression.ps1   # 一键回归（= interop.ps1，5 项三语言对拍）
```

**改 JWT/互通行为必须实跑 `tools/regression.ps1`**，期望 `=== JWT INTEROP: 5/5 passed ===`，并维护 `src/jwt_test.zig` 里的黄金样本与字节级断言。

## 每轮收尾（务必）

① `docs/互操作契约.md` 新增一节（**含用户原话**）；② `tools/continuity/sync-memory.ps1` 同步记忆（在项目根目录运行或传 `-ProjectPath`）；③ 跑回归验证并如实汇报。
