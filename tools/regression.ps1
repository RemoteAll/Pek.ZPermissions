# Pek.ZPermissions 一键回归入口（构建 -> 单元测试 -> 三语言对拍），退出码 0/1 可直接接 CI。
#
# 薄壳：具体步骤全部在 tools\interop.ps1（单一实现，避免两份对拍逻辑漂移）。
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\regression.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\regression.ps1 -RCardPath 'D:\Code\Rust\Pek.RCard'

param(
    [string]$RCardPath = 'G:\Code\Rust\Pek.RCard'
)

$ErrorActionPreference = 'Stop'

$reportDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'artifacts\regression'
New-Item -ItemType Directory -Force $reportDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$report = Join-Path $reportDir "report-$stamp.txt"

& (Join-Path $PSScriptRoot 'interop.ps1') -RCardPath $RCardPath | Tee-Object -FilePath $report
$code = $LASTEXITCODE

# 第二步：真实 HTTP 服务上的鉴权中间件端到端（401 / 200 / 豁免路径）。
# 单元测试用的是伪造 Ctx，只有这一步能证明「真的发出了 401/200」。
if ($code -eq 0) {
    & (Join-Path $PSScriptRoot 'http_guard_e2e.ps1') | Tee-Object -FilePath $report -Append
    $guardCode = $LASTEXITCODE
    # 2 = 未构建（interop 已保证构建过，出现即视为异常）；0 = 通过；其余 = 失败
    if ($guardCode -ne 0) { $code = 1 }
}

# 第三步：C# 键空间镜像与真 Redis 的双向对拍（Redis 不可用时脚本自身 SKIP，不算失败）。
if ($code -eq 0) {
    & (Join-Path $PSScriptRoot 'redis_mirror_e2e.ps1') | Tee-Object -FilePath $report -Append
    if ($LASTEXITCODE -ne 0) { $code = 1 }
}

Write-Host ("report: {0}" -f $report)
exit $code
