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

Write-Host ("report: {0}" -f $report)
exit $code
