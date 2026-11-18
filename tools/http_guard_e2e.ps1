# 真实 HTTP 服务端到端验证 http_auth 中间件（Pek.ZPermissions）
#
# 为什么需要它：src\http_auth.zig 的单元测试用的是**伪造 Ctx**，
# 只能证明判定逻辑对，证明不了「挂到真服务上、真的发出 401/200」。
# 本脚本起 examples\http_guard_demo.zig 编出的真服务，用真实 HTTP 请求验收。
#
# 用法：powershell -NoProfile -ExecutionPolicy Bypass -File tools\http_guard_e2e.ps1
#      可选 -Port 18571 指定端口。
# 退出码：0 = 全部通过；1 = 有失败；2 = 前置条件缺失（未构建）。
#
# 注意：本脚本含中文，必须以 UTF-8 with BOM 保存（PS 5.1 会按 ANSI 读无 BOM 文件）。

param(
    [int]$Port = 18571
)

$ErrorActionPreference = 'Stop'

$root = Split-Path $PSScriptRoot -Parent
$demoExe = Join-Path $root 'zig-out\bin\http-guard-demo.exe'
$zpermExe = Join-Path $root 'zig-out\bin\zperm.exe'

if (-not (Test-Path $demoExe) -or -not (Test-Path $zpermExe)) {
    Write-Host "[SKIP] 未找到构建产物，请先执行 zig build：" -NoNewline
    Write-Host " $demoExe / $zpermExe"
    exit 2
}

$reportDir = Join-Path $root 'artifacts\regression'
if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Force $reportDir | Out-Null }
$reportPath = Join-Path $reportDir ("http-guard-e2e-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$lines = New-Object System.Collections.ArrayList

function Write-Report([string]$text) {
    Write-Host $text
    [void]$lines.Add($text)
}

# 跑外部命令并取 stdout（PS 5.1 下 $ErrorActionPreference='Stop' 会把 stderr 当终止错误）
function Invoke-External {
    param([string]$Exe, [string[]]$Arguments)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $Exe @Arguments 2>&1
        return @{ Output = ($out | Out-String); Code = $LASTEXITCODE }
    } finally {
        $ErrorActionPreference = $prev
    }
}

function Wait-Port {
    param([int]$Port, [int]$TimeoutSec = 15)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            $c.Connect('127.0.0.1', $Port)
            $c.Close()
            return $true
        } catch {
            Start-Sleep -Milliseconds 200
        }
    }
    return $false
}

# 返回 @{ Status = <int>; Body = <string> }；4xx/5xx 不抛异常
function Invoke-Http {
    param([string]$Url, [hashtable]$Headers = @{})
    try {
        $r = Invoke-WebRequest -Uri $Url -Headers $Headers -UseBasicParsing -TimeoutSec 5
        return @{ Status = [int]$r.StatusCode; Body = [string]$r.Content }
    } catch {
        $resp = $_.Exception.Response
        if ($resp) {
            $code = [int]$resp.StatusCode
            $body = ''
            try {
                $stream = $resp.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $body = $reader.ReadToEnd()
                $reader.Close()
            } catch { }
            return @{ Status = $code; Body = $body }
        }
        return @{ Status = -1; Body = $_.Exception.Message }
    }
}

$secret = 'HS256:e2e-guard-key'
$passed = 0
$failed = 0

function Assert-Case {
    param([string]$Name, [bool]$Ok, [string]$Detail)
    if ($Ok) {
        $script:passed++
        Write-Report ("[PASS] {0}{1}" -f $Name, $(if ($Detail) { " -> $Detail" } else { '' }))
    } else {
        $script:failed++
        Write-Report ("[FAIL] {0}{1}" -f $Name, $(if ($Detail) { " -> $Detail" } else { '' }))
    }
}

$proc = $null
try {
    $proc = Start-Process -FilePath $demoExe -ArgumentList @($secret, $Port) -PassThru -WindowStyle Hidden
    if (-not (Wait-Port -Port $Port)) {
        Write-Report "[FAIL] 服务未在 15 秒内监听 127.0.0.1:$Port"
        exit 1
    }
    Write-Report "[INFO] 服务已就绪：http://127.0.0.1:$Port（pid=$($proc.Id)）"

    $base = "http://127.0.0.1:$Port"

    # ① 豁免路径：无令牌也必须 200
    $r = Invoke-Http -Url "$base/health"
    Assert-Case -Name '豁免路径 /health 无令牌' -Ok ($r.Status -eq 200 -and $r.Body -like '*"ok":true*') -Detail ("status={0} body={1}" -f $r.Status, $r.Body)

    # ② 受保护路径：无令牌 → 401
    $r = Invoke-Http -Url "$base/api/whoami"
    Assert-Case -Name '受保护路径 /api/whoami 无令牌' -Ok ($r.Status -eq 401) -Detail ("status={0} body={1}" -f $r.Status, $r.Body)

    # ③ 受保护路径：坏令牌 → 401
    $r = Invoke-Http -Url "$base/api/whoami" -Headers @{ Authorization = 'Bearer not-a-jwt' }
    Assert-Case -Name '受保护路径 坏令牌' -Ok ($r.Status -eq 401) -Detail ("status={0} body={1}" -f $r.Status, $r.Body)

    # ④ 用 CLI 生成真实令牌 → 200 且能拿到 auth.uid
    #    payload 必须走 @file：PowerShell 传参会把 JSON 的引号吃掉（实测 ERROR=负载解析失败）
    $payloadFile = Join-Path $env:TEMP ("zperm-e2e-payload-{0}.json" -f (Get-Date -Format 'HHmmssfff'))
    [IO.File]::WriteAllText($payloadFile, '{"sub":"42","name":"e2e"}', (New-Object Text.UTF8Encoding($false)))
    $gen = Invoke-External -Exe $zpermExe -Arguments @('jwt', 'gen', $secret, "@$payloadFile", '30')
    Remove-Item $payloadFile -Force -ErrorAction SilentlyContinue
    $token = ''
    foreach ($line in ($gen.Output -split "`r?`n")) {
        if ($line -like 'TOKEN=*') { $token = $line.Substring(6).Trim() }
    }
    if (-not $token) {
        $script:failed++
        Write-Report ("[FAIL] 未能从 zperm jwt gen 输出中解析 TOKEN（exit={0}）" -f $gen.Code)
        Write-Report $gen.Output
    } else {
        $r = Invoke-Http -Url "$base/api/whoami" -Headers @{ Authorization = "Bearer $token" }
        Assert-Case -Name '受保护路径 有效令牌' -Ok ($r.Status -eq 200 -and $r.Body -like '*"uid":"42"*') -Detail ("status={0} body={1}" -f $r.Status, $r.Body)

        # ⑤ scheme 大小写不敏感（Bearer/Bearer 都是合法写法）
        $r = Invoke-Http -Url "$base/api/whoami" -Headers @{ Authorization = "bearer $token" }
        Assert-Case -Name '小写 bearer scheme' -Ok ($r.Status -eq 200) -Detail ("status={0}" -f $r.Status)
    }
} finally {
    if ($proc -and -not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
}

$total = $passed + $failed
Write-Report ''
Write-Report ("=== HTTP GUARD E2E: {0}/{1} passed ===" -f $passed, $total)
[IO.File]::WriteAllLines($reportPath, $lines, (New-Object Text.UTF8Encoding($false)))
Write-Host "[report] $reportPath"

if ($failed -gt 0 -or $total -eq 0) { exit 1 }
exit 0
