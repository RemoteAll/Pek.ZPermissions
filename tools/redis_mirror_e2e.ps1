# C# 键空间镜像（CSharpMirror）与真 Redis 的双向对拍
#
# 验证目标：Zig 侧写的 `jwt:token:access:{token}` 记录，与 C# `JsonWebTokenStore`
# 通过 NewLife.Caching 落到 Redis 的内容**同格式**；反向也要能读。
#
#   Zig 写 → redis-cli 读：值一致 + TTL 正确
#   redis-cli 写（C# 格式）→ Zig 读：值一致
#
# 用法：powershell -NoProfile -ExecutionPolicy Bypass -File tools\redis_mirror_e2e.ps1
#      可选 -Server 127.0.0.1:6379 -Db 15
# 退出码：0 = 通过或 Redis 不可用（SKIP）；1 = 有失败。
#
# 注意：本脚本含中文，必须以 UTF-8 with BOM 保存（PS 5.1 会按 ANSI 读无 BOM 文件）。

param(
    [string]$Server = '127.0.0.1:6379',
    [int]$Db = 15,
    [string]$RedisCli = ''
)

$ErrorActionPreference = 'Stop'

$root = Split-Path $PSScriptRoot -Parent
$zpermExe = Join-Path $root 'zig-out\bin\zperm.exe'

$reportDir = Join-Path $root 'artifacts\regression'
if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Force $reportDir | Out-Null }
$reportPath = Join-Path $reportDir ("redis-mirror-e2e-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$lines = New-Object System.Collections.ArrayList

function Write-Report([string]$text) {
    Write-Host $text
    [void]$lines.Add($text)
}

function Test-RedisUp {
    param([string]$Server)
    $parts = $Server.Split(':')
    $host_ = $parts[0]
    $port_ = if ($parts.Length -gt 1) { [int]$parts[1] } else { 6379 }
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $c.Connect($host_, $port_)
        $c.Close()
        return $true
    } catch { return $false }
}

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

function Get-CliValue {
    param([string]$Cli, [int]$Db, [string]$Command, [string]$Key)
    $r = Invoke-External -Exe $Cli -Arguments @('-n', "$Db", '--raw', $Command, $Key)
    return $r.Output.Trim()
}

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

if (-not (Test-Path $zpermExe)) {
    Write-Report "[SKIP] 未找到 $zpermExe，请先执行 zig build"
    [IO.File]::WriteAllLines($reportPath, $lines, (New-Object Text.UTF8Encoding($false)))
    exit 0
}

if (-not (Test-RedisUp -Server $Server)) {
    Write-Report "[SKIP] Redis 不可用（$Server），跳过镜像对拍（不视为失败）"
    Write-Report '=== REDIS MIRROR E2E: SKIP ==='
    [IO.File]::WriteAllLines($reportPath, $lines, (New-Object Text.UTF8Encoding($false)))
    Write-Host "[report] $reportPath"
    exit 0
}

if (-not $RedisCli) {
    $cmd = Get-Command redis-cli -ErrorAction SilentlyContinue
    if ($cmd) { $RedisCli = $cmd.Source }
    elseif (Test-Path 'D:\Redis\redis-cli.exe') { $RedisCli = 'D:\Redis\redis-cli.exe' }
}

$stamp = Get-Date -Format 'HHmmssfff'
$zigToken = "e2e-zig-write-$stamp"
$csToken = "e2e-cs-write-$stamp"
$issued = [int][double]::Parse((Get-Date -UFormat %s))
$expires = $issued + 600
$zigKey = "jwt:token:access:$zigToken"
$csKey = "jwt:token:access:$csToken"

try {
    # ① Zig 侧连通
    $ping = Invoke-External -Exe $zpermExe -Arguments @('redis', 'ping', $Server, "--db=$Db")
    Assert-Case -Name 'zig -> redis ping' -Ok ($ping.Output -like '*PING=1*') -Detail $ping.Output.Trim()

    # ② Zig 写入
    $put = Invoke-External -Exe $zpermExe -Arguments @('redis', 'put', $Server, $zigToken, '42', "$issued", "$expires", "--db=$Db")
    Assert-Case -Name 'zig 写入访问令牌记录' -Ok ($put.Output -like '*SAVED=1*') -Detail $put.Output.Trim()

    # ③ Zig 读回
    $get = Invoke-External -Exe $zpermExe -Arguments @('redis', 'get', $Server, $zigToken, "--db=$Db")
    Assert-Case -Name 'zig 读回自身写入' -Ok ($get.Output -like '*EXISTS=1*' -and $get.Output -like '*"UId":42*') -Detail $get.Output.Trim()

    if ($RedisCli) {
        # ④ redis-cli 独立核对（键名 / 值 / TTL）
        $raw = Get-CliValue -Cli $RedisCli -Db $Db -Command 'GET' -Key $zigKey
        $expectExpires = $expires * 1000
        $okValue = ($raw -like '*"UId":42*') -and ($raw -like "*`"AccessTokenUtcExpires`":$expectExpires*") -and ($raw -like "*`"StartTime`":$($issued * 1000)*")
        Assert-Case -Name 'redis-cli 读到 Zig 写入的值（毫秒单位）' -Ok $okValue -Detail $raw

        $ttl = Get-CliValue -Cli $RedisCli -Db $Db -Command 'TTL' -Key $zigKey
        $ttlNum = 0
        [void][int]::TryParse(($ttl -replace '[^0-9-]', ''), [ref]$ttlNum)
        Assert-Case -Name 'TTL 与令牌有效期一致' -Ok ($ttlNum -gt 0 -and $ttlNum -le 600) -Detail "ttl=$ttlNum"

        # ⑤ 反向：redis-cli 按 C# JsonWebToken 格式写入 → Zig 读
        $csJson = '{"UId":7,"AccessToken":"' + $csToken + '","AccessTokenUtcExpires":' + ($expires * 1000) + ',"RefreshToken":"","RefreshUtcExpires":0,"StartTime":' + ($issued * 1000) + '}'
        $tmp = Join-Path $env:TEMP ("zperm-cs-record-{0}.json" -f $stamp)
        [IO.File]::WriteAllText($tmp, $csJson, (New-Object Text.UTF8Encoding($false)))
        Get-Content $tmp -Raw | & $RedisCli -n $Db -x SET $csKey | Out-Null
        & $RedisCli -n $Db EXPIRE $csKey 600 | Out-Null
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue

        $csGet = Invoke-External -Exe $zpermExe -Arguments @('redis', 'get', $Server, $csToken, "--db=$Db")
        $okCs = ($csGet.Output -like '*EXISTS=1*') -and ($csGet.Output -like '*"UId":7*')
        Assert-Case -Name 'zig 读到 redis-cli 写入的 C# 格式记录' -Ok $okCs -Detail $csGet.Output.Trim()
    } else {
        Write-Report '[SKIP] 未找到 redis-cli，跳过外部工具核对与反向对拍'
    }
} finally {
    if ($RedisCli) {
        & $RedisCli -n $Db DEL $zigKey $csKey | Out-Null
    } else {
        [void](Invoke-External -Exe $zpermExe -Arguments @('redis', 'del', $Server, $zigToken, "--db=$Db"))
    }
}

$total = $passed + $failed
Write-Report ''
Write-Report ("=== REDIS MIRROR E2E: {0}/{1} passed ===" -f $passed, $total)
[IO.File]::WriteAllLines($reportPath, $lines, (New-Object Text.UTF8Encoding($false)))
Write-Host "[report] $reportPath"

if ($failed -gt 0 -or $total -eq 0) { exit 1 }
exit 0
