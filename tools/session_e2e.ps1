# 会话后端端到端验证（SQLite + Redis）
#
# 验证 `zperm session` 在两种后端上的完整行为：
#   register → check(active) → revoke/revokeuser → check(invalid) → list
# 并额外守住一个已修 bug：**无效连接串必须正常报错，不能段错误**
# （Pek.ZCode 曾因 Dal.open 与 initWithModel 双重释放，任何初始化失败都变成 segfault）。
#
# 用法：powershell -NoProfile -ExecutionPolicy Bypass -File tools\session_e2e.ps1
# 退出码：0 = 通过（Redis 不可用时该部分 SKIP，不算失败）；1 = 有失败。
#
# 注意：本脚本含中文，必须以 UTF-8 with BOM 保存。

param(
    [string]$RedisServer = '127.0.0.1:6379',
    [int]$RedisDb = 15,
    [string]$RedisCli = ''
)

$ErrorActionPreference = 'Stop'

$root = Split-Path $PSScriptRoot -Parent
$zpermExe = Join-Path $root 'zig-out\bin\zperm.exe'

$reportDir = Join-Path $root 'artifacts\regression'
if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Force $reportDir | Out-Null }
$reportPath = Join-Path $reportDir ("session-e2e-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$lines = New-Object System.Collections.ArrayList

function Write-Report([string]$text) {
    Write-Host $text
    [void]$lines.Add($text)
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

$stamp = Get-Date -Format 'HHmmssfff'
$dbFile = Join-Path $env:TEMP ("zperm-session-e2e-{0}.db" -f $stamp)
$conn = "Data Source=$dbFile"
$token = "e2e-session-$stamp"
$uid = 4242

try {
    # ── SQLite 后端 ──────────────────────────────────────────────
    $r = Invoke-External -Exe $zpermExe -Arguments @('session', 'register', $conn, $token, "$uid", '--client=web')
    Assert-Case -Name 'SQLite register' -Ok ($r.Output -like '*REGISTERED=1*' -and $r.Output -like '*STORE=store*') -Detail $r.Output.Trim()

    $r = Invoke-External -Exe $zpermExe -Arguments @('session', 'check', $conn, $token)
    Assert-Case -Name 'SQLite check（应 active）' -Ok ($r.Output -like '*STATE=active*' -and $r.Output -like '*AUTHORIZE=1*') -Detail $r.Output.Trim()

    $r = Invoke-External -Exe $zpermExe -Arguments @('session', 'list', $conn, "$uid")
    Assert-Case -Name 'SQLite list（应 1 条）' -Ok ($r.Output -like '*COUNT=1*') -Detail $r.Output.Trim()

    $r = Invoke-External -Exe $zpermExe -Arguments @('session', 'revokeuser', $conn, "$uid")
    Assert-Case -Name 'SQLite revokeuser' -Ok ($r.Output -like '*BUMPED=1*') -Detail $r.Output.Trim()

    $r = Invoke-External -Exe $zpermExe -Arguments @('session', 'check', $conn, $token)
    Assert-Case -Name 'SQLite 踢线后 check（应 invalid）' -Ok ($r.Output -like '*STATE=invalid*' -and $r.Output -like '*AUTHORIZE=0*') -Detail $r.Output.Trim()

    # ── 连接名回退（--conn，对齐 C# `DAL.Init`：未配置连接串即用 Data/{名}.db）──
    $dataDir = Join-Path $env:TEMP ("zperm-conn-$stamp")
    $connToken = "e2e-conn-$stamp"
    try {
        $r = Invoke-External -Exe $zpermExe -Arguments @('session', 'register', $connToken, "$uid", '--conn=Permissions', "--data=$dataDir", '--client=cfgall')
        $okConn = ($r.Output -like '*REGISTERED=1*') -and ($r.Output -like "*Data Source=$dataDir/Permissions.db*")
        Assert-Case -Name '--conn 回退生成默认 SQLite 连接串' -Ok $okConn -Detail (($r.Output -split "`r?`n" | Where-Object { $_ -like 'CONNSTR=*' }) -join ' ')
        Assert-Case -Name '--conn 自动创建数据目录与库文件' -Ok (Test-Path (Join-Path $dataDir 'Permissions.db')) -Detail $dataDir

        $r = Invoke-External -Exe $zpermExe -Arguments @('session', 'check', $connToken, '--conn=Permissions', "--data=$dataDir")
        Assert-Case -Name '--conn 模式下 check 为 active' -Ok ($r.Output -like '*STATE=active*') -Detail $r.Output.Trim()

        # 非法连接名（含空格）必须被拒绝，且给出与 C# 一致的口径提示。
        # 断言用英文 error 名：exe 输出 UTF-8，而 PS 5.1 按 GBK 解码中文会变乱码。
        $r = Invoke-External -Exe $zpermExe -Arguments @('session', 'list', '1', '--conn=bad name', "--data=$dataDir")
        Assert-Case -Name '非法连接名被拒绝' -Ok ($r.Output -like '*InvalidConnName*' -and $r.Code -eq 2) -Detail ("code={0}" -f $r.Code)
    } finally {
        Remove-Item $dataDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    # 护栏：无效连接串必须正常报错，不能段错误（Pek.ZCode 双重释放 bug 的回归用例）
    $r = Invoke-External -Exe $zpermExe -Arguments @('session', 'list', 'not-a-conn-string', '1')
    $noCrash = ($r.Output -notlike '*Segmentation*')
    Assert-Case -Name '无效连接串正常报错（不崩溃）' -Ok ($noCrash -and $r.Output -like '*ERROR=*') -Detail $r.Output.Trim()

    # ── Redis 后端 ───────────────────────────────────────────────
    if (Test-RedisUp -Server $RedisServer) {
        $prefix = "e2e-$stamp`:"
        # 注意：**不要写 `'--redis=' + $RedisServer, ...`** —— PS 5.1 里逗号（数组构造）优先级高于 `+`，
        # 会把后面的参数一并拼进 `--redis` 的值里（实测 SERVER 变成 "127.0.0.1:6379 --redisdb=15 ..."）。
        $redisArgs = @("--redis=$RedisServer", "--redisdb=$RedisDb", "--prefix=$prefix")

        $r = Invoke-External -Exe $zpermExe -Arguments (@('session', 'register', $token, "$uid", '--client=mobile') + $redisArgs)
        Assert-Case -Name 'Redis register' -Ok ($r.Output -like '*REGISTERED=1*') -Detail $r.Output.Trim()

        $r = Invoke-External -Exe $zpermExe -Arguments (@('session', 'check', $token) + $redisArgs)
        Assert-Case -Name 'Redis check（应 active，含 client/pwd 回读）' -Ok ($r.Output -like '*STATE=active*' -and $r.Output -like '*CLIENT=mobile*') -Detail $r.Output.Trim()

        $r = Invoke-External -Exe $zpermExe -Arguments (@('session', 'list', "$uid") + $redisArgs)
        Assert-Case -Name 'Redis list（应 1 条）' -Ok ($r.Output -like '*COUNT=1*') -Detail $r.Output.Trim()

        $r = Invoke-External -Exe $zpermExe -Arguments (@('session', 'revokeuser', "$uid") + $redisArgs)
        Assert-Case -Name 'Redis revokeuser' -Ok ($r.Output -like '*BUMPED=1*') -Detail $r.Output.Trim()

        $r = Invoke-External -Exe $zpermExe -Arguments (@('session', 'check', $token) + $redisArgs)
        Assert-Case -Name 'Redis 踢线后 check（应 invalid）' -Ok ($r.Output -like '*STATE=invalid*') -Detail $r.Output.Trim()

        # 清理：按前缀扫描删除（键名是 sha256，无法直接构造）
        if (-not $RedisCli) {
            $cmd = Get-Command redis-cli -ErrorAction SilentlyContinue
            if ($cmd) { $RedisCli = $cmd.Source }
            elseif (Test-Path 'D:\Redis\redis-cli.exe') { $RedisCli = 'D:\Redis\redis-cli.exe' }
        }
        if ($RedisCli) {
            $keys = & $RedisCli -n $RedisDb --scan --pattern "$prefix*"
            foreach ($k in $keys) { if ($k) { & $RedisCli -n $RedisDb DEL $k | Out-Null } }
        }
    } else {
        Write-Report "[SKIP] Redis 不可用（$RedisServer），跳过 Redis 后端用例"
    }
} finally {
    Remove-Item $dbFile -Force -ErrorAction SilentlyContinue
    Remove-Item ($dbFile + '-wal') -Force -ErrorAction SilentlyContinue
    Remove-Item ($dbFile + '-shm') -Force -ErrorAction SilentlyContinue
}

$total = $passed + $failed
Write-Report ''
Write-Report ("=== SESSION E2E: {0}/{1} passed ===" -f $passed, $total)
[IO.File]::WriteAllLines($reportPath, $lines, (New-Object Text.UTF8Encoding($false)))
Write-Host "[report] $reportPath"

if ($failed -gt 0 -or $total -eq 0) { exit 1 }
exit 0
