# Pek.ZPermissions JWT interop matrix: Zig <-> C# (NewLife.Web.JwtBuilder) <-> Rust (Pek.RPermissions)
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\interop.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\interop.ps1 -RCardPath 'D:\Code\Rust\Pek.RCard'
#
# All-ASCII script (PS 5.1 safe without BOM). Does not use "2>&1 |" pipelines,
# because those turn native stderr into terminating errors under $ErrorActionPreference='Stop'.

param(
    [string]$RCardPath = 'G:\Code\Rust\Pek.RCard'
)

$ErrorActionPreference = 'Stop'

$zigRoot = Split-Path $PSScriptRoot -Parent
$zperm = Join-Path $zigRoot 'zig-out\bin\zperm.exe'
$secret = 'HS256:rcard-interop-key-2026'
$work = Join-Path $env:TEMP 'zperm-jwt'
New-Item -ItemType Directory -Force $work | Out-Null
[IO.File]::WriteAllText("$work\claims.json", '{"sub":"42","name":"alice","from":"rcard","clientType":"app"}', (New-Object Text.UTF8Encoding($false)))

$results = New-Object System.Collections.ArrayList
function Record([string]$name, [bool]$ok, [string]$detail) {
    [void]$results.Add([pscustomobject]@{ Name = $name; Ok = $ok; Detail = $detail })
    $tag = if ($ok) { 'PASS' } else { 'FAIL' }
    Write-Host ("[{0}] {1} {2}" -f $tag, $name, $detail)
}

function Get-Token([object]$lines) {
    $t = ($lines | Where-Object { $_ -match '^TOKEN=' }) -replace '^TOKEN=', ''
    if (-not $t) { throw 'no TOKEN= line in output' }
    return $t
}

function Get-ResultOk([object]$lines) {
    return [bool]($lines | Where-Object { $_ -eq 'RESULT=OK' })
}

Write-Host '[step] build Zig ...'
Push-Location $zigRoot
& zig build
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "zig build failed (exit $LASTEXITCODE)" }
& zig build test
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "zig build test failed (exit $LASTEXITCODE)" }
Pop-Location

Write-Host '[step] build C# JwtInterop (real NewLife.Web.JwtBuilder) ...'
& dotnet build (Join-Path $RCardPath 'tools\csharp\JwtInterop\JwtInterop.csproj') -v q --nologo | Out-Null
if ($LASTEXITCODE -ne 0) { throw "dotnet build failed (exit $LASTEXITCODE)" }
$csDll = Join-Path $RCardPath 'tools\csharp\JwtInterop\bin\Debug\net10.0\JwtInterop.dll'
if (-not (Test-Path $csDll)) { throw "C# tool not found: $csDll" }

# --- 1/4 C# gen -> Zig verify ---
try {
    $cs = & dotnet $csDll gen $secret "@$work\claims.json" 120
    $t = Get-Token $cs
    $z = & $zperm jwt verify $secret $t
    Record 'csharp-gen -> zig-verify' (Get-ResultOk $z) ''
} catch { Record 'csharp-gen -> zig-verify' $false $_.Exception.Message }

# --- 2/4 Zig gen -> C# verify ---
try {
    $zg = & $zperm jwt gen $secret "@$work\claims.json" 120
    $t = Get-Token $zg
    $cs = & dotnet $csDll verify $secret $t
    Record 'zig-gen -> csharp-verify' (Get-ResultOk $cs) ''
} catch { Record 'zig-gen -> csharp-verify' $false $_.Exception.Message }

# --- 3/4 Rust gen -> Zig verify ---
try {
    Push-Location $RCardPath
    $rs = & cargo run -q --example jwt_tool -- gen $secret "@$work\claims.json" 120
    Pop-Location
    $t = Get-Token $rs
    $z = & $zperm jwt verify $secret $t
    Record 'rust-gen -> zig-verify' (Get-ResultOk $z) ''
} catch { Record 'rust-gen -> zig-verify' $false $_.Exception.Message }

# --- 4/4 Zig gen -> Rust verify ---
try {
    $zg = & $zperm jwt gen $secret "@$work\claims.json" 120
    $t = Get-Token $zg
    Push-Location $RCardPath
    $rs = & cargo run -q --example jwt_tool -- verify $secret $t
    Pop-Location
    Record 'zig-gen -> rust-verify' (Get-ResultOk $rs) ''
} catch { Record 'zig-gen -> rust-verify' $false $_.Exception.Message }

# --- 5/5 Zig selfcheck (C# golden sample built into the binary) ---
try {
    $sc = & $zperm jwt selfcheck
    Record 'zig-selfcheck(csharp-golden)' ([bool]($sc | Where-Object { $_ -eq 'SELFCHECK=OK' })) ''
} catch { Record 'zig-selfcheck(csharp-golden)' $false $_.Exception.Message }

$failed = @($results | Where-Object { -not $_.Ok })
Write-Host ''
Write-Host ("=== JWT INTEROP: {0}/{1} passed ===" -f ($results.Count - $failed.Count), $results.Count)
if ($failed.Count -gt 0) {
    foreach ($f in $failed) { Write-Host ("  FAILED: {0} {1}" -f $f.Name, $f.Detail) }
    exit 1
}
exit 0
