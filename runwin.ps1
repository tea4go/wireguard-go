#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
Clear-Host

# ============================================================
#  Paths & environment
# ============================================================
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $SCRIPT_DIR.EndsWith('\')) { $SCRIPT_DIR += '\' }

$env:GOCACHE = Join-Path $SCRIPT_DIR '.gocache'
$env:GOTMPDIR = Join-Path $SCRIPT_DIR '.gotmp'

$OUT_EXE_NAME = 'wireguard.exe'
$RUN_EXE     = Join-Path $SCRIPT_DIR $OUT_EXE_NAME

if (-not (Test-Path $env:GOCACHE))  { New-Item -ItemType Directory -Path $env:GOCACHE  -Force | Out-Null }
if (-not (Test-Path $env:GOTMPDIR)) { New-Item -ItemType Directory -Path $env:GOTMPDIR -Force | Out-Null }

# ============================================================
#  Overridable env vars (set before calling this script):
#    APP_TAG     - force build version (e.g. v3.0.9), skips VERSION.txt auto-increment
#    IS_BETA     - "true" or empty (default: empty, align with Makefile)
#    LOG_LEVEL   - verbose/debug/info/notice/warn/error/silent
#    RUN_CONFIG  - full path to the .conf/.zip config file
#  Persistent version file:
#    VERSION.txt at project root (SCRIPT_DIR) holds last MAJOR.MINOR.PATCH;
#    each build auto-increments PATCH, carrying over when any digit > 9
#      e.g. v3.0.9 -> v3.1.0 ; v3.9.9 -> v4.0.0
# ============================================================
if ([string]::IsNullOrWhiteSpace($env:IS_BETA))     { $env:IS_BETA     = 'false' }
if ([string]::IsNullOrWhiteSpace($env:LOG_LEVEL))   { $env:LOG_LEVEL   = 'verbose' }
if ([string]::IsNullOrWhiteSpace($env:RUN_CONFIG))  { $env:RUN_CONFIG  = Join-Path $SCRIPT_DIR 'conf\wgtun1.conf' }

$VERSION_FILE = Join-Path $SCRIPT_DIR 'VERSION.txt'

# ============================================================
#  Pre-flight checks
# ============================================================
if (-not (Get-Command 'go' -ErrorAction SilentlyContinue)) {
    Write-Host '[ERROR] ''go'' command not found in PATH. Please install Go and add it to PATH.' -ForegroundColor Red
    exit 1
}

$RUN_CFG_USE = $env:RUN_CONFIG
if (-not [string]::IsNullOrWhiteSpace($RUN_CFG_USE) -and -not (Test-Path $RUN_CFG_USE)) {
    Write-Host "[WARN] Config file not found: $RUN_CFG_USE" -ForegroundColor Yellow
    Write-Host '       Starting without --confile argument (you can set RUN_CONFIG env var to override).' -ForegroundColor Yellow
    $RUN_CFG_USE = ''
}

# ============================================================
#  Version resolution (align with Makefile logic)
#  Priority:
#    1) APP_TAG env var already set -> use it directly, skip VERSION.txt
#    2) else read VERSION.txt (or start v3.0.0 if missing),
#       increment PATCH with carry (each digit max = 9), persist back
# ============================================================
if (-not [string]::IsNullOrWhiteSpace($env:APP_TAG)) {
    $APP_TAG = $env:APP_TAG.Trim()
    Write-Host "[INFO] Using forced APP_TAG=$APP_TAG (VERSION.txt not updated)" -ForegroundColor Cyan
} else {
    [int]$MA = 3; [int]$MI = 0; [int]$PA = 0

    if (Test-Path $VERSION_FILE) {
        $raw = (Get-Content $VERSION_FILE -TotalCount 1 -ErrorAction SilentlyContinue)
        if (-not [string]::IsNullOrWhiteSpace($raw)) {
            $cur = $raw.Trim().TrimStart('v') -replace '\s', ''
            $parts = $cur -split '[.\-_ ]'
            if ($parts.Count -ge 1 -and $parts[0] -match '^\d+$') { $MA = [int]$parts[0] }
            if ($parts.Count -ge 2 -and $parts[1] -match '^\d+$') { $MI = [int]$parts[1] }
            if ($parts.Count -ge 3 -and $parts[2] -match '^\d+$') { $PA = [int]$parts[2] }
        }
    }

    $PA++
    if ($PA -gt 9) { $PA = 0; $MI++ }
    if ($MI -gt 9) { $MI = 0; $MA++ }

    $APP_TAG = "v$MA.$MI.$PA"
    Set-Content -Path $VERSION_FILE -Value $APP_TAG -Encoding ASCII -NoNewline
}

# ============================================================
#  Locale-INDEPENDENT date/time via Get-Date -Format
#    BuildTime : "yyyy-MM-dd(HH:mm:ss)"
#    _d (date) : "yyyyMMdd"
#    _t (time) : "HHmm"
# ============================================================
$now       = Get-Date
$BuildTime = $now.ToString('yyyy-MM-dd(HH:mm:ss)')
$_d        = $now.ToString('yyyyMMdd')
$_t        = $now.ToString('HHmm')
if ($env:IS_BETA -eq 'true') {
    $APP_VER_FULL = "${APP_TAG}_B${_d}_${_t}"
} else {
    $APP_VER_FULL = $APP_TAG
}

# GOOS / GOARCH for banner
$GOOS_T   = (& go env GOOS)   | Select-Object -First 1
$GOARCH_T = (& go env GOARCH) | Select-Object -First 1

Write-Host '======================================================='
Write-Host "Project Dir : $SCRIPT_DIR"
Write-Host "Version File: $VERSION_FILE"
Write-Host "Build Tag   : $APP_TAG"
if ($env:IS_BETA -eq 'true') {
    Write-Host ("App Version : {0}       (IS_BETA=true: v3.0.1_B20060930_0930)" -f $APP_VER_FULL)
} else {
    Write-Host ("App Version : {0}       (IS_BETA=false: v3.0.1 only)" -f $APP_VER_FULL)
}
Write-Host "Build Time  : $BuildTime"
Write-Host "Beta        : $($env:IS_BETA)"
Write-Host "Platform    : $GOOS_T/$GOARCH_T"
Write-Host "LogLevel    : $($env:LOG_LEVEL)"
Write-Host "Config      : $RUN_CFG_USE"
Write-Host "Output      : $RUN_EXE"
Write-Host '======================================================='

# ============================================================
#  Clean up & stale process cleanup (kill ONLY our own exes +
#  Go toolchain subprocesses; never kill arbitrary go.exe
#  since other Go projects / IDE backends may be running)
# ============================================================
Get-ChildItem -Path $SCRIPT_DIR -Filter '*.exe.old' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

foreach ($proc in @('wireguard', 'wireguard-go', 'compile', 'asm', 'link')) {
    Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

# ============================================================
#  Build with ldflags injection — values injected into
#  Go `package main` variables defined in main.go / main_windows.go:
#    - main.appVer         (APP_VER_FULL = IS_BETA=true -> TAG_BYYYYMMDD_HHmm
#                                          IS_BETA=false -> TAG only)
#    - main.BuildTime      ("yyyy-MM-dd(HH:mm:ss)", still wrap the entire
#                            -X VALUE in escaped "..." quotes for robustness)
#    - main.IsBeta         (only if $env:IS_BETA is non-empty)
# ============================================================
$LDFLAGS_PARTS = @('-s', '-w')
$LDFLAGS_PARTS += "-X main.appVer=$APP_VER_FULL"
$LDFLAGS_PARTS += "-X `"main.BuildTime=$BuildTime`""     # NB: inner escaped quotes for robustness
if (-not [string]::IsNullOrWhiteSpace($env:IS_BETA)) {
    $LDFLAGS_PARTS += "-X main.IsBeta=$($env:IS_BETA)"
}
$LDFLAGS = $LDFLAGS_PARTS -join ' '

Write-Host "Running: go build -buildvcs=false -trimpath -ldflags `"$LDFLAGS`" -o `"$OUT_EXE_NAME`""
& go build -buildvcs=false -trimpath -ldflags $LDFLAGS -o $OUT_EXE_NAME
if ($LASTEXITCODE -ne 0) {
    Write-Host '[ERROR] Build failed.' -ForegroundColor Red
    exit $LASTEXITCODE
}
Write-Host "Build OK: $RUN_EXE" -ForegroundColor Green

# Optional: copy to PATH alias directory if exists
$ALIAS_DIR = 'C:\DevDisk\Other\Alias'
if (Test-Path $ALIAS_DIR) {
    Copy-Item -Path $RUN_EXE -Destination $ALIAS_DIR -Force -ErrorAction SilentlyContinue
}

Write-Host '======================================================='

# ============================================================
#  Admin check + elevate if needed
# ============================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

$exeArgs = @()
if (-not [string]::IsNullOrWhiteSpace($RUN_CFG_USE)) {
    $exeArgs += '--confile'
    $exeArgs += $RUN_CFG_USE
}

if ($isAdmin) {
    & $RUN_EXE @exeArgs
    exit $LASTEXITCODE
}

# Elevate
Write-Host "Requesting administrator rights to start $OUT_EXE_NAME ..." -ForegroundColor Cyan
$procInfo = Start-Process -FilePath $RUN_EXE -ArgumentList $exeArgs -Verb RunAs -Wait -PassThru
exit $procInfo.ExitCode
