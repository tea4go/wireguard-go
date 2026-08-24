#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('windows', 'linux', 'macos')]
    [string]$OS = 'windows',

    [ValidateSet('amd64', 'arm64')]
    [string]$Arch = 'amd64'
)

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

switch ($OS) {
    'windows' {
        $TargetGOOS = 'windows'
        $OUT_BIN_NAME = 'wireguard.exe'
    }
    'linux' {
        $TargetGOOS = 'linux'
        $OUT_BIN_NAME = 'wireguard-go'
    }
    'macos' {
        $TargetGOOS = 'darwin'
        $OUT_BIN_NAME = 'wireguard-go'
    }
}

$RUN_EXE = Join-Path $SCRIPT_DIR $OUT_BIN_NAME

if (-not (Test-Path $env:GOCACHE))  { New-Item -ItemType Directory -Path $env:GOCACHE  -Force | Out-Null }
if (-not (Test-Path $env:GOTMPDIR)) { New-Item -ItemType Directory -Path $env:GOTMPDIR -Force | Out-Null }

# ============================================================
#  Overridable env vars (set before calling this script):
#    APP_TAG     - force build version (e.g. v3.0.9), skips VERSION.txt auto-increment
#    IS_BETA     - "true" or empty (default: empty, align with Makefile)
#    log_level   - numeric 0..7 (default 5=Notice, 7=Debug/Verbose)
#    RUN_CONFIG  - full path to the .conf/.zip config file
#  Persistent version file:
#    VERSION.txt at project root (SCRIPT_DIR) holds last MAJOR.MINOR.PATCH;
#    each build auto-increments PATCH, carrying over when any digit > 9
#      e.g. v3.0.9 -> v3.1.0 ; v3.9.9 -> v4.0.0
# ============================================================
if ([string]::IsNullOrWhiteSpace($env:IS_BETA))     { $env:IS_BETA     = 'false' }
if ([string]::IsNullOrWhiteSpace($env:log_level))   { $env:log_level   = '7' }
if ($OS -eq 'windows' -and [string]::IsNullOrWhiteSpace($env:RUN_CONFIG)) {
    $env:RUN_CONFIG  = Join-Path $SCRIPT_DIR 'conf\wgtun1.conf'
}

$VERSION_FILE = Join-Path $SCRIPT_DIR 'VERSION.txt'

# ============================================================
#  Pre-flight checks
# ============================================================
if (-not (Get-Command 'go' -ErrorAction SilentlyContinue)) {
    Write-Host '[错误] 未在 PATH 中找到 go 命令，请安装 Go 并添加到系统 PATH。' -ForegroundColor Red
    exit 1
}

if ($OS -eq 'windows') {
    $RUN_CFG_USE = $env:RUN_CONFIG
    if (-not [string]::IsNullOrWhiteSpace($RUN_CFG_USE) -and -not (Test-Path $RUN_CFG_USE)) {
        Write-Host "[警告] 未找到配置文件: $RUN_CFG_USE" -ForegroundColor Yellow
        Write-Host '       将不使用 --confile 参数启动（可设置 RUN_CONFIG 环境变量指定配置文件）。' -ForegroundColor Yellow
        $RUN_CFG_USE = ''
    }
} else {
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
    Write-Host "[信息] 使用强制版本号 APP_TAG=$APP_TAG（不更新 VERSION.txt）" -ForegroundColor Cyan
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

Write-Host '======================================================='
Write-Host "项目目录    : $SCRIPT_DIR"
Write-Host "版本文件    : $VERSION_FILE"
Write-Host "构建标签    : $APP_TAG"
if ($env:IS_BETA -eq 'true') {
    Write-Host ("应用版本    : {0}       (测试版=true: v3.0.1_B20060930_0930)" -f $APP_VER_FULL)
} else {
    Write-Host ("应用版本    : {0}       (测试版=false: 仅 v3.0.1)" -f $APP_VER_FULL)
}
Write-Host "构建时间    : $BuildTime"
Write-Host "测试版      : $($env:IS_BETA)"
Write-Host "目标平台    : $OS/$Arch"
Write-Host "Go 目标     : $TargetGOOS/$Arch"
if ($OS -eq 'windows') {
    Write-Host "日志级别    : $($env:log_level) (0=紧急..5=通知..7=调试/详细)"
    Write-Host "配置文件    : $RUN_CFG_USE"
}
Write-Host "输出文件    : $RUN_EXE"
Write-Host '======================================================='

# ============================================================
#  Clean up & stale process cleanup (kill ONLY our own exes +
#  Go toolchain subprocesses; never kill arbitrary go.exe
#  since other Go projects / IDE backends may be running)
# ============================================================
Get-ChildItem -Path $SCRIPT_DIR -Filter '*.exe.old' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

if ($OS -eq 'windows') {
    foreach ($proc in @('wireguard', 'wireguard-go', 'compile', 'asm', 'link')) {
        Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
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

$env:GOOS = $TargetGOOS
$env:GOARCH = $Arch

Write-Host "执行构建: GOOS=$TargetGOOS GOARCH=$Arch go build -buildvcs=false -trimpath -ldflags `"$LDFLAGS`" -o `"$OUT_BIN_NAME`""
& go build -buildvcs=false -trimpath -ldflags $LDFLAGS -o $OUT_BIN_NAME
if ($LASTEXITCODE -ne 0) {
    Write-Host '[错误] 构建失败。' -ForegroundColor Red
    exit $LASTEXITCODE
}
Write-Host "构建成功: $RUN_EXE" -ForegroundColor Green

# Optional: copy to PATH alias directory if exists
$ALIAS_DIR = 'C:\DevDisk\Other\Alias'
if ($OS -eq 'windows' -and (Test-Path $ALIAS_DIR)) {
    Copy-Item -Path $RUN_EXE -Destination $ALIAS_DIR -Force -ErrorAction SilentlyContinue
}

Write-Host '======================================================='

if ($OS -ne 'windows') {
    Write-Host "[信息] 非 Windows 目标仅执行编译，不自动运行输出文件。" -ForegroundColor Cyan
    exit 0
}

# ============================================================
#  停止守护进程（确保旧的 wireguard 守护进程已关闭）
# ============================================================
Write-Host '[信息] 正在停止 wireguard 相关守护进程...' -ForegroundColor Cyan
$daemonStopped = $false
foreach ($proc in @('wireguard', 'wireguard-go')) {
    $found = Get-Process -Name $proc -ErrorAction SilentlyContinue
    if ($found) {
        $found | ForEach-Object {
            Write-Host "  停止进程: $($_.ProcessName) (PID: $($_.Id))" -ForegroundColor Yellow
        }
        $found | Stop-Process -Force -ErrorAction SilentlyContinue
        $daemonStopped = $true
    }
}
if ($daemonStopped) {
    Start-Sleep -Seconds 1
    Write-Host '[信息] 守护进程已停止。' -ForegroundColor Green
} else {
    Write-Host '[信息] 未发现正在运行的守护进程。' -ForegroundColor Gray
}
Write-Host '======================================================='

# ============================================================
#  Admin check + elevate if needed
# ============================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

$exeArgs = @()
if ($args.Count -gt 0) {
    $exeArgs = @($args)
} else {
    if (-not [string]::IsNullOrWhiteSpace($RUN_CFG_USE)) {
        $exeArgs += '--confile'
        $exeArgs += $RUN_CFG_USE
    }
    $exeArgs += '-f'
}

if ($isAdmin) {
    & $RUN_EXE @exeArgs
    exit $LASTEXITCODE
}

# 提权
Write-Host "正在请求管理员权限以启动 $OUT_BIN_NAME ..." -ForegroundColor Cyan
$procInfo = Start-Process -FilePath $RUN_EXE -ArgumentList $exeArgs -Verb RunAs -Wait -PassThru
exit $procInfo.ExitCode
