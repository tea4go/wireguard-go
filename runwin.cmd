@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul
cls

set "SCRIPT_DIR=%~dp0"
set "GOCACHE=%SCRIPT_DIR%.gocache"
set "GOTMPDIR=%SCRIPT_DIR%.gotmp"

set "OUT_EXE_NAME=wireguard.exe"
set "RUN_EXE=%SCRIPT_DIR%%OUT_EXE_NAME%"

if not exist "%GOCACHE%" mkdir "%GOCACHE%" >nul 2>nul
if not exist "%GOTMPDIR%" mkdir "%GOTMPDIR%" >nul 2>nul

REM ============================================================
REM  Overridable env vars (set before calling this script):
REM    APP_TAG     - force build version (e.g. v3.0.9), skips VERSION.txt auto-increment
REM    IS_BETA     - "true" or empty
REM    LOG_LEVEL   - verbose/debug/info/notice/warn/error/silent
REM    RUN_CONFIG  - full path to the .conf/.zip config file
REM  Persistent version file:
REM    VERSION.txt at project root (SCRIPT_DIR) holds last MAJOR.MINOR.PATCH;
REM    each build auto-increments PATCH, carrying over when any digit > 9
REM      e.g. v3.0.9 -> v3.1.0 ; v3.9.9 -> v4.0.0
REM ============================================================
if "%IS_BETA%"==""    set "IS_BETA=true"
if "%LOG_LEVEL%"==""  set "LOG_LEVEL=verbose"
if "%RUN_CONFIG%"=="" set "RUN_CONFIG=%SCRIPT_DIR%conf\wgtun1.conf"

set "VERSION_FILE=%SCRIPT_DIR%VERSION.txt"

REM ---------- Date (fixed offsets: YYYY at 0..3, MM at 5..6, DD at 8..9) ----------
set "year=%date:~0,4%"
set "month=%date:~5,2%"
set "day=%date:~8,2%"

REM ---------- Time (HH at 0..1, MI at 3..4, SS at 6..7) ----------
set "hour=%time:~0,2%"
if "%hour:~0,1%" == " " set "hour=0%hour:~1,1%"
set "minute=%time:~3,2%"
set "second=%time:~6,2%"

REM ---------- Compose final values ----------
set "_YYYY=%year%"
set "_MM=%month%"
set "_DD=%day%"
set "_HH=%hour%"
set "_MI=%minute%"
set "_SS=%second%"
set "BuildTime=%_YYYY%-%_MM%-%_DD% %_HH%:%_MI%:%_SS%"
set "_d=%_YYYY%%_MM%%_DD%"
set "_t=%_HH%%_MI%"

set "APP_VER_FULL=%APP_TAG%_B%_d%_%_t%"

REM GOOS / GOARCH for banner
set "GOOS_T="
set "GOARCH_T="
for /f "usebackq tokens=*" %%A in (`go env GOOS`)   do set "GOOS_T=%%A"
for /f "usebackq tokens=*" %%A in (`go env GOARCH`) do set "GOARCH_T=%%A"

echo =======================================================
echo Project Dir : !SCRIPT_DIR!
echo Build Tag   : !APP_TAG!
echo App Version : !APP_VER_FULL!       (example: v3.0.1_B20060930_0930)
echo Build Time  : !BuildTime!
echo Beta        : !IS_BETA!
echo Platform    : !GOOS_T!/!GOARCH_T!
echo LogLevel    : !LOG_LEVEL!
echo Config      : !RUN_CONFIG!
echo Output      : !RUN_EXE!
echo =======================================================

REM Clean old leftover exe
del /f /q "%SCRIPT_DIR%*.exe.old" >nul 2>nul

REM Kill stale build/running processes (best effort)
taskkill /f /im compile.exe      >nul 2>nul
taskkill /f /im asm.exe          >nul 2>nul
taskkill /f /im link.exe         >nul 2>nul
taskkill /f /im git.exe          >nul 2>nul
taskkill /f /im go.exe           >nul 2>nul
taskkill /f /im wireguard.exe    >nul 2>nul
taskkill /f /im wireguard-go.exe >nul 2>nul

REM Build with ldflags injection (APP_VER_FULL format: TAG_BYYYYMMDD_HHmm, BuildTime, IsBeta)
REM Note: main.BuildTime contains a space, so wrap its -X value in escaped \"...\" quotes
set LDFLAGS=-s -w -X main.appVer=!APP_VER_FULL! -X \"main.BuildTime=!BuildTime!\" -X main.IsBeta=!IS_BETA!
echo Running: go build -buildvcs=false -trimpath -ldflags "!LDFLAGS!" -o "!OUT_EXE_NAME!"
go build -buildvcs=false -trimpath -ldflags "!LDFLAGS!" -o "!OUT_EXE_NAME!"
if errorlevel 1 (
    echo [ERROR] Build failed.
    exit /b 1
)
echo Build OK: !RUN_EXE!

REM Optional: copy to PATH alias directory if exists
if exist "C:\DevDisk\Other\Alias\*" copy /y "!RUN_EXE!" "C:\DevDisk\Other\Alias\" >nul 2>nul

echo =======================================================
echo Starting !OUT_EXE_NAME! (log_level=!LOG_LEVEL!, config=!RUN_CONFIG!)...

REM Check admin rights, elevate if needed
net session >nul 2>&1
if errorlevel 1 goto run_elevated

"!RUN_EXE!" --confile "!RUN_CONFIG!"
goto :eof

:run_elevated
echo Requesting administrator rights to start !OUT_EXE_NAME! ...
powershell -NoProfile -Command ^
  "$exe = '!RUN_EXE!';" ^
  "$cfg = '!RUN_CONFIG!';" ^
  "$p = Start-Process -FilePath $exe -ArgumentList '--confile', $cfg -Verb RunAs -Wait -PassThru;" ^
  "exit $p.ExitCode"
exit /b %errorlevel%
