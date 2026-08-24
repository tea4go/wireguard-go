@echo off
setlocal EnableExtensions EnableDelayedExpansion
cls

set "SCRIPT_DIR=%~dp0"
set "GOCACHE=%SCRIPT_DIR%.gocache"
set "GOTMPDIR=%SCRIPT_DIR%.gotmp"

set "OUT_EXE_NAME=wireguard.exe"
set "RUN_EXE=%SCRIPT_DIR%%OUT_EXE_NAME%"

if not exist "%GOCACHE%" mkdir "%GOCACHE%" >nul 2>nul
if not exist "%GOTMPDIR%" mkdir "%GOTMPDIR%" >nul 2>nul

REM ======================================================================
REM 可通过环境变量覆盖以下参数：
REM   GIT_TAG       : 强制指定版本号（不写则从 git describe --dirty 推导，兜底 v0.0.0-devel）
REM   IS_BETA       : 是否标记为 Beta（默认 "true"，留空则不注入
REM   LOG_LEVEL     : WireGuard device logger 的 LOG_LEVEL（verbose/debug/info/notice/warn/error/silent，默认 verbose
REM   RUN_CONFIG    : 启动时使用的配置文件路径（默认 .\conf\wgtun1.conf）
REM ======================================================================
if "%IS_BETA%"==""        set "IS_BETA=true"
if "%LOG_LEVEL%"==""      set "LOG_LEVEL=verbose"
if "%RUN_CONFIG%"==""     set "RUN_CONFIG=%SCRIPT_DIR%conf\wgtun1.conf"

REM === 版本号注入：优先取外部 GIT_TAG，否则用 git describe，失败再兜底
set "GIT_TAG_INPUT=%GIT_TAG%"
if "%GIT_TAG_INPUT%"=="" for /f "delims=" %%i in ('git -C "%SCRIPT_DIR%" describe --dirty --always --tags 2^>nul') do set "GIT_TAG_INPUT=%%i"
if "%GIT_TAG_INPUT%"=="" set "GIT_TAG_INPUT=v0.0.0-devel"

REM 构建时间：YYYY-MM-DD_HH-MM-SS，统一 0 前缀补齐（避免 %time% 空格影响）
for /f "tokens=1-6 delims=/:. " %%a in ("%date% %time: =0%") do set "BuildTime=%%a-%%b-%%c_%%d-%%e-%%f"

REM 通过 go env 获取 GOOS / GOARCH 以展示（用 for /f 确保输出安全）
set "GOOS_T="
set "GOARCH_T="
for /f "usebackq tokens=*" %%A in (`go env GOOS`)   do set "GOOS_T=%%A"
for /f "usebackq tokens=*" %%A in (`go env GOARCH`) do set "GOARCH_T=%%A"

echo =======================================================
echo Project Dir : %SCRIPT_DIR%
echo Build Tag   : %GIT_TAG_INPUT%
echo Build Time  : %BuildTime%
echo Beta        : %IS_BETA%
echo Platform    : %GOOS_T%/%GOARCH_T%
echo LogLevel    : %LOG_LEVEL%
echo Config      : %RUN_CONFIG%
echo Output      : %RUN_EXE%
echo =======================================================

REM 清理历史产物（不依赖 attrib -H 的旧残留）
del /f /q "%SCRIPT_DIR%*.exe.old" >nul 2>nul

REM 杀掉可能挂起的构建 / 运行中的进程
taskkill /f /im compile.exe      >nul 2>nul
taskkill /f /im asm.exe          >nul 2>nul
taskkill /f /im link.exe         >nul 2>nul
taskkill /f /im git.exe          >nul 2>nul
taskkill /f /im go.exe           >nul 2>nul
taskkill /f /im wireguard.exe    >nul 2>nul
taskkill /f /im wireguard-go.exe >nul 2>nul

REM 构建：通过 -ldflags 直接注入版本号、构建时间、Beta 标记
set "LDFLAGS=-s -w -X main.appVer=%GIT_TAG_INPUT% -X main.BuildTime=%BuildTime% -X main.IsBeta=%IS_BETA%"
echo Running: go build -buildvcs=false -trimpath -ldflags "%LDFLAGS%" -o "%OUT_EXE_NAME%"
go build -buildvcs=false -trimpath -ldflags "%LDFLAGS%" -o "%OUT_EXE_NAME%"
if errorlevel 1 (
    echo [ERROR] Build failed.
    exit /b 1
)
echo Build OK: %RUN_EXE%

REM 可选：把产物复制到 %PATH% 中的别名目录（不存在则跳过）
if exist "C:\DevDisk\Other\Alias\*" copy /y "%RUN_EXE%" "C:\DevDisk\Other\Alias\" >nul 2>nul

echo =======================================================
echo Starting %OUT_EXE_NAME% (log_level=%LOG_LEVEL%, config=%RUN_CONFIG%)...

REM 检查是否已为管理员权限；无权限则自动提权启动
net session >nul 2>&1
if errorlevel 1 goto run_elevated

"%RUN_EXE%" --confile "%RUN_CONFIG%"
goto :eof

:run_elevated
echo Requesting administrator rights to start %OUT_EXE_NAME% ...
powershell -NoProfile -Command ^
  "$exe = '%RUN_EXE%';" ^
  "$cfg = '%RUN_CONFIG%';" ^
  "$p = Start-Process -FilePath $exe -ArgumentList '--confile', $cfg -Verb RunAs -Wait -PassThru;" ^
  "exit $p.ExitCode"
exit /b %errorlevel%
