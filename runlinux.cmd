@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "PS1_SCRIPT=%SCRIPT_DIR%buildapp.ps1"

if not exist "%PS1_SCRIPT%" (
    echo [ERROR] buildapp.ps1 not found: %PS1_SCRIPT%
    exit /b 1
)

REM Thin wrapper: delegate Linux cross-build to buildapp.ps1, forcing -OS linux.
REM Usage:
REM   runlinux.cmd                 -> default linux/amd64
REM   runlinux.cmd -Arch arm64     -> linux/arm64
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1_SCRIPT%" -OS linux %*
exit /b %ERRORLEVEL%