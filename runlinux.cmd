@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "PS1_SCRIPT=%SCRIPT_DIR%buildapp.ps1"

if not exist "%PS1_SCRIPT%" (
    echo [ERROR] buildapp.ps1 not found: %PS1_SCRIPT%
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1_SCRIPT%" %*
exit /b %ERRORLEVEL%
