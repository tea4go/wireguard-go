@echo off
setlocal
cls

set "SCRIPT_DIR=%~dp0"
set "GOCACHE=%SCRIPT_DIR%.gocache"
set "GOTMPDIR=%SCRIPT_DIR%.gotmp"
set "RUN_EXE=%SCRIPT_DIR%wireguard.exe"

if not exist "%GOCACHE%" mkdir "%GOCACHE%" >nul 2>nul
if not exist "%GOTMPDIR%" mkdir "%GOTMPDIR%" >nul 2>nul

set "BuildTime=%date%_%time%"
set "BuildTime=%BuildTime: =0%"
set "IsBeta=true"

echo BuildTime:%BuildTime%

attrib -H *.old               >nul 2>nul
del *.exe.old                 >nul 2>nul

taskkill /f /im compile.exe   >nul 2>nul
taskkill /f /im asm.exe       >nul 2>nul
taskkill /f /im link.exe      >nul 2>nul
taskkill /f /im git.exe       >nul 2>nul
taskkill /f /im go.exe        >nul 2>nul
taskkill /f /im wireguard.exe >nul 2>nul

go build -buildvcs=false -ldflags "-X main.IsBeta=%IsBeta% -X main.BuildTime=%BuildTime%"
if errorlevel 1 (
    echo Build failed.
    exit /b 1
)

copy /y wireguard.exe C:\DevDisk\Other\Alias >nul 2>nul
echo =======================================================

net session >nul 2>&1
if errorlevel 1 goto run_elevated

"%RUN_EXE%" -l=7 --confile ".\conf\wgtun1.conf"
goto :eof

:run_elevated
echo Requesting administrator rights to start wireguard.exe ...
powershell -NoProfile -Command "$exe = '%RUN_EXE%'; $cfg = '%RUN_CONFIG%'; $p = Start-Process -FilePath $exe -ArgumentList '--confile', $cfg -Verb RunAs -Wait -PassThru; exit $p.ExitCode"
exit /b %errorlevel%
