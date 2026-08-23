@echo off
@REM chcp 65001
cls

set "hour=%time:~0,2%"
if "%hour:~0,1%" == " " set "hour=0%hour:~1,1%"

set "year=%date:~0,4%"
set "month=%date:~5,2%"
set "day=%date:~8,2%"

set "minute=%time:~3,2%"
set "second=%time:~6,2%"

set "date_text=%year%-%month%-%day%(%hour%:%minute%:%second%)"
set "date_version=%year%%month%%day%_%hour%%minute%%second%"

set BuildTime=%date_text%
rem 检查是否传递了 -release 参数, 设置为true表示测试版，false表示正式版
set IsBeta=true

echo BuildTime:%BuildTime%

attrib -H *.old                >nul 2>nul
del *.exe.old                  >nul 2>nul

:: 清理残留的编译进程
taskkill /f /im compile.exe    >nul 2>nul
taskkill /f /im asm.exe        >nul 2>nul
taskkill /f /im link.exe       >nul 2>nul
taskkill /f /im git.exe        >nul 2>nul
taskkill /f /im go.exe         >nul 2>nul
taskkill /f /im wireguard.exe  >nul 2>nul
go build -ldflags "-X main.IsBeta=%IsBeta% -X main.BuildTime=%BuildTime%"

if errorlevel 1 (
    echo 编译失败，请检查错误信息。
    exit /b 1
)

copy /y wireguard.exe  C:\DevDisk\Other\Alias >nul 2>nul
echo =======================================================

wireguard wgtun1
