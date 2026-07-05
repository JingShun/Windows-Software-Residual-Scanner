@echo off
chcp 65001
cd /d "%~dp0"

:: 確保以管理員權限執行
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo 請以「系統管理員身分」執行此批次檔。
    pause
    exit /b
)

:: 呼叫 PowerShell
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Scan-Residuals.ps1"
pause