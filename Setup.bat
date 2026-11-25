@echo off
chcp 950 >nul
title SimpleHoneypot 安裝

rem 切到這個 .bat 所在的資料夾（提權後 CWD 會變成 System32）
cd /d "%~dp0"

rem 沒有系統管理員權限就用 UAC 重新啟動自己
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo 需要系統管理員權限，正在要求提權...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

if not exist "python\python.exe" (
    echo 找不到 python\python.exe，請確認這個資料夾是從部署包解開的。
    pause
    exit /b 1
)

"python\python.exe" setup.py
echo.
pause
