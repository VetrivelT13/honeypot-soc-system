@echo off
:: =============================================================================
:: start_cowrie.bat — Launch Cowrie SSH Honeypot via WSL (run on Windows)
:: Double-click this file OR run from Command Prompt
:: =============================================================================

title Cowrie SSH Honeypot

echo.
echo  ╔══════════════════════════════════════════════════╗
echo  ║   COWRIE SSH HONEYPOT — Starting via WSL        ║
echo  ║   Port: 2222   Log: FYProject/logs/cowrie/      ║
echo  ╚══════════════════════════════════════════════════╝
echo.

:: Check WSL is available
where wsl >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] WSL is not installed or not in PATH.
    echo.
    echo  To install WSL, open PowerShell as Administrator and run:
    echo    wsl --install
    echo  Then restart your computer.
    echo.
    pause
    exit /b 1
)

echo  [INFO] Launching Cowrie inside WSL...
echo  [INFO] Keep this window open while running.
echo  [INFO] Press Ctrl+C to stop the live feed (Cowrie keeps running in background)
echo.

:: Run the start script inside WSL
wsl bash /mnt/c/Users/vetri/Desktop/FYProject/cowrie_integration/start_cowrie_wsl.sh

echo.
echo  [INFO] Cowrie session ended.
pause
