@echo off
:: =============================================================================
:: setup_cowrie.bat — One-click Cowrie Setup via WSL (run on Windows)
:: Run this ONCE to install Cowrie inside WSL
:: =============================================================================

title Cowrie Setup

echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║   COWRIE SSH HONEYPOT — One-Time Setup                      ║
echo  ║   This will install Cowrie inside WSL/Ubuntu                ║
echo  ║   Estimated time: 3-5 minutes                               ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.
echo  [STEP 1] Checking WSL installation...

where wsl >nul 2>&1
if errorlevel 1 (
    echo.
    echo  [ERROR] WSL not found! Install it first:
    echo.
    echo    1. Open PowerShell as Administrator
    echo    2. Run: wsl --install
    echo    3. Restart your computer
    echo    4. Open Ubuntu from Start Menu and set a username/password
    echo    5. Then re-run this setup
    echo.
    pause
    exit /b 1
)

echo  [OK] WSL found.
echo.
echo  [STEP 2] Verifying Windows drive is mounted in WSL...
wsl ls /mnt/c/Users/vetri/Desktop/FYProject >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Cannot see FYProject from WSL.
    echo  Make sure FYProject is at: C:\Users\vetri\Desktop\FYProject
    pause
    exit /b 1
)
echo  [OK] FYProject visible from WSL.
echo.

echo  [STEP 3] Running Cowrie installation inside WSL...
echo  (You may be prompted for your WSL/Ubuntu sudo password)
echo.

wsl bash /mnt/c/Users/vetri/Desktop/FYProject/cowrie_integration/setup_cowrie_wsl.sh

if errorlevel 1 (
    echo.
    echo  [ERROR] Setup encountered an error. Check the output above.
    pause
    exit /b 1
)

echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║   SETUP COMPLETE!                                           ║
echo  ╠══════════════════════════════════════════════════════════════╣
echo  ║  Next Steps:                                                ║
echo  ║  1. Double-click start_all.bat to run the full system       ║
echo  ║  OR                                                         ║
echo  ║  1. Double-click start_cowrie.bat  → starts SSH honeypot    ║
echo  ║  2. Run: python main.py            → starts everything else  ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.
pause
