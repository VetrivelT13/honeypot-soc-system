@echo off
chcp 437 >nul 2>&1
title FYProject - Honeypot SOC System

echo.
echo  =========================================================
echo   ADVANCED MULTI-SERVICE HONEYPOT - SOC PLATFORM
echo   Final Year Cybersecurity Project - Vetrivel
echo  =========================================================
echo.

cd /d C:\Users\vetri\Desktop\FYProject

:: --- Check Python ---
python --version >nul 2>&1
if errorlevel 1 goto NO_PYTHON
echo [OK] Python found.
goto CHECK_WSL

:NO_PYTHON
echo [ERROR] Python not found in PATH.
echo Install Python 3.9+ from https://python.org
pause
exit /b 1

:: --- Check WSL ---
:CHECK_WSL
wsl --status >nul 2>&1
if errorlevel 1 goto NO_WSL
echo [OK] WSL found.
goto START_COWRIE

:NO_WSL
echo [SKIP] WSL not available - Cowrie SSH honeypot will be skipped.
echo        Telnet, Web Honeypot and SOC Dashboard will run normally.
goto START_MAIN

:: --- Start Cowrie via WSL ---
:START_COWRIE
echo [1/2] Starting Cowrie SSH Honeypot in WSL...
start "Cowrie SSH Honeypot [Port 2222]" cmd /k "wsl bash /mnt/c/Users/vetri/Desktop/FYProject/cowrie_integration/start_cowrie_wsl.sh"
echo [OK] Cowrie window launched on port 2222.
echo      Waiting 4 seconds for Cowrie to initialise...
timeout /t 4 /nobreak >nul

:: --- Start main SOC system ---
:START_MAIN
echo.
echo [2/2] Starting SOC Dashboard + Web Honeypot + Telnet Honeypot...
echo.
echo  ---------------------------------------------------------
echo   SOC Dashboard  --  http://localhost:5000
echo   Web Honeypot   --  http://localhost:8080/login
echo   Telnet Trap    --  telnet localhost 2323
echo   SSH Honeypot   --  ssh root@localhost -p 2222
echo  ---------------------------------------------------------
echo.
echo  Press Ctrl+C to stop all services.
echo.

python main.py

echo.
echo [INFO] System stopped.
pause
