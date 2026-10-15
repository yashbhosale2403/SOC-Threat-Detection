@echo off
title CyberSentinel SOC Platform - Final Year Project
color 0b

rem Safe local-development defaults for the local Windows launcher.
set "DEBUG=True"
if not defined SECRET_KEY set "SECRET_KEY=local-development-only-not-for-production"
if not defined ALLOWED_HOSTS set "ALLOWED_HOSTS=127.0.0.1,localhost"

echo ========================================================
echo        CyberSentinel AI-Powered SOC Platform
echo      Final Year B.E. Computer Science Project
echo ========================================================
echo.

echo [*] Applying latest database migrations...
python manage.py migrate --noinput
if errorlevel 1 goto :error

echo.
echo [*] Seeding demonstration security data and threat intelligence...
python seed_data.py
if errorlevel 1 goto :error

echo.
echo [*] Launching CyberSentinel SOC Dashboard on http://127.0.0.1:8000/
echo [*] Press Ctrl+C in this console window to terminate the server.
echo.

start http://127.0.0.1:8000/
python manage.py runserver 127.0.0.1:8000
pause
goto :eof

:error
echo.
echo [ERROR] Setup failed. Check the error message above.
pause
