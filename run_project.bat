@echo off
title CyberSentinel SOC Platform - Final Year Project
color 0b

echo ========================================================
echo        CyberSentinel AI-Powered SOC Platform
echo      Final Year B.E. Computer Science Project
echo ========================================================
echo.

echo [*] Applying latest database migrations...
python manage.py migrate --noinput

echo.
echo [*] Seeding demonstration security data and threat intelligence...
python seed_data.py

echo.
echo [*] Launching CyberSentinel SOC Dashboard on http://127.0.0.1:8000/
echo [*] Press Ctrl+C in this console window to terminate the server.
echo.

start http://127.0.0.1:8000/
python manage.py runserver 127.0.0.1:8000
pause
