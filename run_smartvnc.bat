@echo off
title SmartVNC Launcher
cd /d "%~dp0"
echo ======================================================================
echo                     STARTING SMARTVNC SYSTEM
echo ======================================================================
echo.

if exist ".venv\Scripts\python.exe" (
    set "PYTHON_EXE=.venv\Scripts\python.exe"
) else (
    set "PYTHON_EXE=python"
)

echo Using Python: "%PYTHON_EXE%"
echo.

echo [1/3] Starting SMARTVNC Risk API (Port 5000)...
start "SmartVNC - Risk API" cmd /k ""%PYTHON_EXE%" ml-engine/api/risk_api.py"

timeout /t 2 /nobreak >nul

echo [2/3] Starting SMARTVNC Network Monitor (Port 5900)...
start "SmartVNC - Network Monitor" cmd /k ""%PYTHON_EXE%" monitoring/vnc_monitor.py"

timeout /t 2 /nobreak >nul

echo [3/3] Launching SmartVNC Security Dashboard in your web browser...
echo Local URL: http://localhost:8501
echo.
"%PYTHON_EXE%" -m streamlit run dashboard/dashboard.py

pause
