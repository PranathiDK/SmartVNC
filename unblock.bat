@echo off
set "PYTHON_EXE=C:\Users\Pranathi D K\anaconda3\python.exe"
if not exist "%PYTHON_EXE%" (
    set "PYTHON_EXE=python"
)

if "%~1"=="" (
    "%PYTHON_EXE%" C:\SmartVNC\unblock.py
) else (
    "%PYTHON_EXE%" C:\SmartVNC\unblock.py %1
)
