Set-Location $PSScriptRoot

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "                    STARTING SMARTVNC SYSTEM                          " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

if (Test-Path ".\.venv\Scripts\python.exe") {
    $PythonExe = ".\.venv\Scripts\python.exe"
} else {
    $PythonExe = "python"
}

Write-Host "`n[1/3] Starting Risk Prediction API (Port 5000)..." -ForegroundColor Green
Start-Process cmd -ArgumentList "/k `"$PythonExe`" ml-engine/api/risk_api.py"

Start-Sleep -Seconds 2

Write-Host "[2/3] Starting Live Network Monitor (Port 5900)..." -ForegroundColor Green
Start-Process cmd -ArgumentList "/k `"$PythonExe`" monitoring/vnc_monitor.py"

Start-Sleep -Seconds 2

Write-Host "[3/3] Launching Security Dashboard in your browser..." -ForegroundColor Green
Write-Host "Dashboard URL: http://localhost:8501" -ForegroundColor Yellow
& "$PythonExe" -m streamlit run dashboard/dashboard.py
