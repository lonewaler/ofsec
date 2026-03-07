@echo off
echo [OfSec V3] Stopping services...
taskkill /F /FI "WINDOWTITLE eq *uvicorn*" >nul 2>&1
taskkill /F /FI "WINDOWTITLE eq *taskiq*" >nul 2>&1
REM Kill by port as fallback
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8000 ^| findstr LISTENING') do (
    taskkill /F /PID %%a >nul 2>&1
)
echo [OK] Services stopped.
