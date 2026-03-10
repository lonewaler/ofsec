@echo off
setlocal

echo ═══════════════════════════════════════════
echo   OfSec V3 — Startup Script (Windows)
echo ═══════════════════════════════════════════
echo.

REM 1. Python check
where python >nul 2>&1 || (echo [ERROR] Python not found in PATH & exit /b 1)
for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo [OK] Python %PYVER% found

REM 1b. Node.js check
where npm >nul 2>&1 || (echo [ERROR] npm not found in PATH & exit /b 1)
for /f "tokens=*" %%v in ('npm --version 2^>^&1') do set NPMVER=%%v
echo [OK] Node/npm %NPMVER% found

set VENV_PATH=backend\venv
set PYTHON_EXE=%VENV_PATH%\Scripts\python.exe

REM 2. Virtualenv check
if not exist %PYTHON_EXE% (
    echo [ERROR] Virtual environment not found at %VENV_PATH%
    echo Please ensure the backend\venv exists and dependencies are installed.
    exit /b 1
)
echo [OK] Using Virtual Environment: %VENV_PATH%

REM 3. .env check
if not exist backend\.env (
    copy backend\.env.example backend\.env >nul
    echo [WARN] .env created — fill in API keys in backend\.env before use
)

REM 4. Database Migrations
echo [SETUP] Running Database Migrations...
cd backend
venv\Scripts\python.exe -m alembic upgrade head
cd ..
echo [OK] Migrations complete

REM 5. Create log dir
if not exist backend\logs mkdir backend\logs

REM 6. Start Taskiq worker in background
echo [OK] Starting Taskiq worker...
start /b cmd /c "cd backend && venv\Scripts\python.exe -m taskiq worker app.workers.taskiq_app:broker --workers 2 > logs\worker.log 2>&1"

REM 7. Start Uvicorn server in background
echo [OK] Starting Uvicorn server...
start /b cmd /c "cd backend && venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload > logs\server.log 2>&1"

REM 8. Wait for startup
timeout /t 6 /nobreak >nul

REM 9. Health check
curl -sf http://localhost:8000/health >nul 2>&1
if %errorlevel% == 0 (
    echo.
    echo ═══════════════════════════════════════════
    echo   [OK] OfSec V3 running!
    echo   Dashboard:  http://localhost:8000
    echo   API docs:   http://localhost:8000/api/docs
    echo   Logs:       backend\logs\server.log
    echo ═══════════════════════════════════════════
) else (
    echo [ERROR] Server failed — check backend\logs\server.log
    if exist backend\logs\server.log (
        echo --- Last 10 lines of server.log ---
        powershell -Command "Get-Content backend\logs\server.log -Tail 10"
    )
    exit /b 1
)

echo.
echo Press Ctrl+C to stop, or close this window.
pause >nul

