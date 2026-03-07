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

REM 2. Virtualenv
if not exist .venv (
    python -m venv .venv
    echo [OK] Created .venv
)
call .venv\Scripts\activate.bat
echo [OK] Activated .venv

REM 3. Dependencies
pip install -q -r backend\requirements.txt 2>nul
if %errorlevel% neq 0 (
    echo [WARN] requirements.txt not found, installing from pyproject.toml...
    cd backend
    pip install -q -e .
    cd ..
)
echo [OK] Dependencies installed

REM 4. .env check
if not exist backend\.env (
    copy backend\.env.example backend\.env >nul
    echo [WARN] .env created — fill in API keys in backend\.env before use
)

REM 5. Create log dir
if not exist backend\logs mkdir backend\logs

REM 6. Start Taskiq worker in background
echo [OK] Starting Taskiq worker...
start /b cmd /c "cd backend && python -m taskiq worker app.workers.taskiq_app:broker --workers 2 >> logs\worker.log 2>&1"

REM 7. Start Uvicorn server in background
echo [OK] Starting Uvicorn server...
start /b cmd /c "cd backend && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload >> logs\server.log 2>&1"

REM 8. Wait for startup
timeout /t 4 /nobreak >nul

REM 9. Health check
curl -sf http://localhost:8000/health >nul 2>&1
if %errorlevel% == 0 (
    echo.
    echo ═══════════════════════════════════════════
    echo   [OK] OfSec V3 running!
    echo   Dashboard:  http://localhost:8000
    echo   API docs:   http://localhost:8000/docs
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
