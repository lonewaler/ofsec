@echo off
title OfSec V3 Launcher
color 0A

echo.
echo  ============================================
echo       OfSec V3 — Platform Launcher
echo       Vector Triangulum Cybersecurity
echo  ============================================
echo.

:: ─── Check Python ──────────────────────────
where python >nul 2>&1
if errorlevel 1 (
    color 0C
    echo  [ERROR] Python is not installed or not in PATH!
    echo  Download from https://python.org/downloads
    echo.
    pause
    exit /b 1
)

:: Show Python version
for /f "tokens=*" %%i in ('python --version 2^>^&1') do set PY_VER=%%i
echo  [OK] Found %PY_VER%

:: ─── Check Node.js ─────────────────────────
where node >nul 2>&1
if errorlevel 1 (
    color 0C
    echo  [ERROR] Node.js is not installed or not in PATH!
    echo  Download from https://nodejs.org
    echo.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('node --version 2^>^&1') do set NODE_VER=%%i
echo  [OK] Found Node.js %NODE_VER%

:: ─── Navigate to backend ───────────────────
cd /d "%~dp0backend"
if errorlevel 1 (
    color 0C
    echo  [ERROR] Cannot find backend directory!
    pause
    exit /b 1
)

:: ─── Create virtual environment if needed ───
if not exist "venv" (
    echo.
    echo  [SETUP] Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        color 0C
        echo  [ERROR] Failed to create virtual environment!
        pause
        exit /b 1
    )
    echo  [OK] Virtual environment created.
)

:: ─── Activate virtual environment ───────────
call venv\Scripts\activate.bat
echo  [OK] Virtual environment activated.

:: ─── Install / update dependencies ──────────
echo.
echo  [SETUP] Checking Python dependencies...
pip install -e "." --quiet --disable-pip-version-check 2>nul
if errorlevel 1 (
    echo  [WARN] Some dependencies may have failed. Trying with --no-deps...
    pip install -e "." --quiet --disable-pip-version-check --no-deps 2>nul
)
echo  [OK] Python dependencies ready.

:: ─── Create logs directory ──────────────────
if not exist "logs" mkdir logs
echo  [OK] Log directory ready (backend\logs\)

:: ─── Set environment from .env ──────────────
if exist ".env" (
    echo  [OK] Environment file found (.env)
) else if exist ".env.example" (
    echo  [WARN] No .env file found — copying from .env.example
    copy .env.example .env >nul
    echo  [OK] Created .env from template — edit API keys as needed
) else (
    echo  [WARN] No .env file found — using defaults
)

:: ─── Install frontend dependencies ──────────
echo.
echo  [SETUP] Checking frontend dependencies...
cd /d "%~dp0frontend"
if not exist "node_modules" (
    echo  [SETUP] Installing npm packages...
    cmd /c npm install --silent 2>nul
)
echo  [OK] Frontend dependencies ready.

:: ─── Display startup info ───────────────────
echo.
echo  ┌─────────────────────────────────────────┐
echo  │  Starting OfSec V3 (Vite + FastAPI)     │
echo  │                                           │
echo  │  Frontend: http://localhost:3000           │
echo  │  Backend:  http://localhost:8000           │
echo  │  API Docs: http://localhost:8000/docs      │
echo  │  Health:   http://localhost:8000/health     │
echo  │  Logs:     backend\logs\ofsec.log          │
echo  └─────────────────────────────────────────┘
echo.

:: ─── Start the backend server ───────────────
echo  [STARTING] Launching uvicorn on port 8000...
cd /d "%~dp0backend"
start "OfSec Backend" cmd /k "cd /d "%~dp0backend" && call venv\Scripts\activate.bat && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"

:: ─── Start the Vite dev server ──────────────
echo  [STARTING] Launching Vite dev server on port 3000...
cd /d "%~dp0frontend"
start "OfSec Frontend" cmd /k "cd /d "%~dp0frontend" && cmd /c npx vite --host"

:: ─── Wait for servers to start ──────────────
echo  Waiting for servers to initialize (6 seconds)...
timeout /t 6 /nobreak > nul

:: ─── Open browser (Vite dev server) ─────────
echo  [OK] Opening browser...
start http://localhost:3000/

echo.
echo  ============================================
echo   OfSec V3 is running!
echo.
echo   * Frontend: http://localhost:3000  (Vite HMR)
echo   * Backend:  http://localhost:8000
echo   * API:      http://localhost:8000/docs
echo   * Logs:     backend\logs\ofsec.log
echo   * Errors:   backend\logs\ofsec_errors.log
echo.
echo   Press any key to close this launcher.
echo   (Do NOT close the server terminal windows!)
echo  ============================================
echo.
pause
