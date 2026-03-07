#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

echo "═══════════════════════════════════════════"
echo "  OfSec V3 — Startup Script (Linux/Mac)"
echo "═══════════════════════════════════════════"
echo ""

# 1. Python check
PY_VER=$(python3 --version 2>&1 | grep -oP '3\.\K[0-9]+' || echo "0")
[ "$PY_VER" -lt 11 ] && error "Python 3.11+ required (found 3.$PY_VER)"
info "Python 3.$PY_VER found"

# 2. Virtualenv
[ ! -d ".venv" ] && python3 -m venv .venv && info "Created .venv"
source .venv/bin/activate
info "Activated .venv"

# 3. Dependencies
if [ -f "backend/requirements.txt" ]; then
    pip install -q -r backend/requirements.txt
else
    warn "requirements.txt not found, installing from pyproject.toml..."
    cd backend && pip install -q -e . && cd ..
fi
info "Dependencies installed"

# 4. .env check
if [ ! -f "backend/.env" ]; then
    cp backend/.env.example backend/.env
    warn ".env created from .env.example — fill in API keys before use"
fi

# 5. Redis check
if redis-cli ping &>/dev/null; then
    info "Redis is running"
else
    warn "Redis not found — using InMemoryBroker (tasks won't survive restarts)"
fi

# 6. Create log dir
mkdir -p backend/logs

# 7. Start worker
cd backend
python -m taskiq worker app.workers.taskiq_app:broker \
    --workers 2 >> logs/worker.log 2>&1 &
WORKER_PID=$!
info "Taskiq worker started (PID $WORKER_PID)"

# 8. Start server
python -m uvicorn app.main:app \
    --host 0.0.0.0 --port 8000 --reload >> logs/server.log 2>&1 &
SERVER_PID=$!
info "Uvicorn started (PID $SERVER_PID)"
cd ..

# 9. Save PIDs
echo "$WORKER_PID $SERVER_PID" > .pids

# 10. Health check
sleep 3
if curl -sf http://localhost:8000/health > /dev/null; then
    echo ""
    echo "═══════════════════════════════════════════"
    info "OfSec V3 is running!"
    info "Dashboard:  http://localhost:8000"
    info "API docs:   http://localhost:8000/docs"
    info "Logs:       backend/logs/ofsec.log"
    echo "═══════════════════════════════════════════"
else
    error "Server failed to start — last 20 lines of log:\n$(tail -20 backend/logs/server.log)"
fi

echo ""
warn "Press Ctrl+C to stop all services"
trap 'kill $WORKER_PID $SERVER_PID 2>/dev/null; rm -f .pids; echo -e "\n${GREEN}Stopped.${NC}"' SIGINT SIGTERM
wait
