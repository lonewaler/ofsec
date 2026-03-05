#!/usr/bin/env bash
# OfSec V3 — Production start script
set -euo pipefail

echo "[OfSec] Running database migrations..."
alembic upgrade head
echo "[OfSec] Migrations complete."

if [ "${ENVIRONMENT:-development}" = "production" ]; then
  echo "[OfSec] Starting in PRODUCTION mode"
  exec gunicorn app.main:app \
    --workers "${GUNICORN_WORKERS:-4}" \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind "0.0.0.0:${PORT:-8000}" \
    --timeout 120 \
    --access-logfile - \
    --error-logfile - \
    --log-level "${LOG_LEVEL:-warning}"
else
  echo "[OfSec] Starting in DEVELOPMENT mode"
  exec uvicorn app.main:app \
    --host 0.0.0.0 \
    --port "${PORT:-8000}" \
    --reload \
    --log-level "${LOG_LEVEL:-info}"
fi
