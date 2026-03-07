#!/usr/bin/env bash
if [ -f .pids ]; then
    read WORKER_PID SERVER_PID < .pids
    kill $WORKER_PID $SERVER_PID 2>/dev/null && echo "Stopped." || echo "Processes already stopped."
    rm -f .pids
else
    echo "No .pids file found — killing by port"
    fuser -k 8000/tcp 2>/dev/null || true
fi
