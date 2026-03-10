"""
OfSec V3 — Log Router
=======================
Endpoints for frontend error reporting and log retrieval.
"""

from __future__ import annotations

import os
from collections import deque
from datetime import UTC, datetime

import structlog
from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from app.core.logging import get_error_log_file_path, get_log_file_path

router = APIRouter(prefix="/log", tags=["Logging"])
logger = structlog.get_logger()


class FrontendErrorReport(BaseModel):
    """Error reported from the frontend JS."""

    message: str = Field(..., description="Error message")
    source: str = Field(default="frontend", description="Error source (page, component)")
    stack: str = Field(default="", description="Stack trace if available")
    url: str = Field(default="", description="Page URL where error occurred")
    user_agent: str = Field(default="", description="Browser user agent")


@router.post("/error", tags=["Logging"])
async def report_frontend_error(report: FrontendErrorReport, request: Request):
    """Receive error reports from the frontend and log them."""
    client_ip = request.client.host if request.client else "unknown"
    logger.error(
        "frontend.error",
        message=report.message,
        source=report.source,
        stack=report.stack,
        url=report.url,
        user_agent=report.user_agent,
        client_ip=client_ip,
    )
    return {"status": "logged", "timestamp": datetime.now(UTC).isoformat()}


@router.get("/recent", tags=["Logging"])
async def get_recent_logs(lines: int = 50, level: str = "all"):
    """
    Get recent log entries from the log file.
    level: 'all', 'error', 'warning', 'info'
    """
    log_path = get_error_log_file_path() if level in ("error", "warning") else get_log_file_path()

    if not os.path.exists(log_path):
        return {"entries": [], "total": 0, "file": log_path}

    # Read last N lines efficiently
    try:
        with open(log_path, encoding="utf-8") as f:
            all_lines = deque(f, maxlen=lines)
        entries = [line.strip() for line in all_lines if line.strip()]
        return {"entries": entries, "total": len(entries), "file": log_path}
    except Exception as e:
        logger.error("log.read_failed", error=str(e))
        return {"entries": [], "total": 0, "error": str(e)}
