"""
OfSec V3 — Structured Logging
==============================
JSON structured logging via structlog for observability.
Logs to both console (dev) AND rotating file (always).
"""

from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

import structlog

from app.config import settings

# Log directory — sits at backend/logs/
LOG_DIR = Path(__file__).resolve().parent.parent.parent / "logs"
LOG_FILE = LOG_DIR / "ofsec.log"
ERROR_LOG_FILE = LOG_DIR / "ofsec_errors.log"

# Max 10 MB per log file, keep 5 backups
MAX_LOG_BYTES = 10 * 1024 * 1024
BACKUP_COUNT = 5


def setup_logging() -> None:
    """Configure structured JSON logging with file and console outputs."""

    # Ensure log directory exists
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    # ─── structlog pipeline ──────────────────────
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer() if not settings.DEBUG
            else structlog.dev.ConsoleRenderer(colors=True),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(settings.LOG_LEVEL)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # ─── Python stdlib logging (for uvicorn + file output) ───
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)

    # Clear existing handlers to avoid duplicates on reload
    root.handlers.clear()

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)
    console.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    root.addHandler(console)

    # Rotating file handler — all logs
    file_handler = RotatingFileHandler(
        str(LOG_FILE),
        maxBytes=MAX_LOG_BYTES,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        '{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
        datefmt="%Y-%m-%dT%H:%M:%S",
    ))
    root.addHandler(file_handler)

    # Separate error log file — only WARNING+
    error_handler = RotatingFileHandler(
        str(ERROR_LOG_FILE),
        maxBytes=MAX_LOG_BYTES,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
    )
    error_handler.setLevel(logging.WARNING)
    error_handler.setFormatter(logging.Formatter(
        '{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
        datefmt="%Y-%m-%dT%H:%M:%S",
    ))
    root.addHandler(error_handler)

    # Redirect uvicorn / sqlalchemy logs through our handlers
    for logger_name in ["uvicorn", "uvicorn.error", "uvicorn.access", "sqlalchemy.engine"]:
        named_logger = logging.getLogger(logger_name)
        named_logger.handlers = root.handlers[:]
        named_logger.setLevel(
            logging.DEBUG if settings.DEBUG else logging.WARNING
        )
        named_logger.propagate = False


def get_log_file_path() -> str:
    """Return path to the main log file."""
    return str(LOG_FILE)


def get_error_log_file_path() -> str:
    """Return path to the error log file."""
    return str(ERROR_LOG_FILE)
