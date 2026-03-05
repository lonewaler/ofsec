"""
OfSec V3 — FastAPI Application Entry Point
===========================================
Main application factory with middleware, routers, and lifecycle events.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import ORJSONResponse
from prometheus_client import make_asgi_app

from app.config import settings
from app.core.logging import setup_logging
from app.database import engine, async_session_factory

import structlog

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan — startup and shutdown events."""
    # ─── Startup ──────────────────────────────────
    from app.core.startup_checks import validate_environment
    validate_environment(settings.ENVIRONMENT)

    setup_logging()
    logger.info(
        "ofsec.startup",
        version="3.0.0",
        environment=settings.ENVIRONMENT,
        debug=settings.DEBUG,
    )

    # Verify DB connectivity (no schema changes — Alembic handles that)
    try:
        from sqlalchemy import text
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        logger.info("ofsec.db.connected", url=settings.DATABASE_URL.split("@")[-1])
    except Exception as e:
        logger.error("ofsec.db.connection_failed", error=str(e))

    # Start APScheduler
    from app.core.scheduler import start_scheduler, stop_scheduler
    start_scheduler()
    logger.info("ofsec.scheduler.started")

    # Seed default admin if no users exist yet
    try:
        from app.workers.db_utils import worker_db_session
        from app.repositories.user_repo import UserRepository as _UR
        async with worker_db_session() as _seed_db:
            _repo = _UR(_seed_db)
            if await _repo.count() == 0:
                await _repo.create(
                    email="admin@ofsec.io",
                    password="ChangeMe123!",
                    display_name="Admin",
                    role="admin",
                )
                logger.warning(
                    "ofsec.user.default_admin_created",
                    email="admin@ofsec.io",
                    action_required="CHANGE THIS PASSWORD IMMEDIATELY",
                )
    except Exception as _e:
        logger.error("ofsec.user.seed_failed", error=str(_e))

    yield

    # ─── Shutdown ─────────────────────────────────
    stop_scheduler()
    logger.info("ofsec.shutdown")
    await engine.dispose()


def create_app() -> FastAPI:
    """Application factory."""
    app = FastAPI(
        title="OfSec Vector Triangulum V3",
        description="Advanced Cybersecurity Operations Platform — Recon, Scanning, Attack Simulation, AI/ML Analysis, Defense",
        version="3.0.0",
        docs_url="/docs" if settings.DEBUG else None,
        redoc_url="/redoc" if settings.DEBUG else None,
        default_response_class=ORJSONResponse,
        lifespan=lifespan,
    )

    # ─── Middleware ────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    if not settings.DEBUG:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)

    # ─── Prometheus metrics ───────────────────────
    metrics_app = make_asgi_app()
    app.mount("/metrics", metrics_app)

    # ─── API Routers ──────────────────────────────
    from app.api.v1 import router as api_v1_router
    app.include_router(api_v1_router, prefix="/api/v1")

    # ─── Health Check ─────────────────────────────
    @app.get("/health", tags=["System"])
    async def health_check() -> dict:
        """System health check endpoint."""
        return {
            "status": "healthy",
            "version": "3.0.0",
            "environment": settings.ENVIRONMENT,
            "services": {
                "database": "connected",
                "redis": "connected",
                "qdrant": "connected",
            },
        }

    # ─── Frontend Static Files ────────────────────
    import pathlib
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import FileResponse

    frontend_dir = pathlib.Path(__file__).resolve().parent.parent.parent / "frontend"
    if frontend_dir.exists():
        app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

        @app.get("/", include_in_schema=False)
        async def serve_frontend():
            return FileResponse(str(frontend_dir / "index.html"))

    return app


# Application instance
app = create_app()
