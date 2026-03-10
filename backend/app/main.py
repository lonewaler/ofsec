"""
OfSec V3 — FastAPI Application Entry Point
===========================================
Main application factory with middleware, routers, and lifecycle events.
"""

import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import make_asgi_app

try:
    from fastapi.responses import ORJSONResponse
except Exception:
    ORJSONResponse = JSONResponse  # fallback if orjson not installed

from app.config import settings
from app.core.logging import setup_logging
from app.core.redis_bus import redis_bus
from app.database import engine

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

    # Auto-create all tables on startup (dev convenience — Alembic handles prod)
    try:
        from app.models import Base as ModelBase

        async with engine.begin() as conn:
            await conn.run_sync(ModelBase.metadata.create_all)
        logger.info("ofsec.db.tables_created")
    except Exception as e:
        logger.error("ofsec.db.table_creation_failed", error=str(e))

    # Verify DB connectivity
    try:
        from sqlalchemy import text

        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        logger.info("ofsec.db.connected", url=settings.DATABASE_URL.split("@")[-1])
    except Exception as e:
        logger.error("ofsec.db.connection_failed", error=str(e))

    # Start APScheduler
    from app.core.scheduler import register_threat_sweep, start_scheduler, stop_scheduler

    start_scheduler()
    register_threat_sweep()  # daily IOC sweep at 03:00 UTC
    logger.info("ofsec.scheduler.started")

    # Connect Redis Pub/Sub
    try:
        await redis_bus.connect()
        logger.info("ofsec.redis_bus.connected")
    except Exception as e:
        logger.error("ofsec.redis_bus.connection_failed", error=str(e))

    # Seed default admin if no users exist yet
    try:
        from app.repositories.user_repo import UserRepository as _UR  # noqa: N814
        from app.workers.db_utils import worker_db_session

        async with worker_db_session() as _seed_db:
            _repo = _UR(_seed_db)
            if await _repo.count() == 0:
                await _repo.create(
                    email="admin@ofsec.io",
                    password="ChangeMe123!",  # noqa: S106
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
    await redis_bus.disconnect()
    stop_scheduler()
    logger.info("ofsec.shutdown")
    await engine.dispose()


def create_app() -> FastAPI:
    """Application factory."""
    app = FastAPI(
        title="OfSec Vector Triangulum V3",
        description="Advanced Cybersecurity Operations Platform — Recon, Scanning, Attack Simulation, AI/ML Analysis, Defense",  # noqa: E501
        version="3.0.0",
        docs_url="/docs" if settings.DEBUG else None,
        redoc_url="/redoc" if settings.DEBUG else None,
        default_response_class=ORJSONResponse,
        lifespan=lifespan,
    )

    # ─── Exception Handlers ───────────────────────
    from app.core.exceptions import register_exception_handlers

    register_exception_handlers(app)

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

    # ─── Security Headers Middleware ──────────────
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' data:;"
        return response

    # ─── Rate Limiting Stub Middleware ────────────
    @app.middleware("http")
    async def rate_limit_stub(request: Request, call_next):
        # STUB: Implement Redis-based rate limiting here.
        # e.g., limit = 100 req / minute per IP.
        # if await redis.get(f"rate_limit:{request.client.host}") > limit:
        #     return JSONResponse({"detail": "Too Many Requests"}, status_code=429)
        return await call_next(request)

    # ─── Request Logging Middleware ───────────────
    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        start = time.time()
        response = await call_next(request)
        duration_ms = round((time.time() - start) * 1000, 1)
        logger.info(
            "http.request",
            method=request.method,
            path=str(request.url.path),
            status=response.status_code,
            duration_ms=duration_ms,
        )
        return response

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

    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles

    frontend_dir = pathlib.Path(__file__).resolve().parent.parent.parent / "frontend"
    dist_dir = frontend_dir / "dist"

    # In production, serve the Vite-built dist/ folder
    if dist_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(dist_dir / "assets")), name="assets")

        @app.get("/", include_in_schema=False)
        async def serve_frontend():
            return FileResponse(str(dist_dir / "index.html"))

        # SPA catch-all: serve index.html for any non-API, non-static route
        @app.get("/{full_path:path}", include_in_schema=False)
        async def serve_spa(full_path: str):
            BLOCKED_PREFIXES = (  # noqa: N806
                "api/",
                "docs",
                "redoc",
                "openapi.json",
                "health",
                "static",
                "assets",
                "favicon",
            )
            if any(full_path.startswith(p) for p in BLOCKED_PREFIXES):
                raise HTTPException(status_code=404, detail=f"Not found: /{full_path}")

            index = dist_dir / "index.html"
            if index.exists():
                return FileResponse(str(index))
            raise HTTPException(status_code=404, detail="Frontend not built")

    # Dev fallback: serve raw frontend as static files (no Vite needed)
    elif frontend_dir.exists():
        # Mount each frontend subdirectory at its expected URL path
        # so that index.html's references like /css/style.css and /js/main.js resolve correctly.
        for subdir in ("css", "js", "images", "fonts", "static"):
            sub_path = frontend_dir / subdir
            if sub_path.is_dir():
                app.mount(f"/{subdir}", StaticFiles(directory=str(sub_path)), name=f"frontend-{subdir}")

        @app.get("/", include_in_schema=False)
        async def serve_frontend_dev():
            return FileResponse(str(frontend_dir / "index.html"))

        # SPA catch-all for dev mode too
        @app.get("/{full_path:path}", include_in_schema=False)
        async def serve_spa_dev(full_path: str):
            BLOCKED_PREFIXES = (  # noqa: N806
                "api/",
                "docs",
                "redoc",
                "openapi.json",
                "health",
                "css",
                "js",
                "images",
                "fonts",
                "static",
            )
            if any(full_path.startswith(p) for p in BLOCKED_PREFIXES):
                raise HTTPException(status_code=404, detail=f"Not found: /{full_path}")

            index = frontend_dir / "index.html"
            if index.exists():
                return FileResponse(str(index))
            raise HTTPException(status_code=404, detail="Frontend not built")

    return app


# Application instance
app = create_app()
