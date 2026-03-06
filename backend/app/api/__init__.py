"""
OfSec V3 — API v1 Router
==========================
Versioned API router aggregating all endpoint modules.
"""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()

# ─── Import and include sub-routers ──────────
from app.api.v1.ai import router as ai_router
from app.api.v1.attack import router as attack_router
from app.api.v1.auth import router as auth_router
from app.api.v1.defense import router as defense_router
from app.api.v1.ops import router as ops_router
from app.api.v1.recon import router as recon_router
from app.api.v1.scanner import router as scanner_router

router.include_router(recon_router)
router.include_router(scanner_router)
router.include_router(auth_router)
router.include_router(attack_router)
router.include_router(ai_router)
router.include_router(defense_router)
router.include_router(ops_router)


@router.get("/status", tags=["System"])
async def api_status() -> dict:
    """API v1 status check."""
    return {
        "api_version": "v1",
        "status": "operational",
        "modules": {
            "recon": "available",
            "scanner": "available",
            "auth": "available",
            "attack": "available",
            "ai_engine": "available",
            "defense": "available",
            "dashboard": "available",
        },
    }
