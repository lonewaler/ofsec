"""
OfSec V3 — Dashboard & Operations API Endpoints
==================================================
REST API for dashboard, reports, scheduling, and administration (#83–100).
"""

from fastapi import APIRouter, HTTPException

from app.api.deps import CurrentUser
from app.schemas import SuccessResponse
from app.services.ops.orchestrator import OpsOrchestrator

import structlog

logger = structlog.get_logger()

router = APIRouter(prefix="/ops", tags=["Dashboard & Operations"])


# ─── Platform Status ────────────────────────

@router.get("/status")
async def platform_status(user: CurrentUser) -> dict:
    return OpsOrchestrator().get_platform_status()


# ─── Dashboard ──────────────────────────────

@router.get("/dashboard")
async def dashboard_overview(user: CurrentUser) -> dict:
    return OpsOrchestrator().dashboard.get_overview()


@router.get("/dashboard/trend/{metric}")
async def dashboard_trend(metric: str, limit: int = 50, user: CurrentUser = None) -> dict:
    return OpsOrchestrator().dashboard.get_trend(metric, limit)


# ─── Reports ─────────────────────────────────

@router.get("/reports/types")
async def list_report_types(user: CurrentUser) -> dict:
    return {"types": OpsOrchestrator().reports.list_types()}


@router.post("/reports/generate")
async def generate_report(report_type: str, scan_data: dict, user: CurrentUser = None) -> dict:
    return OpsOrchestrator().reports.generate(report_type, scan_data)


# ─── Notifications ──────────────────────────

@router.post("/notifications/send")
async def send_notification(
    title: str, message: str, severity: str = "info",
    channels: list[str] | None = None, user: CurrentUser = None,
) -> dict:
    return OpsOrchestrator().notifications.send(title, message, severity, channels)


@router.get("/notifications")
async def notification_history(limit: int = 50, user: CurrentUser = None) -> dict:
    return {"notifications": OpsOrchestrator().notifications.get_history(limit)}


# ─── Scheduler ──────────────────────────────

@router.post("/jobs")
async def create_job(
    name: str, job_type: str, schedule: str,
    target: str = "", config: dict | None = None, user: CurrentUser = None,
) -> dict:
    orchestrator = OpsOrchestrator()
    result = orchestrator.scheduler.create_job(name, job_type, schedule, target, config)
    orchestrator.audit.log("create_job", "system", name)
    return result


@router.get("/jobs")
async def list_jobs(status: str | None = None, user: CurrentUser = None) -> dict:
    return {"jobs": OpsOrchestrator().scheduler.list_jobs(status)}


@router.delete("/jobs/{job_id}")
async def delete_job(job_id: str, user: CurrentUser = None) -> dict:
    return OpsOrchestrator().scheduler.delete_job(job_id)


# ─── Audit Log ──────────────────────────────

@router.get("/audit")
async def search_audit(
    username: str | None = None, action: str | None = None,
    limit: int = 100, user: CurrentUser = None,
) -> dict:
    return {"entries": OpsOrchestrator().audit.search(username, action, limit=limit)}


@router.get("/audit/user/{username}")
async def user_activity(username: str, user: CurrentUser = None) -> dict:
    return OpsOrchestrator().audit.get_user_activity(username)


# ─── Assets ─────────────────────────────────

@router.post("/assets")
async def add_asset(
    name: str, asset_type: str, address: str,
    criticality: str = "medium", tags: list[str] | None = None,
    user: CurrentUser = None,
) -> dict:
    return OpsOrchestrator().assets.add_asset(name, asset_type, address, tags, criticality)


@router.get("/assets")
async def list_assets(
    asset_type: str | None = None, criticality: str | None = None,
    user: CurrentUser = None,
) -> dict:
    return {"assets": OpsOrchestrator().assets.list_assets(asset_type, criticality)}


@router.get("/assets/risk")
async def asset_risk_summary(user: CurrentUser) -> dict:
    return OpsOrchestrator().assets.get_risk_summary()


# ─── Teams ──────────────────────────────────

@router.get("/team/roles")
async def list_roles(user: CurrentUser) -> dict:
    return {"roles": OpsOrchestrator().teams.list_roles()}


@router.post("/team/members")
async def add_team_member(
    username: str, role: str, email: str = "", user: CurrentUser = None,
) -> dict:
    return OpsOrchestrator().teams.add_member(username, role, email)


@router.get("/team/members")
async def list_members(user: CurrentUser) -> dict:
    return {"members": OpsOrchestrator().teams.list_members()}


# ─── API Keys ───────────────────────────────

@router.post("/apikeys")
async def create_api_key(
    name: str, role: str = "analyst", scopes: list[str] | None = None,
    user: CurrentUser = None,
) -> dict:
    return OpsOrchestrator().api_keys.create_key(name, role, scopes)


@router.get("/apikeys")
async def list_api_keys(user: CurrentUser) -> dict:
    return {"keys": OpsOrchestrator().api_keys.list_keys()}


@router.delete("/apikeys/{key_id}")
async def revoke_api_key(key_id: str, user: CurrentUser = None) -> dict:
    return OpsOrchestrator().api_keys.revoke_key(key_id)


# ─── Config ─────────────────────────────────

@router.get("/config")
async def get_config(user: CurrentUser) -> dict:
    return OpsOrchestrator().config.get_all()


@router.put("/config")
async def update_config(key: str, value: str, user: CurrentUser = None) -> dict:
    return OpsOrchestrator().config.set(key, value)
