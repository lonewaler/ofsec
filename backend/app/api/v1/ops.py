"""
OfSec V3 — Dashboard & Operations API Endpoints
==================================================
REST API for dashboard, reports, scheduling, and administration.
"""

from __future__ import annotations
import secrets as _sec

import structlog
import fastapi
from fastapi import APIRouter, HTTPException

from app.api.deps import CurrentUser
from app.core.scheduler import add_scan_job, list_scheduled_jobs, remove_scan_job
from app.services.ops.orchestrator import OpsOrchestrator

logger = structlog.get_logger()

router = APIRouter(prefix="/ops", tags=["Dashboard & Operations"])

from app.config import settings as _settings
from app.core.notifier import send_test_alert

# ─── Platform Status ────────────────────────

@router.get("/status")
async def platform_status(*, user: CurrentUser) -> dict:
    return OpsOrchestrator().get_platform_status()


# ─── Dashboard ──────────────────────────────

@router.get("/dashboard")
async def dashboard_overview(*, user: CurrentUser) -> dict:
    return OpsOrchestrator().dashboard.get_overview()


@router.get("/dashboard/trend/{metric}")
async def dashboard_trend(*, metric: str, limit: int = 50, user: CurrentUser) -> dict:
    return OpsOrchestrator().dashboard.get_trend(metric, limit)


# ─── Reports ─────────────────────────────────

@router.get("/reports/types")
async def list_report_types(*, user: CurrentUser) -> dict:
    return {"types": OpsOrchestrator().reports.list_types()}


@router.post("/reports/generate")
async def generate_report(*, report_type: str, scan_data: dict, user: CurrentUser) -> dict:
    return OpsOrchestrator().reports.generate(report_type, scan_data)


# ─── Notifications ──────────────────────────

@router.post("/notifications/send")
async def send_notification(*, 
    title: str, message: str, severity: str = "info",
    channels: list[str] | None = None, user: CurrentUser,
) -> dict:
    return OpsOrchestrator().notifications.send(title, message, severity, channels)


@router.get("/notifications")
async def notification_history(*, limit: int = 50, user: CurrentUser) -> dict:
    return {"notifications": OpsOrchestrator().notifications.get_history(limit)}


@router.get("/notifications/failed")
async def list_failed_notifications(*, user: CurrentUser) -> dict:
    import json
    from pathlib import Path
    
    dlq_dir = Path("/tmp/ofsec_dlq")
    failed = []
    if dlq_dir.exists():
        for file in dlq_dir.glob("dlq_*.json"):
            try:
                with open(file, "r") as f:
                    data = json.load(f)
                    data["id"] = file.name
                    failed.append(data)
            except Exception:
                pass
    return {"failed": failed, "count": len(failed)}


@router.post("/notifications/retry")
async def retry_failed_notifications(*, user: CurrentUser) -> dict:
    import httpx
    import json
    from pathlib import Path
    import asyncio
    
    dlq_dir = Path("/tmp/ofsec_dlq")
    if not dlq_dir.exists():
        return {"retried": 0, "failed": 0, "message": "No DLQ directory found"}
        
    retried_count = 0
    failed_count = 0
    files = list(dlq_dir.glob("dlq_*.json"))
    
    async with httpx.AsyncClient(timeout=15.0) as client:
        for file in files:
            try:
                with open(file, "r") as f:
                    data = json.load(f)
                
                url = data.get("target_url")
                payload = data.get("payload")
                
                resp = await client.post(url, json=payload, headers={"Content-Type": "application/json"})
                resp.raise_for_status()
                
                # If successful, delete the file
                file.unlink()
                retried_count += 1
            except Exception as e:
                logger.error("ops.dlq.retry_failed", file=file.name, error=str(e))
                failed_count += 1
                
    return {
        "retried": retried_count,
        "still_failing": failed_count,
        "message": f"Successfully retried {retried_count} notifications"
    }


# ─── Scheduler ──────────────────────────────

@router.post("/jobs")
async def create_job(*, 
    name: str, job_type: str, schedule: str,
    target: str = "", config: dict | None = None, user: CurrentUser,
) -> dict:
    orchestrator = OpsOrchestrator()
    result = orchestrator.scheduler.create_job(name, job_type, schedule, target, config)
    orchestrator.audit.log("create_job", "system", name)
    return result


@router.get("/jobs")
async def list_jobs(*, status: str | None = None, user: CurrentUser) -> dict:
    return {"jobs": OpsOrchestrator().scheduler.list_jobs(status)}


@router.delete("/jobs/{job_id}")
async def delete_job(*, job_id: str, user: CurrentUser) -> dict:
    return OpsOrchestrator().scheduler.delete_job(job_id)


# ─── Audit Log ──────────────────────────────

@router.get("/audit")
async def search_audit(*, 
    username: str | None = None, action: str | None = None,
    limit: int = 100, user: CurrentUser,
) -> dict:
    return {"entries": OpsOrchestrator().audit.search(username, action, limit=limit)}


@router.get("/audit/user/{username}")
async def user_activity(*, username: str, user: CurrentUser) -> dict:
    return OpsOrchestrator().audit.get_user_activity(username)


# ─── Assets ─────────────────────────────────

@router.post("/assets")
async def add_asset(*, 
    name: str, asset_type: str, address: str,
    criticality: str = "medium", tags: list[str] | None = None,
    user: CurrentUser,
) -> dict:
    return OpsOrchestrator().assets.add_asset(name, asset_type, address, tags, criticality)


@router.get("/assets")
async def list_assets(*, 
    asset_type: str | None = None, criticality: str | None = None,
    user: CurrentUser,
) -> dict:
    return {"assets": OpsOrchestrator().assets.list_assets(asset_type, criticality)}


@router.get("/assets/risk")
async def asset_risk_summary(*, user: CurrentUser) -> dict:
    return OpsOrchestrator().assets.get_risk_summary()


# ─── Teams ──────────────────────────────────

@router.get("/team/roles")
async def list_roles(*, user: CurrentUser) -> dict:
    return {"roles": OpsOrchestrator().teams.list_roles()}


@router.post("/team/members")
async def add_team_member(*, 
    username: str, role: str, email: str = "", user: CurrentUser,
) -> dict:
    return OpsOrchestrator().teams.add_member(username, role, email)


@router.get("/team/members")
async def list_members(*, user: CurrentUser) -> dict:
    return {"members": OpsOrchestrator().teams.list_members()}


# ─── API Keys ───────────────────────────────

@router.post("/apikeys")
async def create_api_key(*, 
    name: str, role: str = "analyst", scopes: list[str] | None = None,
    user: CurrentUser,
) -> dict:
    return OpsOrchestrator().api_keys.create_key(name, role, scopes)


@router.get("/apikeys")
async def list_api_keys(*, user: CurrentUser) -> dict:
    return {"keys": OpsOrchestrator().api_keys.list_keys()}


@router.delete("/apikeys/{key_id}")
async def revoke_api_key(*, key_id: str, user: CurrentUser) -> dict:
    return OpsOrchestrator().api_keys.revoke_key(key_id)


# ─── Config ─────────────────────────────────

@router.get("/config")
async def get_config(*, user: CurrentUser) -> dict:
    return OpsOrchestrator().config.get_all()


@router.put("/config")
async def update_config(*, key: str, value: str, user: CurrentUser) -> dict:
    return OpsOrchestrator().config.set(key, value)


# ─── Scan Queue ─────────────────────────────────────────────────────

@router.post("/queue/submit")
async def submit_scan_queue(*, 
    targets: list[str],
    scan_type: str = "recon",
    modules: list[str] | None = None,
    priority: str = "normal",
    user: CurrentUser,
) -> dict:
    """
    Submit a batch of targets to the scan queue.
    Each target becomes one Taskiq task + one JobScheduler record.
    Returns list of job IDs for status tracking.
    """
    from app.workers.recon_tasks import run_full_recon as recon_task
    from app.workers.scan_tasks import run_full_vulnerability_scan as vuln_task

    if not targets:
        raise HTTPException(status_code=400, detail="targets list cannot be empty")
    if len(targets) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 targets per batch")

    orchestrator = OpsOrchestrator()
    submitted = []

    for target in targets:
        try:
            if scan_type == "vuln":
                task = await vuln_task.kiq(target, modules)
            else:
                task = await recon_task.kiq(target, modules)
            task_id = str(task.task_id) if hasattr(task, 'task_id') else str(id(task))
        except Exception:
            import secrets
            task_id = secrets.token_hex(8)

        job = orchestrator.scheduler.create_job(
            name=f"{scan_type.upper()} -- {target}",
            job_type="scan_queue",
            schedule="once",
            target=target,
            config={
                "scan_type": scan_type,
                "modules": modules or [],
                "task_id": task_id,
                "priority": priority,
            },
        )
        job["status"] = "running"
        job["task_id"] = task_id
        submitted.append({
            "job_id": job.get("id", task_id),
            "task_id": task_id,
            "target": target,
            "scan_type": scan_type,
            "status": "queued",
        })

    logger.info("ops.queue.submitted", count=len(submitted), scan_type=scan_type)
    return {
        "submitted": len(submitted),
        "jobs": submitted,
        "message": f"{len(submitted)} scan(s) queued successfully",
    }


@router.get("/queue/status")
async def get_queue_status(*, user: CurrentUser) -> dict:
    """Get current scan queue -- all jobs of type scan_queue."""
    orchestrator = OpsOrchestrator()
    all_jobs = orchestrator.scheduler.list_jobs()
    queue_jobs = [j for j in all_jobs if j.get("type") == "scan_queue"]

    counts = {"running": 0, "completed": 0, "failed": 0, "active": 0}
    for j in queue_jobs:
        s = j.get("status", "active")
        counts[s] = counts.get(s, 0) + 1

    return {
        "queue_length": len(queue_jobs),
        "status_counts": counts,
        "jobs": sorted(queue_jobs, key=lambda j: j.get("created_at", ""), reverse=True)[:100],
    }


@router.post("/queue/{job_id}/cancel")
async def cancel_queued_job(*, job_id: str, user: CurrentUser) -> dict:
    """Cancel a queued scan job."""
    orchestrator = OpsOrchestrator()
    result = orchestrator.scheduler.delete_job(job_id)
    if isinstance(result, dict) and "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return {"cancelled": job_id}


# ─── Scheduled Scans (APScheduler-backed) ────────────────────────────

@router.post("/schedules")
async def create_schedule(*, 
    target: str,
    scan_type: str = "recon",
    schedule_type: str = "cron",
    schedule_value: str = "0 2 * * *",
    modules: list[str] | None = None,
    name: str = "",
    user: CurrentUser,
) -> dict:
    """
    Create a recurring scan schedule.

    Examples:
      schedule_type=cron,     schedule_value="0 2 * * *"    → daily 02:00 UTC
      schedule_type=cron,     schedule_value="0 */6 * * *"  → every 6 hours
      schedule_type=interval, schedule_value="3600"          → every hour
    """
    job_id = f"SCHED-{_sec.token_hex(4).upper()}"
    try:
        info = add_scan_job(
            job_id=job_id,
            target=target,
            scan_type=scan_type,
            schedule_type=schedule_type,
            schedule_value=schedule_value,
            modules=modules,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    logger.info("ops.schedule.created", job_id=job_id, target=target)
    return info


@router.get("/schedules")
async def list_schedules(*, user: CurrentUser) -> dict:
    jobs = list_scheduled_jobs()
    return {"schedules": jobs, "total": len(jobs)}


@router.delete("/schedules/{job_id}")
async def delete_schedule(*, job_id: str, user: CurrentUser) -> dict:
    if not remove_scan_job(job_id):
        raise HTTPException(status_code=404, detail=f"Schedule {job_id} not found")
    return {"deleted": job_id}


# ─── Notification Test & Config ─────────────────────────────────────

@router.post("/notifications/test")
async def test_notification(*, user: CurrentUser) -> dict:
    """Send a test alert to all configured channels."""
    result = await send_test_alert()
    if not result["channels"]:
        return {
            "status": "no_channels",
            "message": "No channels configured. Set ALERT_EMAIL_ENABLED=true or "
                       "ALERT_WEBHOOK_ENABLED=true in your .env file.",
        }
    return {"status": "sent", "channels": result["channels"]}


@router.get("/notifications/config")
async def notification_config(*, user: CurrentUser) -> dict:
    """Return current notification channel configuration (no secrets)."""
    return {
        "email": {
            "enabled": _settings.ALERT_EMAIL_ENABLED,
            "smtp_host": _settings.ALERT_EMAIL_SMTP_HOST,
            "smtp_port": _settings.ALERT_EMAIL_SMTP_PORT,
            "from": _settings.ALERT_EMAIL_FROM,
            "to": _settings.ALERT_EMAIL_TO,
            "configured": bool(_settings.ALERT_EMAIL_USERNAME and _settings.ALERT_EMAIL_TO),
        },
        "webhook": {
            "enabled": _settings.ALERT_WEBHOOK_ENABLED,
            "url_configured": bool(_settings.ALERT_WEBHOOK_URL),
            "url_2_configured": bool(_settings.ALERT_WEBHOOK_URL_2),
            "url_preview": _settings.ALERT_WEBHOOK_URL[:40] + "..."
                           if len(_settings.ALERT_WEBHOOK_URL) > 40
                           else _settings.ALERT_WEBHOOK_URL,
        },
    }

