"""
OfSec V3 — Defense & Operations API Endpoints
================================================
REST API for defense, incident response, SIEM, and operations (#66–82).
"""

from __future__ import annotations
import structlog
import fastapi
from fastapi import APIRouter

from app.api.deps import CurrentUser, DbSession
from app.repositories import AlertRepository, IOCRepository
from app.schemas import SuccessResponse
from app.services.defense.orchestrator import DefenseOrchestrator
from app.workers.defense_tasks import (
    process_security_event,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/defense", tags=["Defense & Operations"])


# ─── Module listing ──────────────────────────

@router.get("/modules")
async def list_defense_modules(*, user: CurrentUser) -> dict:
    return {
        "modules": [
            {"id": "playbooks", "name": "#66 Incident Response Playbooks", "category": "incident"},
            {"id": "triage", "name": "#67 Alert Triage Engine", "category": "incident"},
            {"id": "evidence", "name": "#68 Evidence Collector", "category": "incident"},
            {"id": "log_aggregator", "name": "#69 Log Aggregator", "category": "siem"},
            {"id": "correlation", "name": "#70 Correlation Engine", "category": "siem"},
            {"id": "dashboard_data", "name": "#71 Security Dashboard", "category": "siem"},
            {"id": "hunting", "name": "#72 Threat Hunting", "category": "hunting"},
            {"id": "ioc_sweep", "name": "#73 IOC Sweep", "category": "hunting"},
            {"id": "behavioral", "name": "#74 Behavioral Hunting", "category": "hunting"},
            {"id": "firewall", "name": "#75 Firewall Manager", "category": "remediation"},
            {"id": "patch_mgr", "name": "#76 Patch Manager", "category": "remediation"},
            {"id": "quarantine", "name": "#77 Quarantine Manager", "category": "remediation"},
            {"id": "health", "name": "#78-80 Health Monitor", "category": "monitoring"},
            {"id": "compliance", "name": "#81 Compliance Monitor", "category": "monitoring"},
            {"id": "sla", "name": "#82 SLA Tracker", "category": "monitoring"},
        ],
        "total": 15,
    }


# ─── Security Posture ───────────────────────

@router.get("/posture")
async def get_security_posture(*, user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return orchestrator.get_security_posture()


# ─── Events Pipeline ────────────────────────

@router.post("/event")
async def ingest_security_event(*, event: dict, user: CurrentUser) -> SuccessResponse:
    task = await process_security_event.kiq(event)
    return SuccessResponse(message="Event queued", data={"task_id": str(task.task_id)})


@router.post("/event/instant")
async def process_event_instant(*, event: dict, user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return await orchestrator.process_security_event(event)


# ─── Incident Response ──────────────────────

@router.get("/playbooks")
async def list_playbooks(*, user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return {"playbooks": orchestrator.playbooks.list_playbooks()}


@router.post("/incident")
async def start_incident(*, 
    playbook_id: str, description: str, assignee: str = "",
    user: CurrentUser,
) -> dict:
    orchestrator = DefenseOrchestrator()
    return orchestrator.playbooks.start_incident(playbook_id, description, assignee)


@router.post("/incident/{incident_id}/advance")
async def advance_incident(*, incident_id: str, notes: str = "", user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return orchestrator.playbooks.advance_step(incident_id, notes)


@router.get("/incident/{incident_id}")
async def get_incident(*, incident_id: str, user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return orchestrator.playbooks.get_incident(incident_id)


# ─── Alert Triage ────────────────────────────

@router.post("/alert")
async def triage_alert(*, alert: dict, db: DbSession, user: CurrentUser) -> dict:
    """Ingest alert — persists to DB and runs in-memory triage."""
    repo = AlertRepository(db)

    # Persist
    db_alert = await repo.create_alert(
        severity=alert.get("severity", "medium"),
        source=alert.get("source", "manual"),
        title=alert.get("title", "Alert"),
        message=alert.get("message", ""),
        metadata=alert,
    )

    # Also run through triage engine
    orchestrator = DefenseOrchestrator()
    triage_result = orchestrator.triage.ingest_alert(alert)
    triage_result["db_id"] = db_alert.id
    return triage_result


@router.get("/alerts")
async def get_alert_queue(*, 
    db: DbSession,
    limit: int = 50,
    user: CurrentUser,
) -> dict:
    """Get alerts — DB-persisted alerts merged with live in-memory triage queue."""
    repo = AlertRepository(db)
    db_items, total = await repo.list_alerts(limit=limit)

    db_alerts = [
        {
            "id": a.id,
            "severity": a.severity,
            "source": a.source,
            "title": a.title,
            "message": a.message,
            "status": a.status,
            "timestamp": a.created_at.isoformat() if a.created_at else None,
        }
        for a in db_items
    ]

    # Also include in-memory triage queue (not yet persisted)
    orchestrator = DefenseOrchestrator()
    live_alerts = orchestrator.triage.get_queue(limit)

    # Merge: DB alerts first (most recent), then live unique ones
    seen_titles = {a["title"] for a in db_alerts}
    merged = db_alerts + [a for a in live_alerts if a.get("title") not in seen_titles]

    return {"alerts": merged[:limit], "total": len(merged)}


# ─── IOC Tracking ──────────────────────────────

@router.post("/ioc/track")
async def track_ioc(*, 
    ioc_value: str,
    ioc_type: str = "ip",
    source: str = "manual",
    db: DbSession,
    user: CurrentUser,
) -> dict:
    """Track and persist an IOC to the database."""
    repo = IOCRepository(db)
    ioc = await repo.upsert_ioc(
        ioc_type=ioc_type,
        value=ioc_value,
        source=source,
        confidence=0.7,
    )
    return {
        "id": ioc.id,
        "ioc_type": ioc.ioc_type,
        "value": ioc.value,
        "source": ioc.source,
        "confidence": ioc.confidence,
        "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
        "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
    }


@router.get("/ioc/history")
async def list_ioc_history(*, 
    ioc_type: str | None = None,
    limit: int = 50,
    db: DbSession,
    user: CurrentUser,
) -> dict:
    """List tracked IOCs from the database."""
    repo = IOCRepository(db)
    items, total = await repo.list_iocs(ioc_type=ioc_type, limit=limit)
    return {
        "items": [
            {
                "id": i.id,
                "ioc_type": i.ioc_type,
                "value": i.value,
                "source": i.source,
                "confidence": i.confidence,
                "tags": i.tags,
                "first_seen": i.first_seen.isoformat() if i.first_seen else None,
                "last_seen": i.last_seen.isoformat() if i.last_seen else None,
            }
            for i in items
        ],
        "total": total,
    }


# ─── SIEM ────────────────────────────────────

@router.post("/logs/ingest")
async def ingest_logs(*, logs: list[str], source: str = "app", log_format: str = "syslog", user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return orchestrator.log_aggregator.ingest_batch(logs, source, log_format)


@router.get("/logs/search")
async def search_logs(*, query: str, limit: int = 100, user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return {"results": orchestrator.log_aggregator.search(query, limit)}


@router.get("/correlation/rules")
async def list_correlation_rules(*, user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return {"rules": orchestrator.correlation.list_rules()}


@router.get("/correlation/alerts")
async def get_correlation_alerts(*, limit: int = 50, user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return {"alerts": orchestrator.correlation.get_triggered(limit)}


# ─── Threat Hunting ──────────────────────────

@router.get("/hunting/hypotheses")
async def list_hunt_hypotheses(*, user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return {"hypotheses": orchestrator.hunting.list_hypotheses()}


@router.post("/hunting/start")
async def start_hunt(*, hypothesis_id: str, hunter: str = "analyst", user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return orchestrator.hunting.start_hunt(hypothesis_id, hunter)


@router.post("/ioc/sweep")
async def ioc_sweep(*, logs: list[str], iocs: dict, user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return await orchestrator.sweep_for_iocs(logs, iocs)


@router.post("/dga/check")
async def check_dga(*, domain: str, user: CurrentUser) -> dict:
    return DefenseOrchestrator().behavioral.detect_dga(domain)


# ─── Remediation ─────────────────────────────

@router.post("/firewall/block")
async def block_ip(*, ip: str, reason: str, duration_hours: int = 24, user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return orchestrator.firewall.block_ip(ip, reason, duration_hours)


@router.get("/firewall/rules")
async def get_firewall_rules(*, user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return {"rules": orchestrator.firewall.list_rules()}


@router.get("/firewall/export/iptables")
async def export_iptables(*, user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return {"commands": orchestrator.firewall.generate_iptables()}


@router.post("/quarantine")
async def quarantine_host(*, host: str, reason: str, user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return orchestrator.quarantine.quarantine_host(host, reason)


@router.get("/quarantine")
async def list_quarantined(*, user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return {"quarantined": orchestrator.quarantine.list_quarantined()}


# ─── Monitoring ──────────────────────────────

@router.post("/health/check")
async def health_check(*, endpoints: dict, user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return await orchestrator.run_health_check(endpoints)


@router.get("/compliance/frameworks")
async def list_compliance_frameworks(*, user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return {"frameworks": orchestrator.compliance.list_frameworks()}


@router.post("/compliance/drift")
async def check_compliance_drift(*, 
    framework: str, current_statuses: dict, user: CurrentUser,
) -> dict:
    orchestrator = DefenseOrchestrator()
    return orchestrator.compliance.check_drift(framework, current_statuses)


@router.get("/sla/report")
async def sla_report(*, user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return orchestrator.sla.get_compliance_report()


# ─── Threat Intelligence Auto-Ingestion ──────

@router.post("/intel/sweep")
async def trigger_intel_sweep(*, user: CurrentUser) -> dict:
    """
    Manually trigger a threat intelligence IOC sweep.
    Runs OTX + AbuseIPDB + VirusTotal ingestion immediately.
    The same sweep also runs automatically at 03:00 UTC daily.
    """
    from app.workers.intel_tasks import run_threat_intel_sweep
    task = await run_threat_intel_sweep.kiq()
    logger.info("api.defense.intel_sweep.triggered")
    return {
        "status": "queued",
        "task_id": str(task.task_id),
        "message": "IOC sweep running in background — check /api/v1/defense/ioc/history for results",
    }


@router.get("/intel/sweep/status")
async def intel_sweep_status(*, user: CurrentUser) -> dict:
    """Returns info about the scheduled daily sweep."""
    from app.core.scheduler import get_scheduler
    sched = get_scheduler()
    job = sched.get_job("__threat_intel_sweep__")
    return {
        "schedule": "daily at 03:00 UTC",
        "next_run": job.next_run_time.isoformat() if job and job.next_run_time else None,
        "status": "active" if job else "not_registered",
    }

