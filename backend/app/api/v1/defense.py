"""
OfSec V3 — Defense & Operations API Endpoints
================================================
REST API for defense, incident response, SIEM, and operations (#66–82).
"""

from fastapi import APIRouter, HTTPException

from app.api.deps import CurrentUser
from app.schemas import SuccessResponse
from app.services.defense.orchestrator import DefenseOrchestrator
from app.workers.defense_tasks import (
    process_security_event,
    run_health_checks,
    sweep_for_iocs,
    run_correlation,
)

import structlog

logger = structlog.get_logger()

router = APIRouter(prefix="/defense", tags=["Defense & Operations"])


# ─── Module listing ──────────────────────────

@router.get("/modules")
async def list_defense_modules(user: CurrentUser) -> dict:
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
async def get_security_posture(user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return orchestrator.get_security_posture()


# ─── Events Pipeline ────────────────────────

@router.post("/event")
async def ingest_security_event(event: dict, user: CurrentUser = None) -> SuccessResponse:
    task = await process_security_event.kiq(event)
    return SuccessResponse(message="Event queued", data={"task_id": str(task.task_id)})


@router.post("/event/instant")
async def process_event_instant(event: dict, user: CurrentUser = None) -> dict:
    orchestrator = DefenseOrchestrator()
    return await orchestrator.process_security_event(event)


# ─── Incident Response ──────────────────────

@router.get("/playbooks")
async def list_playbooks(user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return {"playbooks": orchestrator.playbooks.list_playbooks()}


@router.post("/incident")
async def start_incident(
    playbook_id: str, description: str, assignee: str = "",
    user: CurrentUser = None,
) -> dict:
    orchestrator = DefenseOrchestrator()
    return orchestrator.playbooks.start_incident(playbook_id, description, assignee)


@router.post("/incident/{incident_id}/advance")
async def advance_incident(incident_id: str, notes: str = "", user: CurrentUser = None) -> dict:
    orchestrator = DefenseOrchestrator()
    return orchestrator.playbooks.advance_step(incident_id, notes)


@router.get("/incident/{incident_id}")
async def get_incident(incident_id: str, user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return orchestrator.playbooks.get_incident(incident_id)


# ─── Alert Triage ────────────────────────────

@router.post("/alert")
async def triage_alert(alert: dict, user: CurrentUser = None) -> dict:
    orchestrator = DefenseOrchestrator()
    return orchestrator.triage.ingest_alert(alert)


@router.get("/alerts")
async def get_alert_queue(limit: int = 50, user: CurrentUser = None) -> dict:
    orchestrator = DefenseOrchestrator()
    return {"alerts": orchestrator.triage.get_queue(limit)}


# ─── SIEM ────────────────────────────────────

@router.post("/logs/ingest")
async def ingest_logs(logs: list[str], source: str = "app", log_format: str = "syslog", user: CurrentUser = None) -> dict:
    orchestrator = DefenseOrchestrator()
    return orchestrator.log_aggregator.ingest_batch(logs, source, log_format)


@router.get("/logs/search")
async def search_logs(query: str, limit: int = 100, user: CurrentUser = None) -> dict:
    orchestrator = DefenseOrchestrator()
    return {"results": orchestrator.log_aggregator.search(query, limit)}


@router.get("/correlation/rules")
async def list_correlation_rules(user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return {"rules": orchestrator.correlation.list_rules()}


@router.get("/correlation/alerts")
async def get_correlation_alerts(limit: int = 50, user: CurrentUser = None) -> dict:
    orchestrator = DefenseOrchestrator()
    return {"alerts": orchestrator.correlation.get_triggered(limit)}


# ─── Threat Hunting ──────────────────────────

@router.get("/hunting/hypotheses")
async def list_hunt_hypotheses(user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return {"hypotheses": orchestrator.hunting.list_hypotheses()}


@router.post("/hunting/start")
async def start_hunt(hypothesis_id: str, hunter: str = "analyst", user: CurrentUser = None) -> dict:
    orchestrator = DefenseOrchestrator()
    return orchestrator.hunting.start_hunt(hypothesis_id, hunter)


@router.post("/ioc/sweep")
async def ioc_sweep(logs: list[str], iocs: dict, user: CurrentUser = None) -> dict:
    orchestrator = DefenseOrchestrator()
    return await orchestrator.sweep_for_iocs(logs, iocs)


@router.post("/dga/check")
async def check_dga(domain: str, user: CurrentUser = None) -> dict:
    return DefenseOrchestrator().behavioral.detect_dga(domain)


# ─── Remediation ─────────────────────────────

@router.post("/firewall/block")
async def block_ip(ip: str, reason: str, duration_hours: int = 24, user: CurrentUser = None) -> dict:
    orchestrator = DefenseOrchestrator()
    return orchestrator.firewall.block_ip(ip, reason, duration_hours)


@router.get("/firewall/rules")
async def get_firewall_rules(user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return {"rules": orchestrator.firewall.list_rules()}


@router.get("/firewall/export/iptables")
async def export_iptables(user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return {"commands": orchestrator.firewall.generate_iptables()}


@router.post("/quarantine")
async def quarantine_host(host: str, reason: str, user: CurrentUser = None) -> dict:
    orchestrator = DefenseOrchestrator()
    return orchestrator.quarantine.quarantine_host(host, reason)


@router.get("/quarantine")
async def list_quarantined(user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return {"quarantined": orchestrator.quarantine.list_quarantined()}


# ─── Monitoring ──────────────────────────────

@router.post("/health/check")
async def health_check(endpoints: dict, user: CurrentUser = None) -> dict:
    orchestrator = DefenseOrchestrator()
    return await orchestrator.run_health_check(endpoints)


@router.get("/compliance/frameworks")
async def list_compliance_frameworks(user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return {"frameworks": orchestrator.compliance.list_frameworks()}


@router.post("/compliance/drift")
async def check_compliance_drift(
    framework: str, current_statuses: dict, user: CurrentUser = None,
) -> dict:
    orchestrator = DefenseOrchestrator()
    return orchestrator.compliance.check_drift(framework, current_statuses)


@router.get("/sla/report")
async def sla_report(user: CurrentUser) -> dict:
    orchestrator = DefenseOrchestrator()
    return orchestrator.sla.get_compliance_report()
