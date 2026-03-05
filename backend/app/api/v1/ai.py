"""
OfSec V3 — AI/ML Engine API Endpoints
========================================
REST API for AI-powered security intelligence (Upgrades #46–65).
"""

import structlog
from fastapi import APIRouter

from app.api.deps import CurrentUser
from app.schemas import SuccessResponse
from app.services.ai.orchestrator import AIOrchestrator
from app.workers.ai_tasks import (
    analyze_scan_results,
    generate_ai_report,
    monitor_darkweb,
    parse_threat_report,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/ai", tags=["AI/ML Engine"])


# ─── Module listing ─────────────────────────

@router.get("/modules")
async def list_ai_modules(user: CurrentUser) -> dict:
    return {
        "modules": [
            {"id": "network_anomaly", "name": "#46 Network Anomaly Detector", "category": "anomaly"},
            {"id": "behavioral_anomaly", "name": "#47 Behavioral Anomaly Detector", "category": "anomaly"},
            {"id": "log_anomaly", "name": "#48 Log Anomaly Detector", "category": "anomaly"},
            {"id": "threat_parser", "name": "#49 Threat Report Parser", "category": "nlp"},
            {"id": "cve_analyzer", "name": "#50 CVE Analyzer", "category": "nlp"},
            {"id": "darkweb_monitor", "name": "#51 Dark Web Monitor", "category": "nlp"},
            {"id": "attack_predictor", "name": "#52 Attack Prediction", "category": "predictive"},
            {"id": "vuln_forecaster", "name": "#53 Vulnerability Forecaster", "category": "predictive"},
            {"id": "risk_scorer", "name": "#54 ML Risk Scorer", "category": "predictive"},
            {"id": "feedback", "name": "#55 Feedback Loop", "category": "learning"},
            {"id": "adaptive", "name": "#56 Adaptive Scanner", "category": "learning"},
            {"id": "llm_analyze", "name": "#61 LLM Analysis", "category": "llm"},
            {"id": "embedding_search", "name": "#63 Embedding Search", "category": "llm"},
            {"id": "ai_report", "name": "#64 AI Report Generator", "category": "llm"},
        ],
        "total": 14,
    }


# ─── Scan analysis ──────────────────────────

@router.post("/analyze")
async def analyze_scan(scan_data: dict, user: CurrentUser = None) -> SuccessResponse:
    """Queue AI analysis of scan results (async)."""
    task = await analyze_scan_results.kiq(scan_data)
    return SuccessResponse(
        message="AI analysis queued",
        data={"task_id": str(task.task_id)},
    )


@router.post("/analyze/instant")
async def analyze_scan_instant(scan_data: dict, user: CurrentUser = None) -> dict:
    """Run instant AI analysis."""
    orchestrator = AIOrchestrator()
    try:
        return await orchestrator.analyze_scan_results(scan_data)
    finally:
        await orchestrator.close()


# ─── Anomaly detection ──────────────────────

@router.post("/anomaly/network")
async def detect_network_anomaly(traffic_data: list[dict], user: CurrentUser = None) -> dict:
    """Analyze network traffic for anomalies."""
    orchestrator = AIOrchestrator()
    try:
        return await orchestrator.run_module("network_anomaly", {"traffic": traffic_data})
    finally:
        await orchestrator.close()


@router.post("/anomaly/logs")
async def detect_log_anomaly(logs: list[str], user: CurrentUser = None) -> dict:
    """Analyze logs for anomalies."""
    orchestrator = AIOrchestrator()
    try:
        return await orchestrator.run_module("log_anomaly", {"logs": logs})
    finally:
        await orchestrator.close()


@router.post("/anomaly/behavior")
async def detect_behavior_anomaly(user_id: str, event: dict, user: CurrentUser = None) -> dict:
    """Check user behavior for anomalies."""
    orchestrator = AIOrchestrator()
    try:
        return await orchestrator.run_module("behavioral_anomaly", {"user_id": user_id, **event})
    finally:
        await orchestrator.close()


# ─── NLP / Threat Intel ──────────────────────

@router.post("/threat/parse")
async def parse_threat(text: str, user: CurrentUser = None) -> SuccessResponse:
    """Parse threat report for IOCs (async)."""
    task = await parse_threat_report.kiq(text)
    return SuccessResponse(
        message="Threat report parsing queued",
        data={"task_id": str(task.task_id)},
    )


@router.post("/threat/parse/instant")
async def parse_threat_instant(text: str, user: CurrentUser = None) -> dict:
    """Instantly parse threat report."""
    orchestrator = AIOrchestrator()
    try:
        return await orchestrator.parse_threat_report(text)
    finally:
        await orchestrator.close()


@router.post("/cve/analyze")
async def analyze_cve(cve_ids: list[str], user: CurrentUser = None) -> dict:
    """Analyze CVEs from NVD."""
    orchestrator = AIOrchestrator()
    try:
        return await orchestrator.run_module("cve_analyzer", {"cve_ids": cve_ids})
    finally:
        await orchestrator.close()


@router.post("/darkweb/monitor")
async def monitor_dark_web(domain: str, user: CurrentUser = None) -> SuccessResponse:
    """Monitor dark web for domain (async)."""
    task = await monitor_darkweb.kiq(domain)
    return SuccessResponse(
        message=f"Dark web monitoring started for {domain}",
        data={"task_id": str(task.task_id)},
    )


# ─── Predictive ─────────────────────────────

@router.post("/predict/attacks")
async def predict_attacks(findings: list[dict], user: CurrentUser = None) -> dict:
    """Predict likely attacks based on findings."""
    orchestrator = AIOrchestrator()
    try:
        return await orchestrator.run_module("attack_predictor", {"findings": findings})
    finally:
        await orchestrator.close()


@router.post("/risk/score")
async def score_risk(features: dict, user: CurrentUser = None) -> dict:
    """Calculate ML risk score."""
    orchestrator = AIOrchestrator()
    try:
        return await orchestrator.run_module("risk_scorer", {"features": features})
    finally:
        await orchestrator.close()


# ─── Feedback ────────────────────────────────

@router.post("/feedback")
async def submit_feedback(
    finding_id: str,
    module: str,
    is_true_positive: bool,
    analyst_notes: str = "",
    user: CurrentUser = None,
) -> dict:
    """Submit feedback on a finding."""
    orchestrator = AIOrchestrator()
    try:
        return await orchestrator.run_module("feedback", {
            "finding_id": finding_id,
            "module": module,
            "is_true_positive": is_true_positive,
            "analyst_notes": analyst_notes,
        })
    finally:
        await orchestrator.close()


@router.get("/feedback/accuracy")
async def get_accuracy(user: CurrentUser) -> dict:
    """Get model accuracy report."""
    orchestrator = AIOrchestrator()
    return orchestrator.feedback.get_accuracy_report()


# ─── LLM ─────────────────────────────────────

@router.post("/llm/analyze")
async def llm_analyze(findings: list[dict], user: CurrentUser = None) -> dict:
    """LLM-powered finding analysis."""
    orchestrator = AIOrchestrator()
    try:
        return await orchestrator.run_module("llm_analyze", {"findings": findings})
    finally:
        await orchestrator.close()


@router.post("/llm/remediation")
async def llm_remediation(finding: dict, user: CurrentUser = None) -> dict:
    """Get LLM-generated remediation steps."""
    orchestrator = AIOrchestrator()
    try:
        return await orchestrator.run_module("llm_remediation", {"finding": finding})
    finally:
        await orchestrator.close()


@router.post("/llm/explain")
async def llm_explain(vuln_type: str, user: CurrentUser = None) -> dict:
    """Get LLM-generated vulnerability explanation."""
    orchestrator = AIOrchestrator()
    try:
        return await orchestrator.run_module("llm_explain", {"vuln_type": vuln_type})
    finally:
        await orchestrator.close()


# ─── Reports ────────────────────────────────

@router.post("/report")
async def generate_report(scan_data: dict, user: CurrentUser = None) -> SuccessResponse:
    """Generate AI-powered report (async)."""
    task = await generate_ai_report.kiq(scan_data)
    return SuccessResponse(
        message="AI report generation queued",
        data={"task_id": str(task.task_id)},
    )


@router.post("/report/instant")
async def generate_report_instant(scan_data: dict, user: CurrentUser = None) -> dict:
    """Generate AI report instantly."""
    orchestrator = AIOrchestrator()
    try:
        return await orchestrator.run_module("ai_report", scan_data)
    finally:
        await orchestrator.close()
