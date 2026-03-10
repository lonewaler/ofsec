"""
OfSec V3 — AI/ML Task Workers
================================
Taskiq async tasks for AI/ML modules.
"""

from __future__ import annotations

from collections.abc import Awaitable
from typing import Any

import structlog

from app.repositories import ScanRepository
from app.services.ai.orchestrator import AIOrchestrator
from app.workers.db_utils import worker_db_session
from app.workers.taskiq_app import broker

logger = structlog.get_logger()


async def _persist_ai_task(
    task_name: str, target: str, config: dict, orchestrator: AIOrchestrator, exec_coro: Awaitable[Any]
) -> dict:
    async with worker_db_session() as db:
        repo = ScanRepository(db)
        scan = await repo.create_scan(
            target=target,
            scan_type="ai",
            config={"task": task_name, **config},
        )
        try:
            result = await exec_coro
            if not isinstance(result, dict):
                result = {"result": result}

            findings = result.get("findings") or result.get("vulnerabilities") or []
            if findings:
                await repo.add_vulnerabilities(scan.id, findings)

            await repo.complete_scan(scan.id, result_summary={"task": task_name, "findings_count": len(findings)})
            result["scan_id"] = scan.id
            return result
        except Exception as e:
            await repo.complete_scan(scan.id, result_summary={}, error=str(e))
            logger.error(f"task.ai.{task_name}.error", target=target, error=str(e))
            raise
        finally:
            await orchestrator.close()


@broker.task
async def analyze_scan_results(scan_data: dict) -> dict:
    """Run full AI analysis on scan results."""
    logger.info("task.ai.analyze_scan.start")
    orchestrator = AIOrchestrator()
    target = scan_data.get("target", "Unknown")
    return await _persist_ai_task(
        "analyze_scan_results",
        target,
        {"scan_data": scan_data},
        orchestrator,
        orchestrator.analyze_scan_results(scan_data),
    )


@broker.task
async def parse_threat_report(text: str) -> dict:
    """Parse a threat intelligence report."""
    logger.info("task.ai.parse_report.start")
    orchestrator = AIOrchestrator()
    return await _persist_ai_task(
        "parse_threat_report", "Threat Report", {}, orchestrator, orchestrator.parse_threat_report(text)
    )


@broker.task
async def analyze_cves(cve_ids: list[str]) -> dict:
    """Analyze CVEs from NVD."""
    logger.info("task.ai.analyze_cves.start")
    orchestrator = AIOrchestrator()
    return await _persist_ai_task(
        "analyze_cves",
        "CVE Analysis",
        {"cve_ids": cve_ids},
        orchestrator,
        orchestrator.run_module("cve_analyzer", {"cve_ids": cve_ids}),
    )


@broker.task
async def monitor_darkweb(domain: str) -> dict:
    """Monitor dark web for domain."""
    logger.info("task.ai.monitor_darkweb.start", domain=domain)
    orchestrator = AIOrchestrator()
    return await _persist_ai_task(
        "monitor_darkweb",
        domain,
        {"domain": domain},
        orchestrator,
        orchestrator.run_module("darkweb_monitor", {"domain": domain}),
    )


@broker.task
async def run_llm_analysis(findings: list[dict]) -> dict:
    """LLM-powered finding analysis."""
    logger.info("task.ai.llm_analysis.start")
    orchestrator = AIOrchestrator()
    return await _persist_ai_task(
        "llm_analysis",
        "LLM Analysis",
        {"findings_count": len(findings)},
        orchestrator,
        orchestrator.run_module("llm_analyze", {"findings": findings}),
    )


@broker.task
async def generate_ai_report(scan_data: dict) -> dict:
    """Generate AI-powered security report."""
    logger.info("task.ai.generate_report.start")
    orchestrator = AIOrchestrator()
    target = scan_data.get("target", "Unknown")
    return await _persist_ai_task(
        "generate_report",
        target,
        {"scan_data": scan_data},
        orchestrator,
        orchestrator.run_module("ai_report", scan_data),
    )


@broker.task
async def run_anomaly_detection(module: str, data: dict) -> dict:
    """Run anomaly detection module."""
    logger.info("task.ai.anomaly_detection.start", module=module)
    orchestrator = AIOrchestrator()
    target = data.get("target", "Unknown")
    return await _persist_ai_task(
        "anomaly_detection",
        target,
        {"module": module, "data": data},
        orchestrator,
        orchestrator.run_module(module, data),
    )
