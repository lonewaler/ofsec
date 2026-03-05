"""
OfSec V3 — Defense Task Workers
==================================
Taskiq async tasks for defense and operations modules.
"""

import structlog

from app.services.defense.orchestrator import DefenseOrchestrator
from app.workers.taskiq_app import broker

logger = structlog.get_logger()


@broker.task
async def process_security_event(event: dict) -> dict:
    """Process a security event through the defense pipeline."""
    orchestrator = DefenseOrchestrator()
    return await orchestrator.process_security_event(event)


@broker.task
async def run_health_checks(endpoints: dict) -> dict:
    """Run health checks on endpoints."""
    orchestrator = DefenseOrchestrator()
    return await orchestrator.run_health_check(endpoints)


@broker.task
async def sweep_for_iocs(logs: list[str], iocs: dict) -> dict:
    """Sweep logs for IOCs."""
    orchestrator = DefenseOrchestrator()
    return await orchestrator.sweep_for_iocs(logs, iocs)


@broker.task
async def run_correlation(events: list[dict]) -> dict:
    """Process batch of events through correlation engine."""
    orchestrator = DefenseOrchestrator()
    results = []
    for event in events:
        triggered = orchestrator.correlation.add_event(event)
        if triggered:
            results.extend(triggered)
    return {"events_processed": len(events), "alerts_triggered": len(results), "alerts": results}
