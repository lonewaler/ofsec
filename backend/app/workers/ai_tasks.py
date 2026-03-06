"""
OfSec V3 — AI/ML Task Workers
================================
Taskiq async tasks for AI/ML modules.
"""

from __future__ import annotations
import structlog

from app.services.ai.orchestrator import AIOrchestrator
from app.workers.taskiq_app import broker

logger = structlog.get_logger()


@broker.task
async def analyze_scan_results(scan_data: dict) -> dict:
    """Run full AI analysis on scan results."""
    orchestrator = AIOrchestrator()
    try:
        return await orchestrator.analyze_scan_results(scan_data)
    finally:
        await orchestrator.close()


@broker.task
async def parse_threat_report(text: str) -> dict:
    """Parse a threat intelligence report."""
    orchestrator = AIOrchestrator()
    try:
        return await orchestrator.parse_threat_report(text)
    finally:
        await orchestrator.close()


@broker.task
async def analyze_cves(cve_ids: list[str]) -> dict:
    """Analyze CVEs from NVD."""
    orchestrator = AIOrchestrator()
    try:
        return await orchestrator.run_module("cve_analyzer", {"cve_ids": cve_ids})
    finally:
        await orchestrator.close()


@broker.task
async def monitor_darkweb(domain: str) -> dict:
    """Monitor dark web for domain."""
    orchestrator = AIOrchestrator()
    try:
        return await orchestrator.run_module("darkweb_monitor", {"domain": domain})
    finally:
        await orchestrator.close()


@broker.task
async def run_llm_analysis(findings: list[dict]) -> dict:
    """LLM-powered finding analysis."""
    orchestrator = AIOrchestrator()
    try:
        return await orchestrator.run_module("llm_analyze", {"findings": findings})
    finally:
        await orchestrator.close()


@broker.task
async def generate_ai_report(scan_data: dict) -> dict:
    """Generate AI-powered security report."""
    orchestrator = AIOrchestrator()
    try:
        return await orchestrator.run_module("ai_report", scan_data)
    finally:
        await orchestrator.close()


@broker.task
async def run_anomaly_detection(module: str, data: dict) -> dict:
    """Run anomaly detection module."""
    orchestrator = AIOrchestrator()
    try:
        return await orchestrator.run_module(module, data)
    finally:
        await orchestrator.close()
