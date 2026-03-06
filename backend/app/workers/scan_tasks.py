"""
OfSec V3 — Scanner Task Workers (Full Implementation)
=======================================================
Taskiq async tasks wired to vulnerability scanner modules.
"""

from __future__ import annotations
import structlog

from app.repositories import ScanRepository
from app.services.scanner.orchestrator import ScannerOrchestrator
from app.workers.db_utils import worker_db_session
from app.workers.taskiq_app import broker

logger = structlog.get_logger()


@broker.task
async def run_web_scan(target: str, config: dict | None = None) -> dict:
    """#16 Web application vulnerability scan (XSS, SQLi, etc)."""
    logger.info("task.scanner.web.start", target=target)
    orchestrator = ScannerOrchestrator()
    try:
        return await orchestrator.run_module("web_scanner", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_header_analysis(target: str, config: dict | None = None) -> dict:
    """#17 HTTP header security analysis."""
    logger.info("task.scanner.headers.start", target=target)
    orchestrator = ScannerOrchestrator()
    try:
        return await orchestrator.run_module("header_analyzer", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_api_scan(target: str, config: dict | None = None) -> dict:
    """#18 API security scan."""
    logger.info("task.scanner.api.start", target=target)
    orchestrator = ScannerOrchestrator()
    try:
        return await orchestrator.run_module("api_scanner", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_dependency_scan(target: str, config: dict | None = None) -> dict:
    """#19 Dependency vulnerability scan."""
    logger.info("task.scanner.deps.start", target=target)
    orchestrator = ScannerOrchestrator()
    try:
        return await orchestrator.run_module("dependency_scanner", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_container_scan(target: str, config: dict | None = None) -> dict:
    """#20 Container/Dockerfile security scan."""
    logger.info("task.scanner.container.start", target=target)
    orchestrator = ScannerOrchestrator()
    try:
        return await orchestrator.run_module("container_scanner", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_cloud_audit(target: str, config: dict | None = None) -> dict:
    """#21 Cloud configuration audit."""
    logger.info("task.scanner.cloud.start", target=target)
    orchestrator = ScannerOrchestrator()
    try:
        return await orchestrator.run_module("cloud_auditor", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_network_discovery(target: str, config: dict | None = None) -> dict:
    """#22 Network service discovery."""
    logger.info("task.scanner.network.start", target=target)
    orchestrator = ScannerOrchestrator()
    try:
        return await orchestrator.run_module("network_discovery", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_credential_test(target: str, config: dict | None = None) -> dict:
    """#23 Default credential testing."""
    logger.info("task.scanner.creds.start", target=target)
    orchestrator = ScannerOrchestrator()
    try:
        return await orchestrator.run_module("credential_tester", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_ssl_audit(target: str, config: dict | None = None) -> dict:
    """#24 SSL/TLS hardening audit."""
    logger.info("task.scanner.ssl.start", target=target)
    orchestrator = ScannerOrchestrator()
    try:
        return await orchestrator.run_module("ssl_auditor", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_cms_scan(target: str, config: dict | None = None) -> dict:
    """#25 CMS scanner (WordPress, Joomla, Drupal)."""
    logger.info("task.scanner.cms.start", target=target)
    orchestrator = ScannerOrchestrator()
    try:
        return await orchestrator.run_module("cms_scanner", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_compliance_audit(target: str, config: dict | None = None) -> dict:
    """#26 Compliance & configuration audit."""
    logger.info("task.scanner.compliance.start", target=target)
    orchestrator = ScannerOrchestrator()
    try:
        return await orchestrator.run_module("compliance_auditor", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_waf_detection(target: str, config: dict | None = None) -> dict:
    """#27 WAF detection."""
    logger.info("task.scanner.waf.start", target=target)
    orchestrator = ScannerOrchestrator()
    try:
        return await orchestrator.run_module("waf_detector", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_full_vulnerability_scan(target: str, modules: list[str] | None = None) -> dict:
    """Run all vulnerability scanner modules -- persists scan + findings to DB."""
    logger.info("task.scanner.full.start", target=target, modules=modules)

    async with worker_db_session() as db:
        repo = ScanRepository(db)
        scan = await repo.create_scan(
            target=target,
            scan_type="vuln",
            config={"modules": modules or "all"},
        )

        orchestrator = ScannerOrchestrator()
        try:
            result = await orchestrator.run_full_scan(target, modules=modules)

            findings = (
                result.get("findings")
                or result.get("vulnerabilities")
                or []
            )
            if findings:
                await repo.add_vulnerabilities(scan.id, findings)

            severity_summary = {}
            for f in findings:
                sev = (f.get("severity") or "INFO").upper()
                severity_summary[sev] = severity_summary.get(sev, 0) + 1

            await repo.complete_scan(
                scan.id,
                result_summary={
                    "total_findings": len(findings),
                    "severity_summary": severity_summary,
                },
            )

            result["scan_id"] = scan.id
            return result

        except Exception as e:
            await repo.complete_scan(scan.id, result_summary={}, error=str(e))
            logger.error("task.scanner.full.error", target=target, error=str(e))
            raise
        finally:
            await orchestrator.close()
