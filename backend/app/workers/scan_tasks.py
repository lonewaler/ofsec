"""
OfSec V3 — Scanner Task Workers (Full Implementation)
=======================================================
Taskiq async tasks wired to vulnerability scanner modules.
"""

from app.workers.taskiq_app import broker
from app.services.scanner.orchestrator import ScannerOrchestrator

import structlog

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
    """Run all vulnerability scanner modules on a target."""
    logger.info("task.scanner.full.start", target=target, modules=modules)
    orchestrator = ScannerOrchestrator()
    try:
        return await orchestrator.run_full_scan(target, modules=modules)
    finally:
        await orchestrator.close()
