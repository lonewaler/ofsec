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


async def _run_and_persist(
    module_name: str,
    target: str,
    config: dict | None = None,
    scan_type: str = "vuln",
) -> dict:
    """
    Shared helper: run a scanner module and persist the scan + findings.
    Used by every individual module task.
    """
    async with worker_db_session() as db:
        repo = ScanRepository(db)
        scan = await repo.create_scan(
            target=target,
            scan_type=scan_type,
            config={"module": module_name, **(config or {})},
        )

        orchestrator = ScannerOrchestrator()
        try:
            result = await orchestrator.run_module(module_name, target, config)

            findings = (
                result.get("findings")
                or result.get("vulnerabilities")
                or []
            )
            if findings:
                await repo.add_vulnerabilities(scan.id, findings)

            await repo.complete_scan(
                scan.id,
                result_summary={
                    "module": module_name,
                    "findings_count": len(findings),
                    "result_keys": list(result.keys()),
                },
            )
            result["scan_id"] = scan.id
            return result

        except Exception as e:
            await repo.complete_scan(scan.id, result_summary={}, error=str(e))
            logger.error("task.scanner.module.error", module=module_name, target=target, error=str(e))
            raise
        finally:
            await orchestrator.close()


@broker.task
async def run_web_scan(target: str, config: dict | None = None) -> dict:
    """#16 Web application vulnerability scan (XSS, SQLi, etc)."""
    logger.info("task.scanner.web.start", target=target)
    return await _run_and_persist("web_scanner", target, config)


@broker.task
async def run_header_analysis(target: str, config: dict | None = None) -> dict:
    """#17 HTTP header security analysis."""
    logger.info("task.scanner.headers.start", target=target)
    return await _run_and_persist("header_analyzer", target, config)


@broker.task
async def run_api_scan(target: str, config: dict | None = None) -> dict:
    """#18 API security scan."""
    logger.info("task.scanner.api.start", target=target)
    return await _run_and_persist("api_scanner", target, config)


@broker.task
async def run_dependency_scan(target: str, config: dict | None = None) -> dict:
    """#19 Dependency vulnerability scan."""
    logger.info("task.scanner.deps.start", target=target)
    return await _run_and_persist("dependency_scanner", target, config)


@broker.task
async def run_container_scan(target: str, config: dict | None = None) -> dict:
    """#20 Container/Dockerfile security scan."""
    logger.info("task.scanner.container.start", target=target)
    return await _run_and_persist("container_scanner", target, config)


@broker.task
async def run_cloud_audit(target: str, config: dict | None = None) -> dict:
    """#21 Cloud configuration audit."""
    logger.info("task.scanner.cloud.start", target=target)
    return await _run_and_persist("cloud_auditor", target, config)


@broker.task
async def run_network_discovery(target: str, config: dict | None = None) -> dict:
    """#22 Network service discovery."""
    logger.info("task.scanner.network.start", target=target)
    return await _run_and_persist("network_discovery", target, config)


@broker.task
async def run_credential_test(target: str, config: dict | None = None) -> dict:
    """#23 Default credential testing."""
    logger.info("task.scanner.creds.start", target=target)
    return await _run_and_persist("credential_tester", target, config)


@broker.task
async def run_ssl_audit(target: str, config: dict | None = None) -> dict:
    """#24 SSL/TLS hardening audit."""
    logger.info("task.scanner.ssl.start", target=target)
    return await _run_and_persist("ssl_auditor", target, config)


@broker.task
async def run_cms_scan(target: str, config: dict | None = None) -> dict:
    """#25 CMS scanner (WordPress, Joomla, Drupal)."""
    logger.info("task.scanner.cms.start", target=target)
    return await _run_and_persist("cms_scanner", target, config)


@broker.task
async def run_compliance_audit(target: str, config: dict | None = None) -> dict:
    """#26 Compliance & configuration audit."""
    logger.info("task.scanner.compliance.start", target=target)
    return await _run_and_persist("compliance_auditor", target, config)


@broker.task
async def run_waf_detection(target: str, config: dict | None = None) -> dict:
    """#27 WAF detection."""
    logger.info("task.scanner.waf.start", target=target)
    return await _run_and_persist("waf_detector", target, config)


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

            # Extract findings from correct keys returned by ScannerOrchestrator
            findings = list(result.get("correlated_findings", []))
            for mod_name, mod_result in result.get("module_results", {}).items():
                if isinstance(mod_result, dict):
                    findings.extend(mod_result.get("findings", []))
                    findings.extend(mod_result.get("vulnerabilities", []))
            # Also check legacy top-level keys as fallback
            if not findings:
                findings = result.get("findings") or result.get("vulnerabilities") or []
            # Deduplicate by (type, url, parameter) tuple
            seen = set()
            deduped = []
            for f in findings:
                key = (f.get("type", ""), f.get("url", ""), f.get("parameter", ""))
                if key not in seen:
                    seen.add(key)
                    deduped.append(f)
            findings = deduped
            if findings:
                await repo.add_vulnerabilities(scan.id, findings)

            severity_summary: dict[str, int] = {}
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
