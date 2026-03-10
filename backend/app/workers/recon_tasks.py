"""
OfSec V3 — Recon Task Workers
================================
Taskiq async tasks wired to recon service modules.
All tasks persist results to the database via ScanRepository.
"""

from __future__ import annotations

import structlog

from app.repositories import ScanRepository
from app.services.recon.orchestrator import ReconOrchestrator
from app.workers.db_utils import worker_db_session
from app.workers.taskiq_app import broker

logger = structlog.get_logger()


async def _run_and_persist(
    module_name: str,
    target: str,
    config: dict | None = None,
    scan_type: str = "recon",
) -> dict:
    """
    Shared helper: run a recon module and persist the scan + findings.
    Used by every individual module task.
    """
    async with worker_db_session() as db:
        repo = ScanRepository(db)
        scan = await repo.create_scan(
            target=target,
            scan_type=scan_type,
            config={"module": module_name, **(config or {})},
        )

        orchestrator = ReconOrchestrator()
        try:
            result = await orchestrator.run_module(module_name, target, config)

            findings = result.get("findings") or result.get("vulnerabilities") or []
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
            logger.error("task.recon.error", module=module_name, target=target, error=str(e))
            raise
        finally:
            await orchestrator.close()


@broker.task
async def run_cert_transparency_scan(target: str, config: dict | None = None) -> dict:
    logger.info("task.recon.ct_scan.start", target=target)
    return await _run_and_persist("cert_transparency", target, config)


@broker.task
async def run_passive_dns_harvest(target: str, config: dict | None = None) -> dict:
    logger.info("task.recon.dns_harvest.start", target=target)
    return await _run_and_persist("passive_dns", target, config)


@broker.task
async def run_domain_blacklist_audit(target: str, config: dict | None = None) -> dict:
    logger.info("task.recon.blacklist.start", target=target)
    return await _run_and_persist("domain_blacklist", target, config)


@broker.task
async def run_whois_correlation(target: str, config: dict | None = None) -> dict:
    logger.info("task.recon.whois.start", target=target)
    return await _run_and_persist("whois_correlation", target, config)


@broker.task
async def run_web_archive_scrape(target: str, config: dict | None = None) -> dict:
    logger.info("task.recon.archive.start", target=target)
    return await _run_and_persist("web_archive", target, config)


@broker.task
async def run_search_engine_recon(target: str, config: dict | None = None) -> dict:
    logger.info("task.recon.search.start", target=target)
    return await _run_and_persist("search_engine", target, config)


@broker.task
async def run_social_mining(target: str, config: dict | None = None) -> dict:
    logger.info("task.recon.social.start", target=target)
    return await _run_and_persist("social_mining", target, config)


@broker.task
async def run_osint_feed_scan(target: str, config: dict | None = None) -> dict:
    logger.info("task.recon.osint.start", target=target)
    return await _run_and_persist("osint_feed", target, config)


@broker.task
async def run_tech_fingerprint(target: str, config: dict | None = None) -> dict:
    logger.info("task.recon.tech.start", target=target)
    return await _run_and_persist("tech_fingerprint", target, config)


@broker.task
async def run_port_scan(target: str, config: dict | None = None) -> dict:
    logger.info("task.recon.port_scan.start", target=target)
    return await _run_and_persist("port_scan", target, config)


@broker.task
async def run_cloud_discovery(target: str, config: dict | None = None) -> dict:
    logger.info("task.recon.cloud.start", target=target)
    return await _run_and_persist("cloud_discovery", target, config)


@broker.task
async def run_full_recon(target: str, modules: list[str] | None = None) -> dict:
    """
    Run all recon modules -- creates one parent Scan record,
    then dispatches each module and persists their findings together.
    """
    logger.info("task.recon.full.start", target=target, modules=modules)

    async with worker_db_session() as db:
        repo = ScanRepository(db)
        scan = await repo.create_scan(
            target=target,
            scan_type="recon",
            config={"modules": modules or "all", "mode": "full"},
        )

        orchestrator = ReconOrchestrator()
        try:
            result = await orchestrator.run_full_recon(target, modules=modules)

            # Aggregate findings from all module results
            all_findings: list[dict] = []
            for module_result in result.get("results", {}).values():
                if isinstance(module_result, dict):
                    findings = module_result.get("findings") or module_result.get("vulnerabilities") or []
                    all_findings.extend(findings)

            if all_findings:
                await repo.add_vulnerabilities(scan.id, all_findings)

            await repo.complete_scan(
                scan.id,
                result_summary={
                    "modules_run": result.get("modules_run", []),
                    "elapsed_seconds": result.get("elapsed_seconds"),
                    "findings_count": len(all_findings),
                },
            )

            result["scan_id"] = scan.id
            return result

        except Exception as e:
            await repo.complete_scan(scan.id, result_summary={}, error=str(e))
            logger.error("task.recon.full.error", target=target, error=str(e))
            raise
        finally:
            await orchestrator.close()
