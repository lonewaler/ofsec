"""
OfSec V3 — Attack Simulator Task Workers
==========================================
Taskiq async tasks for attack simulation modules.
"""

from __future__ import annotations

import structlog

from app.repositories import ScanRepository
from app.services.attack.orchestrator import AttackOrchestrator
from app.workers.db_utils import worker_db_session
from app.workers.taskiq_app import broker

logger = structlog.get_logger()


async def _run_and_persist(
    module_name: str,
    target: str,
    config: dict | None = None,
    scan_type: str = "attack",
) -> dict:
    async with worker_db_session() as db:
        repo = ScanRepository(db)
        scan = await repo.create_scan(
            target=target,
            scan_type=scan_type,
            config={"module": module_name, **(config or {})},
        )

        orchestrator = AttackOrchestrator()
        try:
            result = await orchestrator.run_module(module_name, target, config)
            # Find and persist vulnerabilities/findings if any
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
            logger.error(f"task.attack.{module_name}.error", target=target, error=str(e))
            raise
        finally:
            await orchestrator.close()


@broker.task
async def run_payload_generation(target: str, config: dict | None = None) -> dict:
    """#31 Generate attack payloads."""
    logger.info("task.attack.payload.start", target=target)
    return await _run_and_persist("payload_generator", target, config)


@broker.task
async def run_exploit_search(target: str, config: dict | None = None) -> dict:
    """#32 Search exploit database."""
    logger.info("task.attack.exploit.start", target=target)
    return await _run_and_persist("exploit_framework", target, config)


@broker.task
async def run_brute_force(target: str, config: dict | None = None) -> dict:
    """#33 Brute-force authentication test."""
    logger.info("task.attack.brute_force.start", target=target)
    return await _run_and_persist("brute_force", target, config)


@broker.task
async def run_phishing_campaign(target: str, config: dict | None = None) -> dict:
    """#34 Generate phishing campaign."""
    logger.info("task.attack.phishing.start", target=target)
    return await _run_and_persist("phishing", target, config)


@broker.task
async def run_social_engineering(target: str, config: dict | None = None) -> dict:
    """#35 Social engineering assessment."""
    logger.info("task.attack.social_engineering.start", target=target)
    return await _run_and_persist("social_engineering", target, config)


@broker.task
async def run_privesc_scan(target: str, config: dict | None = None) -> dict:
    """#37 Privilege escalation scan."""
    logger.info("task.attack.privesc.start", target=target)
    return await _run_and_persist("privesc", target, config)


@broker.task
async def run_lateral_movement(target: str, config: dict | None = None) -> dict:
    """#38 Lateral movement assessment."""
    logger.info("task.attack.lateral_movement.start", target=target)
    return await _run_and_persist("lateral_movement", target, config)


@broker.task
async def run_exfiltration_test(target: str, config: dict | None = None) -> dict:
    """#39 Data exfiltration test."""
    logger.info("task.attack.exfiltration.start", target=target)
    return await _run_and_persist("exfiltration", target, config)


@broker.task
async def run_c2_action(target: str, config: dict | None = None) -> dict:
    """#40 C2 framework action."""
    logger.info("task.attack.c2.start", target=target)
    return await _run_and_persist("c2", target, config)


@broker.task
async def run_full_attack_simulation(target: str, modules: list[str] | None = None) -> dict:
    """Run coordinated attack simulation."""
    logger.info("task.attack.full.start", target=target, modules=modules)

    async with worker_db_session() as db:
        repo = ScanRepository(db)
        scan = await repo.create_scan(
            target=target,
            scan_type="attack",
            config={"modules": modules or "all", "mode": "full"},
        )

        orchestrator = AttackOrchestrator()
        try:
            result = await orchestrator.run_attack_simulation(target, modules=modules)

            all_findings = []
            if isinstance(result, dict):
                for module_result in result.get("results", {}).values():
                    if isinstance(module_result, dict):
                        f = module_result.get("findings") or module_result.get("vulnerabilities") or []
                        all_findings.extend(f)

            if all_findings:
                await repo.add_vulnerabilities(scan.id, all_findings)

            await repo.complete_scan(
                scan.id,
                result_summary={
                    "modules_run": result.get("modules_run", []) if isinstance(result, dict) else [],
                    "findings_count": len(all_findings),
                },
            )

            if isinstance(result, dict):
                result["scan_id"] = scan.id
            return result

        except Exception as e:
            await repo.complete_scan(scan.id, result_summary={}, error=str(e))
            logger.error("task.attack.full.error", target=target, error=str(e))
            raise
        finally:
            await orchestrator.close()
