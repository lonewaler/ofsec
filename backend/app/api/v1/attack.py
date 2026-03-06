"""
OfSec V3 — Attack Simulator API Endpoints
============================================
REST API for attack simulation operations (Upgrades #31–45).
"""

from __future__ import annotations
import structlog
import fastapi
from fastapi import APIRouter, HTTPException, status

from app.api.deps import CurrentUser
from app.schemas import SuccessResponse
from app.services.attack.orchestrator import AttackOrchestrator
from app.workers.attack_tasks import (
    run_brute_force,
    run_c2_action,
    run_exfiltration_test,
    run_exploit_search,
    run_full_attack_simulation,
    run_lateral_movement,
    run_payload_generation,
    run_phishing_campaign,
    run_privesc_scan,
    run_social_engineering,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/attack", tags=["Attack Simulator"])

MODULE_TASK_MAP = {
    "payload_generator": run_payload_generation,
    "exploit_framework": run_exploit_search,
    "brute_force": run_brute_force,
    "phishing": run_phishing_campaign,
    "social_engineering": run_social_engineering,
    "privesc": run_privesc_scan,
    "lateral_movement": run_lateral_movement,
    "exfiltration": run_exfiltration_test,
    "c2": run_c2_action,
}


@router.get("/modules")
async def list_attack_modules(*, user: CurrentUser) -> dict:
    """List all available attack modules."""
    return {
        "modules": [
            {"id": "payload_generator", "name": "#31 Payload Generator", "category": "offensive"},
            {"id": "exploit_framework", "name": "#32 Exploit Framework", "category": "offensive"},
            {"id": "brute_force", "name": "#33 Brute-Force Engine", "category": "offensive"},
            {"id": "phishing", "name": "#34 Phishing Simulator", "category": "social"},
            {"id": "social_engineering", "name": "#35 Social Engineering", "category": "social"},
            {"id": "wireless", "name": "#36 Wireless Attacks", "category": "network"},
            {"id": "privesc", "name": "#37 Privilege Escalation", "category": "post-exploit"},
            {"id": "lateral_movement", "name": "#38 Lateral Movement", "category": "post-exploit"},
            {"id": "exfiltration", "name": "#39 Data Exfiltration", "category": "post-exploit"},
            {"id": "c2", "name": "#40 C2 Framework", "category": "c2"},
            {"id": "mitre_mapper", "name": "#41 MITRE ATT&CK", "category": "analysis"},
        ],
        "total": 11,
    }


@router.post("/simulate")
async def start_attack_simulation(*, 
    target: str,
    modules: list[str] | None = None,
    user: CurrentUser,
) -> SuccessResponse:
    """Start an attack simulation (async via Taskiq)."""
    logger.info("api.attack.simulate.start", target=target, modules=modules)

    task_ids = []

    if not modules or "all" in modules:
        task = await run_full_attack_simulation.kiq(target)
        task_ids.append({"module": "full_simulation", "task_id": str(task.task_id)})
    else:
        for module_name in modules:
            task_fn = MODULE_TASK_MAP.get(module_name)
            if task_fn:
                task = await task_fn.kiq(target)
                task_ids.append({"module": module_name, "task_id": str(task.task_id)})

    if not task_ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No valid modules")

    return SuccessResponse(
        message=f"Attack simulation started on {target}",
        data={"tasks": task_ids, "target": target},
    )


@router.post("/simulate/instant")
async def instant_attack_simulation(*, 
    target: str,
    modules: list[str] | None = None,
    user: CurrentUser,
) -> dict:
    """Run attack modules instantly (blocking)."""
    orchestrator = AttackOrchestrator()
    try:
        if modules and len(modules) == 1:
            return await orchestrator.run_module(modules[0], target)
        return await orchestrator.run_attack_simulation(target, modules=modules)
    finally:
        await orchestrator.close()


@router.post("/payloads/generate")
async def generate_payloads(*, 
    payload_type: str = "xss",
    category: str = "basic",
    encoding: str | None = None,
    user: CurrentUser,
) -> dict:
    """Generate specific payloads."""
    from app.services.attack.payload_generator import PayloadGenerator
    gen = PayloadGenerator()

    if payload_type == "xss":
        return {"payloads": gen.generate_xss(category=category, encode=encoding)}
    elif payload_type == "sqli":
        return {"payloads": gen.generate_sqli(category=category)}
    elif payload_type == "cmdi":
        return {"payloads": gen.generate_cmdi()}
    elif payload_type == "ssti":
        return {"payloads": gen.generate_ssti(engine=category)}
    elif payload_type == "ssrf":
        return {"payloads": gen.generate_ssrf()}
    elif payload_type == "all":
        return gen.generate_all()
    else:
        raise HTTPException(status_code=400, detail=f"Unknown payload type: {payload_type}")


@router.post("/phishing/campaign")
async def create_phishing_campaign(*, 
    template: str = "password_reset",
    phishing_url: str = "https://example.com/verify",
    targets: list[dict] | None = None,
    user: CurrentUser,
) -> dict:
    """Create a phishing campaign."""
    from app.services.attack.phishing_engine import PhishingSimulator
    sim = PhishingSimulator()
    return sim.generate_campaign(
        template_name=template,
        targets=targets or [{"name": "Test", "email": "test@example.com"}],
        phishing_url=phishing_url,
    )


@router.get("/phishing/templates")
async def list_phishing_templates(*, user: CurrentUser) -> dict:
    """List available phishing templates."""
    from app.services.attack.phishing_engine import PhishingSimulator
    sim = PhishingSimulator()
    return {"templates": sim.list_templates()}


@router.post("/exploit/search")
async def search_exploits(*, 
    query: str,
    user: CurrentUser,
) -> dict:
    """Search exploit database."""
    from app.services.attack.exploit_engine import ExploitFramework
    fw = ExploitFramework()
    return {"query": query, "results": await fw.search_exploitdb(query)}


@router.get("/mitre/kill-chain")
async def get_mitre_kill_chain(*, user: CurrentUser) -> dict:
    """Get MITRE ATT&CK kill chain."""
    from app.services.attack.c2_framework import MITREAttackMapper
    mapper = MITREAttackMapper()
    return {"kill_chain": mapper.get_kill_chain()}


@router.post("/mitre/map")
async def map_to_mitre(*, finding_type: str, user: CurrentUser) -> dict:
    """Map a finding to MITRE ATT&CK."""
    from app.services.attack.c2_framework import MITREAttackMapper
    mapper = MITREAttackMapper()
    return {"finding_type": finding_type, "mappings": mapper.map_finding(finding_type)}
