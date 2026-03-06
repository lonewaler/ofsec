"""
OfSec V3 — Attack Simulator Task Workers
==========================================
Taskiq async tasks for attack simulation modules.
"""

from __future__ import annotations

import structlog

from app.services.attack.orchestrator import AttackOrchestrator
from app.workers.taskiq_app import broker

logger = structlog.get_logger()


@broker.task
async def run_payload_generation(target: str, config: dict | None = None) -> dict:
    """#31 Generate attack payloads."""
    orchestrator = AttackOrchestrator()
    try:
        return await orchestrator.run_module("payload_generator", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_exploit_search(target: str, config: dict | None = None) -> dict:
    """#32 Search exploit database."""
    orchestrator = AttackOrchestrator()
    try:
        return await orchestrator.run_module("exploit_framework", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_brute_force(target: str, config: dict | None = None) -> dict:
    """#33 Brute-force authentication test."""
    orchestrator = AttackOrchestrator()
    try:
        return await orchestrator.run_module("brute_force", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_phishing_campaign(target: str, config: dict | None = None) -> dict:
    """#34 Generate phishing campaign."""
    orchestrator = AttackOrchestrator()
    try:
        return await orchestrator.run_module("phishing", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_social_engineering(target: str, config: dict | None = None) -> dict:
    """#35 Social engineering assessment."""
    orchestrator = AttackOrchestrator()
    try:
        return await orchestrator.run_module("social_engineering", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_privesc_scan(target: str, config: dict | None = None) -> dict:
    """#37 Privilege escalation scan."""
    orchestrator = AttackOrchestrator()
    try:
        return await orchestrator.run_module("privesc", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_lateral_movement(target: str, config: dict | None = None) -> dict:
    """#38 Lateral movement assessment."""
    orchestrator = AttackOrchestrator()
    try:
        return await orchestrator.run_module("lateral_movement", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_exfiltration_test(target: str, config: dict | None = None) -> dict:
    """#39 Data exfiltration test."""
    orchestrator = AttackOrchestrator()
    try:
        return await orchestrator.run_module("exfiltration", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_c2_action(target: str, config: dict | None = None) -> dict:
    """#40 C2 framework action."""
    orchestrator = AttackOrchestrator()
    try:
        return await orchestrator.run_module("c2", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_full_attack_simulation(target: str, modules: list[str] | None = None) -> dict:
    """Run coordinated attack simulation."""
    logger.info("task.attack.full.start", target=target, modules=modules)
    orchestrator = AttackOrchestrator()
    try:
        return await orchestrator.run_attack_simulation(target, modules=modules)
    finally:
        await orchestrator.close()
