"""
OfSec V3 — Attack Simulator Orchestrator
==========================================
Central orchestrator for all attack simulation modules (#31-45).
"""

from __future__ import annotations
import asyncio
from datetime import UTC, datetime

import structlog

from app.core.telemetry import get_tracer
from app.services.attack.c2_framework import (
    AttackReportGenerator,
    C2Framework,
    MITREAttackMapper,
    WirelessAttackModule,
)
from app.services.attack.exploit_engine import BruteForceEngine, ExploitFramework
from app.services.attack.payload_generator import PayloadGenerator
from app.services.attack.phishing_engine import PhishingSimulator, SocialEngineeringToolkit
from app.services.attack.post_exploitation import (
    DataExfiltrationTester,
    LateralMovementSimulator,
    PrivilegeEscalationScanner,
)

logger = structlog.get_logger()
tracer = get_tracer("attack.orchestrator")


class AttackOrchestrator:
    """
    Central orchestrator for all 15 attack simulation modules.

    Modules:
        31 - Payload Generator
        32 - Exploit Framework
        33 - Brute-Force Engine
        34 - Phishing Simulator
        35 - Social Engineering Toolkit
        36 - Wireless Attack Module
        37 - Privilege Escalation Scanner
        38 - Lateral Movement Simulator
        39 - Data Exfiltration Tester
        40 - C2 Framework
        41 - MITRE ATT&CK Mapper
        42-43 - Attack Report Generator
        44-45 - (Advanced extensions)
    """

    MODULES = {
        "payload_generator": PayloadGenerator,
        "exploit_framework": ExploitFramework,
        "brute_force": BruteForceEngine,
        "phishing": PhishingSimulator,
        "social_engineering": SocialEngineeringToolkit,
        "wireless": WirelessAttackModule,
        "privesc": PrivilegeEscalationScanner,
        "lateral_movement": LateralMovementSimulator,
        "exfiltration": DataExfiltrationTester,
        "c2": C2Framework,
        "mitre_mapper": MITREAttackMapper,
        "report_generator": AttackReportGenerator,
    }

    def __init__(self):
        self._instances: dict = {}

    def _get_module(self, name: str):
        if name not in self._instances:
            cls = self.MODULES.get(name)
            if cls:
                self._instances[name] = cls()
        return self._instances.get(name)

    async def run_module(self, module_name: str, target: str, config: dict | None = None) -> dict:
        """Run a single attack module."""
        with tracer.start_as_current_span(f"attack.{module_name}") as span:
            span.set_attribute("target", target)
            span.set_attribute("module", module_name)
            cfg = config or {}

            module = self._get_module(module_name)
            if not module:
                return {"error": f"Unknown module: {module_name}"}

            try:
                if module_name == "payload_generator":
                    return module.generate_all(cfg)

                elif module_name == "exploit_framework":
                    return {
                        "target": target,
                        "exploits": module.match_exploits(cfg.get("banner", target), cfg.get("version", "")),
                        "search_results": await module.search_exploitdb(target),
                    }

                elif module_name == "brute_force":
                    protocol = cfg.get("protocol", "http_basic")
                    if protocol == "http_form":
                        return await module.brute_http_form(target, **{
                            k: v for k, v in cfg.items() if k != "protocol"
                        })
                    return await module.brute_http_basic(target,
                        usernames=cfg.get("usernames"),
                        passwords=cfg.get("passwords"),
                    )

                elif module_name == "phishing":
                    return module.generate_campaign(
                        template_name=cfg.get("template", "password_reset"),
                        targets=cfg.get("targets", [{"name": "Test User", "email": "test@example.com"}]),
                        phishing_url=cfg.get("phishing_url", "https://phish.example.com/verify"),
                    )

                elif module_name == "social_engineering":
                    return {
                        "scenarios": module.list_scenarios(),
                        "domain_variants": module.generate_domain_variants(target),
                    }

                elif module_name == "wireless":
                    attack_type = cfg.get("attack_type", "deauth")
                    return module.get_attack_plan(attack_type, target)

                elif module_name == "privesc":
                    os_type = cfg.get("os_type", "linux")
                    return module.generate_checklist(os_type)

                elif module_name == "lateral_movement":
                    return await module.scan_lateral_vectors(target)

                elif module_name == "exfiltration":
                    return {
                        "techniques": module.list_techniques(),
                        "dns_test": await module.test_dns_exfil("test-data", target),
                    }

                elif module_name == "c2":
                    action = cfg.get("action", "list_sessions")
                    if action == "create_listener":
                        return module.create_listener(
                            name=cfg.get("name", "default"),
                            protocol=cfg.get("protocol", "https"),
                            port=cfg.get("port", 443),
                        )
                    elif action == "generate_implant":
                        return module.generate_implant(
                            name=cfg.get("name", "implant-1"),
                            os_target=cfg.get("os", "linux"),
                        )
                    return {"sessions": module.list_sessions(), "listeners": module.list_listeners()}

                elif module_name == "mitre_mapper":
                    finding_type = cfg.get("finding_type", "xss")
                    return {
                        "finding_type": finding_type,
                        "mappings": module.map_finding(finding_type),
                        "kill_chain": module.get_kill_chain(),
                    }

                elif module_name == "report_generator":
                    return module.generate_report(cfg.get("results", {"findings": []}))

                return {"error": f"Module {module_name} not routed"}

            except Exception as e:
                logger.error(f"attack.{module_name}.error", target=target, error=str(e), exc_info=True)
                return {"error": str(e), "module": module_name}

    async def run_attack_simulation(
        self,
        target: str,
        modules: list[str] | None = None,
        concurrency: int = 3,
    ) -> dict:
        """Run a coordinated attack simulation."""
        with tracer.start_as_current_span("attack.simulation") as span:
            span.set_attribute("target", target)

            default_modules = [
                "payload_generator", "exploit_framework", "privesc",
                "lateral_movement", "social_engineering", "mitre_mapper",
            ]
            selected = modules or default_modules
            results: dict = {}
            semaphore = asyncio.Semaphore(concurrency)
            start_time = datetime.now(UTC)

            async def run_with_semaphore(mod_name: str):
                async with semaphore:
                    results[mod_name] = await self.run_module(mod_name, target)

            tasks = [run_with_semaphore(m) for m in selected]
            await asyncio.gather(*tasks, return_exceptions=True)

            elapsed = (datetime.now(UTC) - start_time).total_seconds()

            # Aggregate findings
            all_findings = []
            for mod_data in results.values():
                if isinstance(mod_data, dict):
                    all_findings.extend(mod_data.get("findings", []))

            # Generate report
            report_gen = self._get_module("report_generator")
            report = report_gen.generate_report({
                "target": target,
                "modules_run": selected,
                "findings": all_findings,
            })

            logger.info(
                "attack.orchestrator.complete",
                target=target, modules=len(selected),
                elapsed=round(elapsed, 2), findings=len(all_findings),
            )

            return {
                "target": target,
                "modules_run": selected,
                "elapsed_seconds": round(elapsed, 2),
                "report": report,
                "module_results": results,
            }

    async def close(self):
        for name, instance in self._instances.items():
            if hasattr(instance, "close"):
                try:
                    await instance.close()
                except Exception as e:
                    logger.debug("attack.orchestrator.close.error", module=name, error=str(e))
                    pass
