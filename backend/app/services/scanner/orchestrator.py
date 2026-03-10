"""
OfSec V3 — Vulnerability Scanner Orchestrator
===============================================
Central orchestrator coordinating all scanner modules (#16-30).
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import structlog

from app.core.telemetry import get_tracer
from app.services.scanner.advanced_scanner import (
    CloudConfigAuditor,
    ContainerSecurityScanner,
    CredentialTester,
    SubdomainBruteforcer,
    VulnerabilityCorrelator,
    WAFDetector,
)
from app.services.scanner.api_scanner import APISecurityScanner
from app.services.scanner.dependency_scanner import DependencyScanner
from app.services.scanner.header_analyzer import HeaderSecurityAnalyzer
from app.services.scanner.network_scanner import (
    CMSScanner,
    ComplianceAuditor,
    NetworkDiscoveryScanner,
)
from app.services.scanner.ssl_auditor import SSLTLSAuditor
from app.services.scanner.web_scanner import WebApplicationScanner

logger = structlog.get_logger()
tracer = get_tracer("scanner.orchestrator")


class ScannerOrchestrator:
    """
    Central scanner orchestrator — coordinates all 15 vulnerability scanner modules.

    Usage:
        orchestrator = ScannerOrchestrator()
        results = await orchestrator.run_full_scan("https://example.com")
    """

    MODULES = {
        "web_scanner": WebApplicationScanner,
        "header_analyzer": HeaderSecurityAnalyzer,
        "api_scanner": APISecurityScanner,
        "dependency_scanner": DependencyScanner,
        "ssl_auditor": SSLTLSAuditor,
        "network_discovery": NetworkDiscoveryScanner,
        "cms_scanner": CMSScanner,
        "compliance_auditor": ComplianceAuditor,
        "container_scanner": ContainerSecurityScanner,
        "cloud_auditor": CloudConfigAuditor,
        "credential_tester": CredentialTester,
        "waf_detector": WAFDetector,
        "subdomain_bruteforcer": SubdomainBruteforcer,
    }

    def __init__(self):
        self._instances: dict = {}
        self._correlator = VulnerabilityCorrelator()

    def _get_module(self, name: str):
        if name not in self._instances:
            cls = self.MODULES.get(name)
            if cls:
                self._instances[name] = cls()
        return self._instances.get(name)

    async def run_module(self, module_name: str, target: str, config: dict | None = None) -> dict:
        """Run a single scanner module."""
        with tracer.start_as_current_span(f"scanner.{module_name}") as span:
            span.set_attribute("target", target)
            span.set_attribute("module", module_name)

            module = self._get_module(module_name)
            if not module:
                return {"error": f"Unknown module: {module_name}"}

            try:
                if module_name == "web_scanner":
                    return await module.scan(target)
                elif module_name == "header_analyzer":
                    return await module.analyze(target)
                elif module_name == "api_scanner":
                    return await module.scan(target)
                elif module_name == "dependency_scanner":
                    reqs = (config or {}).get("requirements", "")
                    eco = (config or {}).get("ecosystem", "PyPI")
                    return await module.scan_requirements(reqs, eco)
                elif module_name == "ssl_auditor":
                    port = (config or {}).get("port", 443)
                    return await module.audit(target, port=port)
                elif module_name == "network_discovery":
                    return await module.discover(target)
                elif module_name == "cms_scanner":
                    return await module.scan(target)
                elif module_name == "compliance_auditor":
                    return await module.audit(target)
                elif module_name == "container_scanner":
                    dockerfile = (config or {}).get("dockerfile", "")
                    return module.scan_dockerfile(dockerfile)
                elif module_name == "cloud_auditor":
                    return await module.audit_cloud_exposure(target)
                elif module_name == "credential_tester":
                    return await module.scan(target)
                elif module_name == "waf_detector":
                    return await module.detect(target)
                elif module_name == "subdomain_bruteforcer":
                    subs = await module.bruteforce(target)
                    return {"domain": target, "subdomains": subs, "count": len(subs)}
                else:
                    return {"error": f"Module {module_name} not routed"}

            except Exception as e:
                logger.error(
                    f"scanner.{module_name}.error",
                    target=target,
                    error=str(e),
                    exc_info=True,
                )
                return {"error": str(e), "module": module_name}

    async def run_full_scan(
        self,
        target: str,
        modules: list[str] | None = None,
        concurrency: int = 5,
    ) -> dict:
        """Run multiple scanner modules concurrently."""
        with tracer.start_as_current_span("scanner.full") as span:
            span.set_attribute("target", target)

            # Default URL-based modules (skip dependency/container which need file input)
            default_modules = [
                "web_scanner",
                "header_analyzer",
                "api_scanner",
                "ssl_auditor",
                "cms_scanner",
                "compliance_auditor",
                "waf_detector",
                "credential_tester",
            ]
            selected = modules or default_modules
            results: dict = {}
            semaphore = asyncio.Semaphore(concurrency)
            start_time = datetime.now(UTC)

            async def run_with_semaphore(mod_name: str):
                async with semaphore:
                    logger.info("scanner.orchestrator.start", module=mod_name, target=target)
                    result = await self.run_module(mod_name, target)
                    results[mod_name] = result

            tasks = [run_with_semaphore(m) for m in selected]
            await asyncio.gather(*tasks, return_exceptions=True)

            elapsed = (datetime.now(UTC) - start_time).total_seconds()

            # Correlate findings
            correlation = self._correlator.correlate(results)

            logger.info(
                "scanner.orchestrator.complete",
                target=target,
                modules_run=len(selected),
                elapsed=round(elapsed, 2),
                risk=correlation["risk_rating"],
            )

            return {
                "target": target,
                "modules_run": selected,
                "elapsed_seconds": round(elapsed, 2),
                "started_at": start_time.isoformat(),
                "risk_assessment": {
                    "rating": correlation["risk_rating"],
                    "score": correlation["risk_score"],
                    "severity_summary": correlation["severity_summary"],
                },
                "module_results": results,
                "correlated_findings": correlation["findings"][:50],
            }

    async def close(self):
        for instance in self._instances.values():
            if hasattr(instance, "close"):
                await instance.close()
