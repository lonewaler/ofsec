"""
OfSec V3 — Recon Orchestrator
===============================
Central orchestrator that coordinates all recon modules and aggregates results.
"""

import asyncio
from datetime import UTC, datetime

import structlog

from app.core.telemetry import get_tracer
from app.services.recon.advanced_modules import (
    CloudAssetDiscovery,
    PortScanner,
    SubdomainTakeoverChecker,
    TechFingerprinter,
)
from app.services.recon.cert_transparency import CertTransparencyMonitor
from app.services.recon.domain_blacklist import DomainBlacklistAuditor
from app.services.recon.osint_feed import OSINTFeedIntegrator
from app.services.recon.passive_dns import PassiveDNSHarvester
from app.services.recon.recon_report import ReconReportGenerator
from app.services.recon.search_engine import SearchEngineRecon
from app.services.recon.social_mining import SocialMediaMiner
from app.services.recon.web_archive import WebArchiveScraper
from app.services.recon.whois_correlation import WHOISCorrelator

logger = structlog.get_logger()
tracer = get_tracer("recon.orchestrator")


class ReconOrchestrator:
    """
    Central recon orchestrator — coordinates all 15 recon modules.

    Usage:
        orchestrator = ReconOrchestrator()
        results = await orchestrator.run_full_recon("example.com")
        report = orchestrator.generate_report("example.com", results)
    """

    # Available modules and their classes
    MODULES = {
        "cert_transparency": CertTransparencyMonitor,
        "passive_dns": PassiveDNSHarvester,
        "domain_blacklist": DomainBlacklistAuditor,
        "whois_correlation": WHOISCorrelator,
        "web_archive": WebArchiveScraper,
        "search_engine": SearchEngineRecon,
        "social_mining": SocialMediaMiner,
        "osint_feed": OSINTFeedIntegrator,
        "tech_fingerprint": TechFingerprinter,
        "port_scan": PortScanner,
        "cloud_discovery": CloudAssetDiscovery,
        "subdomain_takeover": SubdomainTakeoverChecker,
    }

    def __init__(self):
        self._instances: dict = {}
        self._report_gen = ReconReportGenerator()

    def _get_module(self, name: str):
        """Get or create a module instance."""
        if name not in self._instances:
            cls = self.MODULES.get(name)
            if cls:
                self._instances[name] = cls()
        return self._instances.get(name)

    async def run_module(self, module_name: str, target: str, config: dict | None = None) -> dict:
        """Run a single recon module."""
        with tracer.start_as_current_span(f"recon.{module_name}") as span:
            span.set_attribute("target", target)
            span.set_attribute("module", module_name)

            module = self._get_module(module_name)
            if not module:
                return {"error": f"Unknown module: {module_name}"}

            try:
                # Route to appropriate method
                if module_name == "cert_transparency":
                    return await module.monitor_domain(target)
                elif module_name == "passive_dns":
                    return await module.harvest(target)
                elif module_name == "domain_blacklist":
                    return await module.audit(target)
                elif module_name == "whois_correlation":
                    return await module.correlate(target)
                elif module_name == "web_archive":
                    return await module.scrape(target)
                elif module_name == "search_engine":
                    return await module.run_dork_scan(target)
                elif module_name == "social_mining":
                    return await module.mine(target)
                elif module_name == "osint_feed":
                    return await module.scan(target, target_type="domain")
                elif module_name == "tech_fingerprint":
                    return await module.fingerprint(target)
                elif module_name == "port_scan":
                    return {"ports": await module.scan_ports(target)}
                elif module_name == "cloud_discovery":
                    return await module.discover(target)
                elif module_name == "subdomain_takeover":
                    return {"takeover_results": await module.scan([target])}
                else:
                    return {"error": f"Module {module_name} not implemented"}

            except Exception as e:
                logger.error(
                    f"recon.{module_name}.error",
                    target=target,
                    error=str(e),
                    exc_info=True,
                )
                return {"error": str(e), "module": module_name}

    async def run_full_recon(
        self,
        target: str,
        modules: list[str] | None = None,
        concurrency: int = 5,
    ) -> dict:
        """
        Run multiple recon modules concurrently on a target.

        Args:
            target: Target domain or IP
            modules: List of module names (None = all modules)
            concurrency: Max concurrent modules

        Returns:
            Dict with results from each module
        """
        with tracer.start_as_current_span("recon.full") as span:
            span.set_attribute("target", target)

            selected = modules or list(self.MODULES.keys())
            results: dict = {}
            semaphore = asyncio.Semaphore(concurrency)
            start_time = datetime.now(UTC)

            async def run_with_semaphore(mod_name: str):
                async with semaphore:
                    logger.info("recon.orchestrator.starting", module=mod_name, target=target)
                    result = await self.run_module(mod_name, target)
                    results[mod_name] = result

            tasks = [run_with_semaphore(m) for m in selected]
            await asyncio.gather(*tasks, return_exceptions=True)

            elapsed = (datetime.now(UTC) - start_time).total_seconds()

            logger.info(
                "recon.orchestrator.complete",
                target=target,
                modules_run=len(selected),
                elapsed_seconds=round(elapsed, 2),
            )

            return {
                "target": target,
                "modules_run": selected,
                "elapsed_seconds": round(elapsed, 2),
                "started_at": start_time.isoformat(),
                "results": results,
            }

    def generate_report(self, domain: str, scan_results: dict, fmt: str = "html") -> str | dict | bytes:
        """Generate a report from scan results."""
        module_results = scan_results.get("results", scan_results)

        if fmt == "json":
            return self._report_gen.generate_json(domain, module_results)
        elif fmt == "html":
            return self._report_gen.generate_html(domain, module_results)
        else:
            return self._report_gen.generate_json(domain, module_results)

    async def close(self):
        """Close all module instances."""
        for instance in self._instances.values():
            if hasattr(instance, "close"):
                await instance.close()
