"""
OfSec V3 — Recon Task Workers (Full Implementation)
=====================================================
Taskiq async tasks wired to recon service modules.
"""

from app.workers.taskiq_app import broker
from app.services.recon.orchestrator import ReconOrchestrator

import structlog

logger = structlog.get_logger()


@broker.task
async def run_cert_transparency_scan(target: str, config: dict | None = None) -> dict:
    """#1 Certificate Transparency monitoring scan."""
    logger.info("task.recon.ct_scan.start", target=target)
    orchestrator = ReconOrchestrator()
    try:
        return await orchestrator.run_module("cert_transparency", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_passive_dns_harvest(target: str, config: dict | None = None) -> dict:
    """#2 Passive DNS harvesting."""
    logger.info("task.recon.dns_harvest.start", target=target)
    orchestrator = ReconOrchestrator()
    try:
        return await orchestrator.run_module("passive_dns", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_domain_blacklist_audit(target: str, config: dict | None = None) -> dict:
    """#4 Domain blacklist audit."""
    logger.info("task.recon.blacklist.start", target=target)
    orchestrator = ReconOrchestrator()
    try:
        return await orchestrator.run_module("domain_blacklist", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_whois_correlation(target: str, config: dict | None = None) -> dict:
    """#5 Historical WHOIS correlation."""
    logger.info("task.recon.whois.start", target=target)
    orchestrator = ReconOrchestrator()
    try:
        return await orchestrator.run_module("whois_correlation", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_web_archive_scrape(target: str, config: dict | None = None) -> dict:
    """#6 Web archive scraping."""
    logger.info("task.recon.archive.start", target=target)
    orchestrator = ReconOrchestrator()
    try:
        return await orchestrator.run_module("web_archive", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_search_engine_recon(target: str, config: dict | None = None) -> dict:
    """#7 Search engine dorking."""
    logger.info("task.recon.search.start", target=target)
    orchestrator = ReconOrchestrator()
    try:
        return await orchestrator.run_module("search_engine", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_social_mining(target: str, config: dict | None = None) -> dict:
    """#8 Social media mining."""
    logger.info("task.recon.social.start", target=target)
    orchestrator = ReconOrchestrator()
    try:
        return await orchestrator.run_module("social_mining", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_osint_feed_scan(target: str, config: dict | None = None) -> dict:
    """#9 OSINT feed scan (Shodan, Censys, VirusTotal)."""
    logger.info("task.recon.osint.start", target=target)
    orchestrator = ReconOrchestrator()
    try:
        return await orchestrator.run_module("osint_feed", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_tech_fingerprint(target: str, config: dict | None = None) -> dict:
    """#11 Technology fingerprinting."""
    logger.info("task.recon.tech.start", target=target)
    orchestrator = ReconOrchestrator()
    try:
        return await orchestrator.run_module("tech_fingerprint", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_port_scan(target: str, config: dict | None = None) -> dict:
    """#12 Port & service discovery."""
    logger.info("task.recon.port_scan.start", target=target)
    orchestrator = ReconOrchestrator()
    try:
        return await orchestrator.run_module("port_scan", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_cloud_discovery(target: str, config: dict | None = None) -> dict:
    """#13 Cloud asset discovery."""
    logger.info("task.recon.cloud.start", target=target)
    orchestrator = ReconOrchestrator()
    try:
        return await orchestrator.run_module("cloud_discovery", target, config)
    finally:
        await orchestrator.close()


@broker.task
async def run_full_recon(target: str, modules: list[str] | None = None) -> dict:
    """Run all recon modules on a target."""
    logger.info("task.recon.full.start", target=target, modules=modules)
    orchestrator = ReconOrchestrator()
    try:
        return await orchestrator.run_full_recon(target, modules=modules)
    finally:
        await orchestrator.close()
