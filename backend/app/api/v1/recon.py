"""
OfSec V3 — Recon API Endpoints (Full Implementation)
======================================================
REST API for reconnaissance operations (Upgrades #1–15).
"""

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import HTMLResponse

from app.api.deps import DbSession, CurrentUser
from app.repositories import ScanRepository
from app.schemas import (
    ReconScanRequest,
    ReconResultResponse,
    SuccessResponse,
)
from app.workers.recon_tasks import (
    run_cert_transparency_scan,
    run_passive_dns_harvest,
    run_domain_blacklist_audit,
    run_whois_correlation,
    run_web_archive_scrape,
    run_search_engine_recon,
    run_social_mining,
    run_osint_feed_scan,
    run_tech_fingerprint,
    run_port_scan,
    run_cloud_discovery,
    run_full_recon,
)
from app.services.recon.orchestrator import ReconOrchestrator

import structlog

logger = structlog.get_logger()

router = APIRouter(prefix="/recon", tags=["Reconnaissance"])

# Module name → task function mapping
MODULE_TASK_MAP = {
    "cert_transparency": run_cert_transparency_scan,
    "passive_dns": run_passive_dns_harvest,
    "domain_blacklist": run_domain_blacklist_audit,
    "whois_correlation": run_whois_correlation,
    "web_archive": run_web_archive_scrape,
    "search_engine": run_search_engine_recon,
    "social_mining": run_social_mining,
    "osint_feed": run_osint_feed_scan,
    "tech_fingerprint": run_tech_fingerprint,
    "port_scan": run_port_scan,
    "cloud_discovery": run_cloud_discovery,
}


@router.get("/modules", tags=["Reconnaissance"])
async def list_recon_modules(user: CurrentUser) -> dict:
    """List all available recon modules."""
    return {
        "modules": [
            {"id": "cert_transparency", "name": "#1 Certificate Transparency Monitor", "category": "passive"},
            {"id": "passive_dns", "name": "#2 Passive DNS Harvesting", "category": "passive"},
            {"id": "domain_blacklist", "name": "#4 Domain Blacklist Audit", "category": "passive"},
            {"id": "whois_correlation", "name": "#5 Historical WHOIS Correlation", "category": "passive"},
            {"id": "web_archive", "name": "#6 Web Archive Scraper", "category": "passive"},
            {"id": "search_engine", "name": "#7 Custom Search Engine", "category": "passive"},
            {"id": "social_mining", "name": "#8 Social Media Mining", "category": "passive"},
            {"id": "osint_feed", "name": "#9 OSINT Feed Integration", "category": "passive"},
            {"id": "tech_fingerprint", "name": "#11 Technology Fingerprinting", "category": "active"},
            {"id": "port_scan", "name": "#12 Port & Service Discovery", "category": "active"},
            {"id": "cloud_discovery", "name": "#13 Cloud Asset Discovery", "category": "active"},
        ],
        "total": 11,
    }


@router.post("/scan", response_model=SuccessResponse)
async def start_recon_scan(
    request: ReconScanRequest,
    db: DbSession,
    user: CurrentUser,
) -> SuccessResponse:
    """Start a reconnaissance scan on a target."""
    logger.info(
        "api.recon.scan.start",
        target=request.target,
        modules=request.modules,
        user=user["user_id"],
    )

    task_ids = []

    if "all" in request.modules:
        # Run full recon
        task = await run_full_recon.kiq(request.target)
        task_ids.append({"module": "full_recon", "task_id": str(task.task_id)})
    else:
        # Run selected modules
        for module_name in request.modules:
            task_fn = MODULE_TASK_MAP.get(module_name)
            if task_fn:
                task = await task_fn.kiq(request.target, request.config)
                task_ids.append({"module": module_name, "task_id": str(task.task_id)})
            else:
                logger.warning("api.recon.unknown_module", module=module_name)

    if not task_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No valid modules specified",
        )

    return SuccessResponse(
        message=f"Recon scan started on {request.target}",
        data={"tasks": task_ids, "target": request.target, "modules_queued": len(task_ids)},
    )


@router.post("/scan/instant", tags=["Reconnaissance"])
async def instant_recon_scan(
    request: ReconScanRequest,
    user: CurrentUser,
) -> dict:
    """Run recon modules instantly (blocking) — useful for single-module quick checks."""
    orchestrator = ReconOrchestrator()
    try:
        if "all" in request.modules:
            return await orchestrator.run_full_recon(request.target)
        elif len(request.modules) == 1:
            return await orchestrator.run_module(request.modules[0], request.target, request.config)
        else:
            return await orchestrator.run_full_recon(request.target, modules=request.modules)
    finally:
        await orchestrator.close()


@router.post("/passive", tags=["Reconnaissance"])
async def run_passive_recon(
    request: ReconScanRequest,
    db: DbSession,
    user: CurrentUser,
) -> dict:
    """Run passive recon and persist results."""
    repo = ScanRepository(db)

    # Create scan record
    scan = await repo.create_scan(
        target=request.target,
        scan_type="recon",
        config={"modules": request.modules, "mode": "passive"},
    )

    orchestrator = ReconOrchestrator()
    try:
        if "all" in request.modules:
            results = await orchestrator.run_full_recon(request.target)
        elif len(request.modules) == 1:
            results = await orchestrator.run_module(request.modules[0], request.target, request.config)
        else:
            results = await orchestrator.run_full_recon(request.target, modules=request.modules)

        # Extract any findings and persist them
        findings = results.get("findings") or results.get("vulnerabilities") or []
        if findings:
            await repo.add_vulnerabilities(scan.id, findings)

        await repo.complete_scan(scan.id, result_summary={
            "modules_run": request.modules,
            "findings_count": len(findings),
        })

        # Attach scan_id to response for frontend cross-reference
        results["scan_id"] = scan.id
        return results

    except Exception as e:
        await repo.complete_scan(scan.id, result_summary={}, error=str(e))
        raise
    finally:
        await orchestrator.close()


@router.post("/report", tags=["Reconnaissance"], response_model=None)
async def generate_recon_report(
    request: ReconScanRequest,
    user: CurrentUser,
    fmt: str = "json",
):
    """Run full recon and generate a report."""
    orchestrator = ReconOrchestrator()
    try:
        results = await orchestrator.run_full_recon(request.target, modules=request.modules)
        report = orchestrator.generate_report(request.target, results, fmt=fmt)

        if fmt == "html":
            return HTMLResponse(content=report)
        return report
    finally:
        await orchestrator.close()


@router.get("/results", tags=["Reconnaissance"])
async def list_recon_results(
    db: DbSession,
    user: CurrentUser,
    target: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> dict:
    """List recon scan results from database."""
    repo = ScanRepository(db)
    items, total = await repo.list_scans(
        scan_type="recon", target=target, limit=limit, offset=offset
    )
    return {
        "items": [
            {
                "id": s.id,
                "target": s.target,
                "status": s.status,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "finished_at": s.finished_at.isoformat() if s.finished_at else None,
                "result_summary": s.result_summary,
            }
            for s in items
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/results/{scan_id}", tags=["Reconnaissance"])
async def get_recon_result(
    scan_id: int,
    db: DbSession,
    user: CurrentUser,
) -> dict:
    """Get a specific recon scan result."""
    repo = ScanRepository(db)
    scan = await repo.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return {
        "id": scan.id,
        "target": scan.target,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "config": scan.config,
        "result_summary": scan.result_summary,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "error_message": scan.error_message,
        "vulnerabilities": [
            {
                "id": v.id,
                "title": v.title,
                "severity": v.severity,
                "cvss": v.cvss,
                "description": v.description,
            }
            for v in (scan.vulnerabilities or [])
        ],
    }
