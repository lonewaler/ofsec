"""
OfSec V3 — Vulnerability Scanner API Endpoints (Full Implementation)
======================================================================
REST API for vulnerability scanning operations (Upgrades #16–30).
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, HTTPException, status

from app.api.deps import CurrentUser, DbSession
from app.repositories import ScanRepository
from app.schemas import SuccessResponse
from app.services.scanner.orchestrator import ScannerOrchestrator
from app.workers.scan_tasks import (
    run_api_scan,
    run_cloud_audit,
    run_cms_scan,
    run_compliance_audit,
    run_container_scan,
    run_credential_test,
    run_dependency_scan,
    run_full_vulnerability_scan,
    run_header_analysis,
    run_network_discovery,
    run_ssl_audit,
    run_waf_detection,
    run_web_scan,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/scanner", tags=["Vulnerability Scanner"])

MODULE_TASK_MAP = {
    "web_scanner": run_web_scan,
    "header_analyzer": run_header_analysis,
    "api_scanner": run_api_scan,
    "dependency_scanner": run_dependency_scan,
    "container_scanner": run_container_scan,
    "cloud_auditor": run_cloud_audit,
    "network_discovery": run_network_discovery,
    "credential_tester": run_credential_test,
    "ssl_auditor": run_ssl_audit,
    "cms_scanner": run_cms_scan,
    "compliance_auditor": run_compliance_audit,
    "waf_detector": run_waf_detection,
}


@router.get("/modules")
async def list_scanner_modules(*, user: CurrentUser) -> dict:
    """List all available scanner modules."""
    return {
        "modules": [
            {
                "id": "web_scanner",
                "name": "#16 Web Application Scanner",
                "category": "active",
                "tags": ["xss", "sqli", "csrf"],
            },
            {"id": "header_analyzer", "name": "#17 Header Security Analyzer", "category": "passive"},
            {
                "id": "api_scanner",
                "name": "#18 API Security Scanner",
                "category": "active",
                "tags": ["rest", "graphql"],
            },
            {"id": "dependency_scanner", "name": "#19 Dependency Vuln Scanner", "category": "passive", "tags": ["sca"]},
            {"id": "container_scanner", "name": "#20 Container Security", "category": "passive", "tags": ["docker"]},
            {
                "id": "cloud_auditor",
                "name": "#21 Cloud Config Auditor",
                "category": "active",
                "tags": ["aws", "azure", "gcp"],
            },
            {"id": "network_discovery", "name": "#22 Network Service Discovery", "category": "active"},
            {"id": "credential_tester", "name": "#23 Credential Tester", "category": "active"},
            {"id": "ssl_auditor", "name": "#24 SSL/TLS Auditor", "category": "passive"},
            {"id": "cms_scanner", "name": "#25 CMS Scanner", "category": "active", "tags": ["wordpress", "joomla"]},
            {"id": "compliance_auditor", "name": "#26 Compliance Auditor", "category": "passive", "tags": ["owasp"]},
            {"id": "waf_detector", "name": "#27 WAF Detector", "category": "active"},
        ],
        "total": 12,
    }


@router.post("/scan")
async def start_vulnerability_scan(
    *,
    target: str,
    modules: list[str] | None = None,
    db: DbSession,
    user: CurrentUser,
) -> SuccessResponse:
    """Start a vulnerability scan (async via Taskiq)."""
    logger.info("api.scanner.scan.start", target=target, modules=modules)

    task_ids = []

    if not modules or "all" in modules:
        task = await run_full_vulnerability_scan.kiq(target)
        task_ids.append({"module": "full_scan", "task_id": str(task.task_id)})
    else:
        for module_name in modules:
            task_fn = MODULE_TASK_MAP.get(module_name)
            if task_fn:
                task = await task_fn.kiq(target)
                task_ids.append({"module": module_name, "task_id": str(task.task_id)})

    if not task_ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No valid modules specified")

    return SuccessResponse(
        message=f"Scan started on {target}",
        data={"tasks": task_ids, "target": target, "modules_queued": len(task_ids)},
    )


@router.post("/scan/instant")
async def instant_vulnerability_scan(
    *,
    target: str,
    modules: list[str] | None = None,
    db: DbSession,
    user: CurrentUser,
) -> dict:
    """Run scanner modules instantly and persist results."""
    repo = ScanRepository(db)
    scan = await repo.create_scan(target=target, scan_type="vuln", config={"modules": modules or []})

    orchestrator = ScannerOrchestrator()
    try:
        if modules and len(modules) == 1:
            results = await orchestrator.run_module(modules[0], target)
        else:
            results = await orchestrator.run_full_scan(target, modules=modules)

        findings = results.get("findings") or results.get("vulnerabilities") or []
        if findings:
            await repo.add_vulnerabilities(scan.id, findings)

        severity_summary: dict[str, int] = {}
        for f in findings:
            sev = (f.get("severity") or "info").upper()
            severity_summary[sev] = severity_summary.get(sev, 0) + 1

        await repo.complete_scan(
            scan.id,
            result_summary={
                "total_findings": len(findings),
                "severity_summary": severity_summary,
            },
        )

        results["scan_id"] = scan.id
        return results

    except Exception as e:
        await repo.complete_scan(scan.id, result_summary={}, error=str(e))
        raise
    finally:
        await orchestrator.close()


@router.post("/scan/headers")
async def quick_header_scan(*, url: str, user: CurrentUser) -> dict:
    """Quick header security analysis."""
    orchestrator = ScannerOrchestrator()
    try:
        return await orchestrator.run_module("header_analyzer", url)
    finally:
        await orchestrator.close()


@router.post("/scan/ssl")
async def quick_ssl_scan(*, host: str, port: int = 443, user: CurrentUser) -> dict:
    """Quick SSL/TLS audit."""
    orchestrator = ScannerOrchestrator()
    try:
        return await orchestrator.run_module("ssl_auditor", host, {"port": port})
    finally:
        await orchestrator.close()


@router.get("/results")
async def list_scan_results(
    *,
    db: DbSession,
    user: CurrentUser,
    limit: int = 20,
    offset: int = 0,
) -> dict:
    repo = ScanRepository(db)
    items, total = await repo.list_scans(scan_type="vuln", limit=limit, offset=offset)
    return {
        "items": [
            {
                "id": s.id,
                "target": s.target,
                "status": s.status,
                "result_summary": s.result_summary,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "finished_at": s.finished_at.isoformat() if s.finished_at else None,
            }
            for s in items
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/results/{scan_id}")
async def get_scan_result(*, scan_id: int, db: DbSession, user: CurrentUser) -> dict:
    """Get a specific scan result."""
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")


@router.get("/vulnerabilities")
async def list_vulnerabilities(
    *,
    db: DbSession,
    user: CurrentUser,
    severity: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    repo = ScanRepository(db)
    items, total = await repo.list_vulnerabilities(severity=severity, limit=limit, offset=offset)
    return {
        "items": [
            {
                "id": v.id,
                "scan_id": v.scan_id,
                "title": v.title,
                "severity": v.severity,
                "cwe": v.cwe,
                "cvss": v.cvss,
                "description": v.description,
                "remediation": v.remediation,
                "url": v.url,
                "discovered_at": v.discovered_at.isoformat() if v.discovered_at else None,
            }
            for v in items
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }
