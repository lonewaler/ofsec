"""
OfSec V3 — Recon API Endpoints (Full Implementation)
======================================================
REST API for reconnaissance operations (Upgrades #1–15).
"""

from __future__ import annotations
import asyncio
import json
import json as _json

import structlog
import fastapi
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.responses import HTMLResponse, StreamingResponse

from app.api.deps import CurrentUser, DbSession
from app.config import settings
from app.core import stream_bus
from app.repositories import ScanRepository
from app.schemas import (
    ReconScanRequest,
    SuccessResponse,
)
from app.services.recon.orchestrator import ReconOrchestrator
from app.workers.recon_tasks import (
    run_cert_transparency_scan,
    run_cloud_discovery,
    run_domain_blacklist_audit,
    run_full_recon,
    run_osint_feed_scan,
    run_passive_dns_harvest,
    run_port_scan,
    run_search_engine_recon,
    run_social_mining,
    run_tech_fingerprint,
    run_web_archive_scrape,
    run_whois_correlation,
)

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
async def list_recon_modules(*, user: CurrentUser) -> dict:
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
async def start_recon_scan(*, 
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
async def instant_recon_scan(*, 
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
async def run_passive_recon(*, 
    request: ReconScanRequest,
    db: DbSession,
    user: CurrentUser,
    stream: bool = False,
) -> dict:
    """
    Run passive recon.
    - stream=false (default): blocks until complete, returns full JSON
    - stream=true: returns scan_id immediately; use GET /stream/{scan_id} for live events
    """
    repo = ScanRepository(db)

    scan = await repo.create_scan(
        target=request.target,
        scan_type="recon",
        config={"modules": request.modules, "mode": "passive"},
    )
    scan_id = str(scan.id)

    if stream:
        # Non-blocking: create the bus, kick off the scan in background, return scan_id
        stream_bus.create(scan_id)
        stream_bus.init_control(scan_id)
        asyncio.create_task(
            _run_recon_streaming(scan_id, request, repo)
        )
        return {
            "scan_id": scan.id,
            "status": "started",
            "stream_url": f"/api/v1/recon/stream/{scan_id}",
            "ws_url": f"/api/v1/recon/ws/{scan_id}",
        }

    # Blocking (existing behavior)
    orchestrator = ReconOrchestrator()
    try:
        if "all" in request.modules:
            results = await orchestrator.run_full_recon(request.target)
        elif len(request.modules) == 1:
            results = await orchestrator.run_module(request.modules[0], request.target, request.config)
        else:
            results = await orchestrator.run_full_recon(request.target, modules=request.modules)

        findings = results.get("findings") or results.get("vulnerabilities") or []
        if findings:
            await repo.add_vulnerabilities(scan.id, findings)

        await repo.complete_scan(scan.id, result_summary={
            "modules_run": request.modules,
            "findings_count": len(findings),
        })
        results["scan_id"] = scan.id
        return results

    except Exception as e:
        await repo.complete_scan(scan.id, result_summary={}, error=str(e))
        raise
    finally:
        await orchestrator.close()


async def _run_recon_streaming(*, 
    scan_id: str,
    request,
    repo,
) -> None:
    """
    Background coroutine — runs modules sequentially, publishes events to stream_bus.
    Checks for cancel/pause between each module.
    """
    orchestrator = ReconOrchestrator()
    all_findings: list[dict] = []
    modules = (
        request.modules
        if request.modules and "all" not in request.modules
        else list(getattr(orchestrator, 'MODULES', {}).keys()) or request.modules
    )

    try:
        for i, module_name in enumerate(modules):

            # Cancel check
            if stream_bus.is_cancelled(scan_id):
                await stream_bus.publish(scan_id, {
                    "type": "cancelled",
                    "scan_id": scan_id,
                    "modules_completed": i,
                    "findings_so_far": len(all_findings),
                })
                from app.repositories import ScanRepository as SR
                from app.workers.db_utils import worker_db_session
                async with worker_db_session() as db2:
                    await SR(db2).complete_scan(
                        int(scan_id),
                        result_summary={"cancelled_at_module": module_name},
                        error="Cancelled by user",
                    )
                return

            # Pause loop — 0.5s polling, exits on cancel or resume
            while stream_bus.is_paused(scan_id):
                await asyncio.sleep(0.5)
                if stream_bus.is_cancelled(scan_id):
                    break

            try:
                result = await orchestrator.run_module(module_name, request.target)
                findings = (
                    result.get("findings")
                    or result.get("vulnerabilities")
                    or []
                )
                all_findings.extend(findings)

                await stream_bus.publish(scan_id, {
                    "type": "module_complete",
                    "module": module_name,
                    "index": i + 1,
                    "total": len(modules),
                    "findings_count": len(findings),
                    "data": result,
                })

            except Exception as e:
                await stream_bus.publish(scan_id, {
                    "type": "module_error",
                    "module": module_name,
                    "error": str(e),
                })

        # Persist accumulated findings
        from app.repositories import ScanRepository as SR
        from app.workers.db_utils import worker_db_session
        async with worker_db_session() as db2:
            repo2 = SR(db2)
            if all_findings:
                await repo2.add_vulnerabilities(int(scan_id), all_findings)
            await repo2.complete_scan(
                int(scan_id),
                result_summary={
                    "modules_run": modules,
                    "findings_count": len(all_findings),
                },
            )

        await stream_bus.publish(scan_id, {
            "type": "done",
            "scan_id": scan_id,
            "total_findings": len(all_findings),
        })

    except Exception as e:
        await stream_bus.publish(scan_id, {"type": "error", "error": str(e)})

    finally:
        await stream_bus.close(scan_id)
        stream_bus.cleanup_control(scan_id)
        await orchestrator.close()


@router.get("/stream/{scan_id}", tags=["Reconnaissance"])
async def stream_scan_results(*, 
    scan_id: str,
    user: CurrentUser,
) -> StreamingResponse:
    """
    Server-Sent Events stream for a running scan.
    Connect with EventSource in the browser.
    Each event is a JSON-encoded module result.
    Stream closes automatically when the scan completes.
    """
    async def event_generator():
        async for event in stream_bus.subscribe(scan_id):
            yield f"data: {json.dumps(event)}\n\n"
        yield 'data: {"type": "stream_closed"}\n\n'

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.websocket("/ws/{scan_id}")
async def websocket_scan_stream(*, websocket: WebSocket, scan_id: str) -> None:
    """
    Bidirectional WebSocket for scan streaming + control.

    Auth: pass API key as query param ?token=<api_key>
    Server → Client: module_complete, module_error, ack, done, cancelled, error, ping
    Client → Server: {"action": "cancel"} | {"action": "pause"} | {"action": "resume"} | {"action": "ping"}
    """
    await websocket.accept()

    token = websocket.query_params.get("token", "")
    if token != settings.API_KEY:
        await websocket.send_json({"type": "error", "error": "Unauthorized"})
        await websocket.close(code=4001)
        return

    async def _forward_events() -> None:
        """Forward stream_bus events to WebSocket until done/cancelled/error."""
        async for event in stream_bus.subscribe(scan_id):
            try:
                await websocket.send_json(event)
                if event.get("type") in ("done", "cancelled", "error"):
                    break
            except Exception:
                break

    forward_task = asyncio.create_task(_forward_events())

    try:
        while True:
            try:
                raw = await asyncio.wait_for(
                    websocket.receive_text(), timeout=120.0
                )
                msg = _json.loads(raw)
                action = msg.get("action", "")

                if action == "cancel":
                    stream_bus.cancel(scan_id)
                    await websocket.send_json({
                        "type": "ack", "action": "cancel", "status": "cancelling"
                    })

                elif action == "pause":
                    stream_bus.pause(scan_id)
                    await websocket.send_json({
                        "type": "ack", "action": "pause", "status": "paused"
                    })

                elif action == "resume":
                    stream_bus.resume(scan_id)
                    await websocket.send_json({
                        "type": "ack", "action": "resume", "status": "running"
                    })

                elif action == "ping":
                    await websocket.send_json({"type": "pong"})

            except TimeoutError:
                await websocket.send_json({"type": "ping"})

    except WebSocketDisconnect:
        stream_bus.cancel(scan_id)     # tab closed = cancel the scan

    finally:
        forward_task.cancel()


@router.post("/report", tags=["Reconnaissance"], response_model=None)
async def generate_recon_report(*, 
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
async def list_recon_results(*, 
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
async def get_recon_result(*, 
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
