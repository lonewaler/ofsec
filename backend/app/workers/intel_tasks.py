"""
OfSec V3 — Threat Intelligence Worker Tasks
=============================================
Taskiq background tasks for automated IOC ingestion from:
  - AlienVault OTX  (pulses → domains, IPs, hashes, URLs)
  - VirusTotal      (recent malicious IPs/domains)
  - AbuseIPDB       (top reported abusive IPs)

Results are persisted to threat_iocs via IOCRepository.
High-confidence IOCs trigger alerts via the notification dispatcher.
"""

import asyncio
from datetime import UTC, datetime

import httpx
import structlog

from app.config import settings
from app.repositories import IOCRepository
from app.workers.db_utils import worker_db_session
from app.workers.taskiq_app import broker

logger = structlog.get_logger()

# Minimum confidence to store (0.0–1.0)
MIN_CONFIDENCE = 0.5
# Confidence above which an alert fires
ALERT_CONFIDENCE = 0.85


# ─── Source: AlienVault OTX ──────────────────────────────────────────

async def _fetch_otx_pulses(client: httpx.AsyncClient) -> list[dict]:
    """
    Fetch the most recent OTX pulses from the subscribed feed.
    Returns a flat list of normalised IOC dicts.
    """
    if not settings.OTX_API_KEY:
        logger.warning("intel.otx.skipped", reason="OTX_API_KEY not configured")
        return []

    iocs: list[dict] = []
    try:
        resp = await client.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            headers={"X-OTX-API-KEY": settings.OTX_API_KEY},
            params={"limit": 20, "page": 1},
            timeout=30.0,
        )
        resp.raise_for_status()
        pulses = resp.json().get("results", [])

        for pulse in pulses:
            pulse_name = pulse.get("name", "OTX Pulse")
            tags = pulse.get("tags", [])
            for indicator in pulse.get("indicators", []):
                ioc_type = _normalise_otx_type(indicator.get("type", ""))
                if not ioc_type:
                    continue
                iocs.append({
                    "ioc_type": ioc_type,
                    "value": indicator.get("indicator", ""),
                    "source": "otx",
                    "confidence": 0.75,
                    "tags": tags[:5],
                    "metadata": {
                        "pulse": pulse_name,
                        "otx_id": indicator.get("id"),
                        "description": indicator.get("description", ""),
                    },
                })
        logger.info("intel.otx.fetched", pulses=len(pulses), iocs=len(iocs))
    except Exception as e:
        logger.error("intel.otx.error", error=str(e))

    return iocs


def _normalise_otx_type(otx_type: str) -> str | None:
    """Map OTX indicator types to our ioc_type enum."""
    mapping = {
        "IPv4": "ip",
        "IPv6": "ip",
        "domain": "domain",
        "hostname": "domain",
        "URL": "url",
        "URI": "url",
        "FileHash-MD5": "hash",
        "FileHash-SHA1": "hash",
        "FileHash-SHA256": "hash",
        "email": "email",
        "CVE": "cve",
    }
    return mapping.get(otx_type)


# ─── Source: AbuseIPDB ───────────────────────────────────────────────

async def _fetch_abuseipdb(client: httpx.AsyncClient) -> list[dict]:
    """Fetch top 100 most-reported IPs from AbuseIPDB blacklist."""
    if not settings.ABUSEIPDB_API_KEY:
        logger.warning("intel.abuseipdb.skipped", reason="ABUSEIPDB_API_KEY not configured")
        return []

    iocs: list[dict] = []
    try:
        resp = await client.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers={
                "Key": settings.ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            params={"confidenceMinimum": 90, "limit": 100},
            timeout=30.0,
        )
        resp.raise_for_status()
        for entry in resp.json().get("data", []):
            score = entry.get("abuseConfidenceScore", 0)
            iocs.append({
                "ioc_type": "ip",
                "value": entry.get("ipAddress", ""),
                "source": "abuseipdb",
                "confidence": round(score / 100, 2),
                "tags": [entry.get("countryCode", ""), "blacklist"],
                "metadata": {
                    "abuse_score": score,
                    "total_reports": entry.get("totalReports", 0),
                    "last_reported": entry.get("lastReportedAt", ""),
                },
            })
        logger.info("intel.abuseipdb.fetched", iocs=len(iocs))
    except Exception as e:
        logger.error("intel.abuseipdb.error", error=str(e))

    return iocs


# ─── Source: VirusTotal ──────────────────────────────────────────────

async def _fetch_virustotal(client: httpx.AsyncClient) -> list[dict]:
    """
    Query VT for recently-detected malicious files/URLs.
    Uses the free-tier /feeds/files endpoint (last 24h detections).
    """
    if not settings.VIRUSTOTAL_API_KEY:
        logger.warning("intel.virustotal.skipped", reason="VIRUSTOTAL_API_KEY not configured")
        return []

    iocs: list[dict] = []
    try:
        resp = await client.get(
            "https://www.virustotal.com/api/v3/feeds/files",
            headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            params={"filter": "p:5+", "limit": 25},
            timeout=30.0,
        )
        if resp.status_code == 200:
            for item in resp.json().get("data", []):
                attrs = item.get("attributes", {})
                sha256 = attrs.get("sha256", "")
                if not sha256:
                    continue
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) or 1
                confidence = round(min(malicious / total, 1.0), 2)
                if confidence < MIN_CONFIDENCE:
                    continue
                iocs.append({
                    "ioc_type": "hash",
                    "value": sha256,
                    "source": "virustotal",
                    "confidence": confidence,
                    "tags": attrs.get("type_tags", [])[:5],
                    "metadata": {
                        "malicious_detections": malicious,
                        "meaningful_name": attrs.get("meaningful_name", ""),
                        "type_description": attrs.get("type_description", ""),
                    },
                })
        logger.info("intel.virustotal.fetched", iocs=len(iocs))
    except Exception as e:
        logger.error("intel.virustotal.error", error=str(e))

    return iocs


# ─── Sweep Task ──────────────────────────────────────────────────────

@broker.task
async def run_threat_intel_sweep() -> dict:
    """
    Master IOC ingestion sweep — runs all configured sources,
    deduplicates via IOCRepository.upsert_ioc, fires alerts
    for any high-confidence new IOCs.
    """
    started = datetime.now(UTC)
    logger.info("intel.sweep.start")

    async with httpx.AsyncClient(timeout=30.0) as client:
        results = await asyncio.gather(
            _fetch_otx_pulses(client),
            _fetch_abuseipdb(client),
            _fetch_virustotal(client),
            return_exceptions=True,
        )

    # Flatten, skip any source that threw
    all_iocs: list[dict] = []
    for r in results:
        if isinstance(r, list):
            all_iocs.extend(r)
        elif isinstance(r, Exception):
            logger.error("intel.sweep.source_error", error=str(r))

    # Filter empty values
    all_iocs = [i for i in all_iocs if i.get("value", "").strip()]

    if not all_iocs:
        logger.warning("intel.sweep.no_iocs")
        return {"ingested": 0, "sources": 0, "elapsed_seconds": 0}

    # Persist and count new vs. updated
    new_count = 0
    updated_count = 0
    high_confidence_new: list[dict] = []

    async with worker_db_session() as db:
        repo = IOCRepository(db)
        for ioc in all_iocs:
            try:
                result = await repo.upsert_ioc(
                    ioc_type=ioc["ioc_type"],
                    value=ioc["value"],
                    source=ioc["source"],
                    confidence=ioc.get("confidence", MIN_CONFIDENCE),
                    tags=ioc.get("tags", []),
                    metadata=ioc.get("metadata", {}),
                )
                # Determine if it was newly created
                is_new = (
                    abs((result.last_seen - result.first_seen).total_seconds()) < 2
                )
                if is_new:
                    new_count += 1
                    if ioc.get("confidence", 0) >= ALERT_CONFIDENCE:
                        high_confidence_new.append(ioc)
                else:
                    updated_count += 1
            except Exception as e:
                logger.error("intel.sweep.upsert_error", value=ioc.get("value"), error=str(e))

    elapsed = round((datetime.now(UTC) - started).total_seconds(), 1)
    logger.info(
        "intel.sweep.complete",
        total=len(all_iocs),
        new=new_count,
        updated=updated_count,
        high_confidence=len(high_confidence_new),
        elapsed=elapsed,
    )

    # Fire alerts for high-confidence new IOCs (Feature 3 dispatcher)
    if high_confidence_new:
        try:
            from app.core.notifier import dispatch_alert
            await dispatch_alert(
                title=f"Threat Intel: {len(high_confidence_new)} high-confidence IOC(s) detected",
                message=_format_ioc_summary(high_confidence_new),
                severity="high",
            )
        except Exception as e:
            logger.error("intel.sweep.alert_failed", error=str(e))

    return {
        "total_fetched": len(all_iocs),
        "new": new_count,
        "updated": updated_count,
        "high_confidence_alerts": len(high_confidence_new),
        "elapsed_seconds": elapsed,
        "sources_queried": ["otx", "abuseipdb", "virustotal"],
    }


def _format_ioc_summary(iocs: list[dict]) -> str:
    lines = ["High-confidence threat indicators ingested:"]
    for ioc in iocs[:10]:
        lines.append(
            f"  [{ioc['ioc_type'].upper()}] {ioc['value']} "
            f"(source: {ioc['source']}, confidence: {ioc['confidence']:.0%})"
        )
    if len(iocs) > 10:
        lines.append(f"  ... and {len(iocs) - 10} more")
    return "\n".join(lines)
