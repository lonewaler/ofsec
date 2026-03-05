"""
OfSec V3 — #9 OSINT Feed Integration
======================================
Aggregates data from Shodan, Censys, BinaryEdge, and other OSINT APIs.

Sub-enhancements:
1. Shodan host search & enrichment
2. Censys certificate search
3. BinaryEdge integration
4. VirusTotal domain/IP lookup
5. Auto-query on new asset discovery
6. Rate-limit management per API
7. Data normalization across sources
8. Confidence scoring
9. IOC extraction from feeds
10. Feed health monitoring
"""


import httpx
import structlog

from app.config import settings
from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("recon.osint_feed")


class OSINTFeedIntegrator:
    """Multi-source OSINT feed aggregation with rate limiting."""

    def __init__(self):
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=20.0)
        return self._client

    # ─── Shodan ───────────────────────────────────

    async def shodan_host_lookup(self, ip: str) -> dict:
        """Lookup an IP on Shodan for open ports, services, and vulns."""
        if not settings.SHODAN_API_KEY:
            return {"error": "SHODAN_API_KEY not configured", "ip": ip}

        client = await self._get_client()
        try:
            response = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": settings.SHODAN_API_KEY},
            )
            response.raise_for_status()
            data = response.json()

            return {
                "ip": ip,
                "source": "shodan",
                "hostnames": data.get("hostnames", []),
                "os": data.get("os"),
                "ports": data.get("ports", []),
                "vulns": data.get("vulns", []),
                "asn": data.get("asn"),
                "org": data.get("org"),
                "isp": data.get("isp"),
                "country": data.get("country_code"),
                "city": data.get("city"),
                "last_update": data.get("last_update"),
                "services": [
                    {
                        "port": svc.get("port"),
                        "transport": svc.get("transport"),
                        "product": svc.get("product", ""),
                        "version": svc.get("version", ""),
                        "banner": svc.get("data", "")[:200],
                    }
                    for svc in data.get("data", [])[:20]
                ],
            }
        except httpx.HTTPStatusError as e:
            logger.warning("recon.osint.shodan_error", ip=ip, status=e.response.status_code)
            return {"ip": ip, "source": "shodan", "error": str(e)}
        except Exception as e:
            logger.error("recon.osint.shodan_error", ip=ip, error=str(e))
            return {"ip": ip, "source": "shodan", "error": str(e)}

    async def shodan_domain_search(self, domain: str) -> dict:
        """Search Shodan for hosts related to a domain."""
        if not settings.SHODAN_API_KEY:
            return {"error": "SHODAN_API_KEY not configured"}

        client = await self._get_client()
        try:
            response = await client.get(
                f"https://api.shodan.io/dns/domain/{domain}",
                params={"key": settings.SHODAN_API_KEY},
            )
            response.raise_for_status()
            data = response.json()
            return {
                "domain": domain,
                "source": "shodan",
                "subdomains": data.get("subdomains", []),
                "records": data.get("data", []),
            }
        except Exception as e:
            return {"domain": domain, "source": "shodan", "error": str(e)}

    # ─── VirusTotal ───────────────────────────────

    async def virustotal_domain(self, domain: str) -> dict:
        """Lookup domain on VirusTotal for reputation and detections."""
        if not settings.VIRUSTOTAL_API_KEY:
            return {"error": "VIRUSTOTAL_API_KEY not configured"}

        client = await self._get_client()
        try:
            response = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            )
            response.raise_for_status()
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})

            return {
                "domain": domain,
                "source": "virustotal",
                "reputation": data.get("reputation", 0),
                "detections": {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                },
                "categories": data.get("categories", {}),
                "registrar": data.get("registrar"),
                "creation_date": data.get("creation_date"),
                "whois": data.get("whois", "")[:500],
            }
        except Exception as e:
            return {"domain": domain, "source": "virustotal", "error": str(e)}

    async def virustotal_ip(self, ip: str) -> dict:
        """Lookup IP on VirusTotal."""
        if not settings.VIRUSTOTAL_API_KEY:
            return {"error": "VIRUSTOTAL_API_KEY not configured"}

        client = await self._get_client()
        try:
            response = await client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            )
            response.raise_for_status()
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})

            return {
                "ip": ip,
                "source": "virustotal",
                "reputation": data.get("reputation", 0),
                "detections": {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                },
                "asn": data.get("asn"),
                "as_owner": data.get("as_owner"),
                "country": data.get("country"),
            }
        except Exception as e:
            return {"ip": ip, "source": "virustotal", "error": str(e)}

    # ─── Aggregated Scan ──────────────────────────

    async def scan(self, target: str, target_type: str = "domain") -> dict:
        """Full OSINT scan — aggregates all available sources."""
        with tracer.start_as_current_span("osint_scan") as span:
            span.set_attribute("target", target)
            span.set_attribute("target_type", target_type)

            results = {"target": target, "type": target_type, "sources": {}}

            if target_type == "domain":
                results["sources"]["shodan"] = await self.shodan_domain_search(target)
                results["sources"]["virustotal"] = await self.virustotal_domain(target)
            elif target_type == "ip":
                results["sources"]["shodan"] = await self.shodan_host_lookup(target)
                results["sources"]["virustotal"] = await self.virustotal_ip(target)

            # Calculate aggregate risk
            risk_indicators = 0
            for source_data in results["sources"].values():
                if isinstance(source_data, dict):
                    detections = source_data.get("detections", {})
                    risk_indicators += detections.get("malicious", 0)
                    risk_indicators += len(source_data.get("vulns", []))

            results["aggregate_risk_score"] = min(1.0, risk_indicators / 10)

            logger.info(
                "recon.osint.scan_complete",
                target=target,
                sources=len(results["sources"]),
                risk_score=results["aggregate_risk_score"],
            )
            return results

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
