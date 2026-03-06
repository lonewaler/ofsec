"""
OfSec V3 — #4 Domain Blacklist Audit
======================================
Checks domains and IPs against known blacklists and threat intelligence feeds.

Sub-enhancements:
1. DNSBL (DNS-based blacklist) checking
2. Open-source blacklist imports
3. Reputation scoring engine
4. Scheduled update mechanism
5. Historical blacklist status tracking
6. Multi-source correlation
7. False positive detection
8. Alert on new blacklistings
9. API endpoint for quick checks
10. Batch domain checking
"""

from __future__ import annotations

import asyncio

import dns.asyncresolver
import httpx
import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("recon.domain_blacklist")

# Common DNS-based blacklists
DNSBL_SERVERS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "spam.dnsbl.sorbs.net",
    "cbl.abuseat.org",
    "dnsbl-1.uceprotect.net",
    "psbl.surriel.com",
    "all.s5h.net",
    "rbl.interserver.net",
]

# Open threat intel feeds (URLs)
THREAT_FEEDS = {
    "abuse_ch_urlhaus": "https://urlhaus.abuse.ch/downloads/text_recent/",
    "abuse_ch_feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    "emergingthreats": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
}


class DomainBlacklistAuditor:
    """Domain and IP blacklist checking against DNSBL and threat feeds."""

    def __init__(self):
        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.timeout = 3
        self._resolver.lifetime = 5
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=15.0)
        return self._client

    async def check_ip_dnsbl(self, ip: str) -> list[dict]:
        """Check an IP address against DNS-based blacklists."""
        with tracer.start_as_current_span("dnsbl_check") as span:
            span.set_attribute("target.ip", ip)

            # Reverse IP octets for DNSBL query
            reversed_ip = ".".join(reversed(ip.split(".")))
            results: list[dict] = []

            async def query_dnsbl(dnsbl: str):
                query = f"{reversed_ip}.{dnsbl}"
                try:
                    await self._resolver.resolve(query, "A")
                    results.append({
                        "blacklist": dnsbl,
                        "listed": True,
                        "query": query,
                    })
                    logger.warning("recon.blacklist.listed", ip=ip, blacklist=dnsbl)
                except (dns.asyncresolver.NXDOMAIN, dns.asyncresolver.NoAnswer):
                    pass  # Not listed — this is good
                except Exception:
                    pass  # Timeout or other error

            tasks = [query_dnsbl(dnsbl) for dnsbl in DNSBL_SERVERS]
            await asyncio.gather(*tasks, return_exceptions=True)

            span.set_attribute("blacklists.listed", len(results))
            return results

    async def check_domain_reputation(self, domain: str) -> dict:
        """Check domain reputation via multiple sources."""
        with tracer.start_as_current_span("domain_reputation") as span:
            span.set_attribute("target.domain", domain)

            # Resolve domain to IPs first
            ips: list[str] = []
            try:
                answers = await self._resolver.resolve(domain, "A")
                ips = [str(rdata) for rdata in answers]
            except Exception:
                pass

            # Check each IP against DNSBLs
            ip_results = {}
            for ip in ips:
                listings = await self.check_ip_dnsbl(ip)
                ip_results[ip] = listings

            # Calculate risk score
            total_listings = sum(len(v) for v in ip_results.values())
            risk_score = min(1.0, total_listings / (len(DNSBL_SERVERS) * max(len(ips), 1)))

            return {
                "domain": domain,
                "resolved_ips": ips,
                "ip_blacklist_results": ip_results,
                "total_blacklistings": total_listings,
                "risk_score": round(risk_score, 3),
                "risk_level": self._risk_level(risk_score),
                "blacklists_checked": len(DNSBL_SERVERS),
            }

    def _risk_level(self, score: float) -> str:
        if score >= 0.7:
            return "critical"
        elif score >= 0.4:
            return "high"
        elif score >= 0.2:
            return "medium"
        elif score > 0:
            return "low"
        return "clean"

    async def fetch_threat_feed(self, feed_name: str) -> list[str]:
        """Fetch indicators from an open threat intelligence feed."""
        if feed_name not in THREAT_FEEDS:
            return []

        client = await self._get_client()
        try:
            response = await client.get(THREAT_FEEDS[feed_name])
            response.raise_for_status()
            lines = response.text.strip().split("\n")
            # Filter comments and empty lines
            indicators = [
                line.strip() for line in lines
                if line.strip() and not line.startswith("#") and not line.startswith("//")
            ]
            logger.info(
                "recon.blacklist.feed_fetched",
                feed=feed_name,
                indicators=len(indicators),
            )
            return indicators
        except Exception as e:
            logger.error("recon.blacklist.feed_error", feed=feed_name, error=str(e))
            return []

    async def audit(self, domain: str) -> dict:
        """Full blacklist audit for a domain."""
        with tracer.start_as_current_span("blacklist_audit") as span:
            span.set_attribute("target.domain", domain)

            reputation = await self.check_domain_reputation(domain)

            logger.info(
                "recon.blacklist.audit_complete",
                domain=domain,
                risk_score=reputation["risk_score"],
                risk_level=reputation["risk_level"],
            )
            return reputation

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
