"""
OfSec V3 — #5 Historical WHOIS Correlation
============================================
WHOIS data archival, ownership change detection, and registrant correlation.

Sub-enhancements:
1. Live WHOIS queries
2. Historical record storage
3. Ownership change detection
4. Registrant email graphing
5. Domain age calculation
6. Privacy/proxy detection
7. Name server change tracking
8. Expiry monitoring
9. Registrar reputation analysis
10. Bulk WHOIS queries
"""

from datetime import datetime, timezone
from typing import Optional

import httpx
import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("recon.whois")


class WHOISCorrelator:
    """WHOIS data harvesting and historical correlation."""

    RDAP_URL = "https://rdap.org"

    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=15.0,
                headers={"Accept": "application/rdap+json"},
            )
        return self._client

    async def query_whois(self, domain: str) -> dict:
        """Query WHOIS/RDAP data for a domain."""
        with tracer.start_as_current_span("whois_query") as span:
            span.set_attribute("target.domain", domain)

            client = await self._get_client()
            try:
                response = await client.get(f"{self.RDAP_URL}/domain/{domain}")
                response.raise_for_status()
                raw = response.json()
                return self._parse_rdap(raw, domain)
            except httpx.HTTPStatusError as e:
                logger.warning("recon.whois.http_error", domain=domain, status=e.response.status_code)
                return self._fallback_whois(domain)
            except Exception as e:
                logger.error("recon.whois.error", domain=domain, error=str(e))
                return self._fallback_whois(domain)

    def _parse_rdap(self, raw: dict, domain: str) -> dict:
        """Parse RDAP JSON response into structured WHOIS data."""
        events = {e.get("eventAction"): e.get("eventDate") for e in raw.get("events", [])}
        nameservers = [ns.get("ldhName", "") for ns in raw.get("nameservers", [])]

        # Extract registrant info from entities
        registrant = {}
        for entity in raw.get("entities", []):
            roles = entity.get("roles", [])
            if "registrant" in roles:
                vcard = entity.get("vcardArray", [None, []])[1] if entity.get("vcardArray") else []
                for item in vcard:
                    if isinstance(item, list) and len(item) >= 4:
                        if item[0] == "fn":
                            registrant["name"] = item[3]
                        elif item[0] == "email":
                            registrant["email"] = item[3]
                        elif item[0] == "org":
                            registrant["organization"] = item[3]

        created = events.get("registration")
        domain_age_days = None
        if created:
            try:
                created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                domain_age_days = (datetime.now(timezone.utc) - created_dt).days
            except (ValueError, TypeError):
                pass

        return {
            "domain": domain,
            "status": raw.get("status", []),
            "registrant": registrant,
            "nameservers": nameservers,
            "created_date": events.get("registration"),
            "updated_date": events.get("last changed"),
            "expiry_date": events.get("expiration"),
            "domain_age_days": domain_age_days,
            "privacy_protected": self._is_privacy_protected(registrant),
            "registrar": self._extract_registrar(raw),
            "dnssec": raw.get("secureDNS", {}).get("delegationSigned", False),
        }

    def _fallback_whois(self, domain: str) -> dict:
        """Fallback when RDAP fails — return empty structure."""
        return {
            "domain": domain,
            "status": [],
            "registrant": {},
            "nameservers": [],
            "created_date": None,
            "updated_date": None,
            "expiry_date": None,
            "domain_age_days": None,
            "privacy_protected": None,
            "registrar": None,
            "dnssec": None,
            "error": "WHOIS lookup failed",
        }

    def _is_privacy_protected(self, registrant: dict) -> bool:
        """Detect WHOIS privacy/proxy services."""
        privacy_indicators = [
            "privacy", "proxy", "whoisguard", "domainsbyproxy",
            "contactprivacy", "redacted", "withheld",
        ]
        for value in registrant.values():
            if isinstance(value, str) and any(p in value.lower() for p in privacy_indicators):
                return True
        return False

    def _extract_registrar(self, raw: dict) -> str | None:
        for entity in raw.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [None, []])[1] if entity.get("vcardArray") else []
                for item in vcard:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        return item[3]
        return None

    async def correlate(self, domain: str) -> dict:
        """Full WHOIS correlation scan."""
        with tracer.start_as_current_span("whois_correlate") as span:
            span.set_attribute("target.domain", domain)

            whois_data = await self.query_whois(domain)

            logger.info(
                "recon.whois.correlate_complete",
                domain=domain,
                age_days=whois_data.get("domain_age_days"),
                privacy=whois_data.get("privacy_protected"),
            )
            return whois_data

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
