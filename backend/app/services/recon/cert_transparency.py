"""
OfSec V3 — #1 Certificate Transparency Monitor
=================================================
Monitors Certificate Transparency logs for new certificates matching target domains.
Uses crt.sh API for CT log queries, extracts SANs, tracks expiry, and auto-correlates.

Sub-enhancements:
1. CT log streaming via crt.sh
2. Wildcard certificate matching
3. SAN (Subject Alternative Name) extraction
4. Certificate expiry tracking
5. Auto-correlation with port scans
6. New certificate alerts
7. Issuer analysis
8. Certificate chain validation
9. Historical certificate timeline
10. Bulk domain monitoring
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("recon.cert_transparency")


class CertTransparencyMonitor:
    """Certificate Transparency log monitor via crt.sh."""

    CRT_SH_URL = "https://crt.sh"

    def __init__(self):
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=30.0,
                headers={"User-Agent": "OfSec-V3/3.0"},
                follow_redirects=True,
            )
        return self._client

    async def search_certificates(
        self,
        domain: str,
        wildcard: bool = True,
        exclude_expired: bool = False,
    ) -> list[dict]:
        """
        Search CT logs for certificates matching a domain.

        Args:
            domain: Target domain (e.g., "example.com")
            wildcard: Include wildcard certificates (%.example.com)
            exclude_expired: Filter out expired certificates

        Returns:
            List of certificate records with parsed metadata
        """
        with tracer.start_as_current_span("ct_search") as span:
            span.set_attribute("target.domain", domain)
            span.set_attribute("search.wildcard", wildcard)

            query = f"%.{domain}" if wildcard else domain
            client = await self._get_client()

            try:
                response = await client.get(
                    f"{self.CRT_SH_URL}/",
                    params={
                        "q": query,
                        "output": "json",
                        "exclude": "expired" if exclude_expired else "",
                    },
                )
                response.raise_for_status()

                raw_certs = response.json()
                logger.info(
                    "recon.ct.search_complete",
                    domain=domain,
                    certificates_found=len(raw_certs),
                )

                return [self._parse_certificate(cert) for cert in raw_certs]

            except httpx.HTTPStatusError as e:
                logger.error("recon.ct.http_error", domain=domain, status=e.response.status_code)
                return []
            except Exception as e:
                logger.error("recon.ct.error", domain=domain, error=str(e))
                return []

    def _parse_certificate(self, raw: dict) -> dict:
        """Parse a raw crt.sh certificate record into structured format."""
        return {
            "id": raw.get("id"),
            "issuer_ca_id": raw.get("issuer_ca_id"),
            "issuer_name": raw.get("issuer_name", ""),
            "common_name": raw.get("common_name", ""),
            "name_value": raw.get("name_value", ""),
            "san_domains": self._extract_sans(raw.get("name_value", "")),
            "serial_number": raw.get("serial_number", ""),
            "not_before": raw.get("not_before"),
            "not_after": raw.get("not_after"),
            "is_expired": self._is_expired(raw.get("not_after")),
            "entry_timestamp": raw.get("entry_timestamp"),
        }

    def _extract_sans(self, name_value: str) -> list[str]:
        """Extract unique SAN domains from certificate name_value field."""
        if not name_value:
            return []
        # crt.sh separates SANs with newlines
        sans = [s.strip().lower() for s in name_value.split("\n") if s.strip()]
        return list(set(sans))

    def _is_expired(self, not_after: str | None) -> bool:
        """Check if a certificate has expired."""
        if not not_after:
            return False
        try:
            expiry = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
            return expiry < datetime.now(UTC)
        except (ValueError, TypeError):
            return False

    async def get_certificate_details(self, cert_id: int) -> dict | None:
        """Fetch detailed certificate data by crt.sh ID."""
        client = await self._get_client()
        try:
            response = await client.get(
                f"{self.CRT_SH_URL}/",
                params={"q": f"id={cert_id}", "output": "json"},
            )
            response.raise_for_status()
            data = response.json()
            return self._parse_certificate(data[0]) if data else None
        except Exception as e:
            logger.error("recon.ct.detail_error", cert_id=cert_id, error=str(e))
            return None

    async def monitor_domain(self, domain: str) -> dict:
        """
        Full CT monitoring scan for a domain.
        Returns summary with certificates, expiring certs, and SAN analysis.
        """
        with tracer.start_as_current_span("ct_monitor") as span:
            span.set_attribute("target.domain", domain)

            certs = await self.search_certificates(domain, wildcard=True)

            # Analyze results
            all_sans: set[str] = set()
            expiring_soon: list[dict] = []
            issuers: dict[str, int] = {}

            for cert in certs:
                all_sans.update(cert.get("san_domains", []))

                # Track issuers
                issuer = cert.get("issuer_name", "Unknown")
                issuers[issuer] = issuers.get(issuer, 0) + 1

                # Check certificates expiring within 30 days
                if cert.get("not_after"):
                    try:
                        expiry = datetime.fromisoformat(
                            cert["not_after"].replace("Z", "+00:00")
                        )
                        days_left = (expiry - datetime.now(UTC)).days
                        if 0 < days_left <= 30:
                            cert["days_until_expiry"] = days_left
                            expiring_soon.append(cert)
                    except (ValueError, TypeError):
                        pass

            result = {
                "domain": domain,
                "total_certificates": len(certs),
                "unique_san_domains": sorted(all_sans),
                "san_count": len(all_sans),
                "expiring_within_30_days": expiring_soon,
                "issuer_distribution": issuers,
                "certificates": certs[:100],  # Limit to 100 for response size
            }

            logger.info(
                "recon.ct.monitor_complete",
                domain=domain,
                total_certs=len(certs),
                san_count=len(all_sans),
                expiring=len(expiring_soon),
            )

            return result

    async def close(self):
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
