"""
OfSec V3 — #6 Web Archive Scraper
===================================
Scrapes Wayback Machine for historical snapshots, detects changes, and extracts data.

Sub-enhancements:
1. Wayback Machine CDX API integration
2. Snapshot timeline generation
3. Keyword scanning across snapshots
4. Visual diff detection
5. Technology stack changes over time
6. URL discovery from archived pages
7. Sensitive file detection
8. robots.txt history
9. Sitemap history
10. JavaScript file archival
"""


import httpx
import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("recon.web_archive")


class WebArchiveScraper:
    """Wayback Machine scraper for historical domain intelligence."""

    CDX_API = "https://web.archive.org/cdx/search/cdx"
    WAYBACK_URL = "https://web.archive.org/web"

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

    async def get_snapshots(
        self, domain: str, limit: int = 100, from_date: str | None = None, to_date: str | None = None,
    ) -> list[dict]:
        """Fetch available snapshots from Wayback Machine CDX API."""
        with tracer.start_as_current_span("archive_snapshots") as span:
            span.set_attribute("target.domain", domain)

            client = await self._get_client()
            params = {
                "url": f"{domain}/*",
                "output": "json",
                "limit": str(limit),
                "fl": "timestamp,original,mimetype,statuscode,length",
                "collapse": "urlkey",
            }
            if from_date:
                params["from"] = from_date
            if to_date:
                params["to"] = to_date

            try:
                response = await client.get(self.CDX_API, params=params)
                response.raise_for_status()
                rows = response.json()

                if not rows or len(rows) < 2:
                    return []

                headers = rows[0]
                snapshots = []
                for row in rows[1:]:
                    record = dict(zip(headers, row))
                    record["archive_url"] = (
                        f"{self.WAYBACK_URL}/{record.get('timestamp')}/{record.get('original')}"
                    )
                    snapshots.append(record)

                logger.info("recon.archive.snapshots_found", domain=domain, count=len(snapshots))
                return snapshots

            except Exception as e:
                logger.error("recon.archive.error", domain=domain, error=str(e))
                return []

    async def get_robots_txt_history(self, domain: str) -> list[dict]:
        """Fetch historical robots.txt files from the archive."""
        client = await self._get_client()
        params = {
            "url": f"{domain}/robots.txt",
            "output": "json",
            "fl": "timestamp,statuscode",
            "limit": "20",
        }
        try:
            response = await client.get(self.CDX_API, params=params)
            response.raise_for_status()
            rows = response.json()
            if not rows or len(rows) < 2:
                return []
            headers = rows[0]
            return [dict(zip(headers, row)) for row in rows[1:]]
        except Exception:
            return []

    async def find_sensitive_files(self, domain: str) -> list[dict]:
        """Search archive for potentially sensitive files."""
        sensitive_patterns = [
            ".env", ".git/config", "wp-config.php", ".htaccess",
            "web.config", "config.yml", "config.json", "secrets",
            ".aws/credentials", "id_rsa", "backup", ".sql",
            "phpinfo.php", "debug", "admin",
        ]

        client = await self._get_client()
        found: list[dict] = []

        for pattern in sensitive_patterns:
            try:
                params = {
                    "url": f"{domain}/*{pattern}*",
                    "output": "json",
                    "limit": "5",
                    "fl": "timestamp,original,statuscode",
                }
                response = await client.get(self.CDX_API, params=params)
                if response.status_code == 200:
                    rows = response.json()
                    if rows and len(rows) > 1:
                        headers = rows[0]
                        for row in rows[1:]:
                            record = dict(zip(headers, row))
                            if record.get("statuscode") == "200":
                                found.append({
                                    **record,
                                    "pattern": pattern,
                                    "severity": "high" if pattern in [".env", ".git/config", "id_rsa"] else "medium",
                                })
            except Exception:
                continue

        logger.info("recon.archive.sensitive_files", domain=domain, found=len(found))
        return found

    async def scrape(self, domain: str) -> dict:
        """Full web archive scrape for a domain."""
        with tracer.start_as_current_span("archive_scrape") as span:
            span.set_attribute("target.domain", domain)

            snapshots = await self.get_snapshots(domain, limit=50)
            robots_history = await self.get_robots_txt_history(domain)
            sensitive_files = await self.find_sensitive_files(domain)

            # Build timeline from snapshot timestamps
            timeline = {}
            for snap in snapshots:
                ts = snap.get("timestamp", "")
                if len(ts) >= 4:
                    year = ts[:4]
                    timeline[year] = timeline.get(year, 0) + 1

            result = {
                "domain": domain,
                "total_snapshots": len(snapshots),
                "timeline": timeline,
                "snapshots": snapshots[:25],
                "robots_txt_history": robots_history,
                "sensitive_files": sensitive_files,
                "sensitive_file_count": len(sensitive_files),
            }

            logger.info(
                "recon.archive.scrape_complete",
                domain=domain,
                snapshots=len(snapshots),
                sensitive=len(sensitive_files),
            )
            return result

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
