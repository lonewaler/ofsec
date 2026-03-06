"""
OfSec V3 — #11-15 Additional Recon Modules
=============================================
#11 Technology Fingerprinting
#12 Port & Service Fingerprinting
#13 Cloud Asset Discovery
#14 Network Topology Mapping
#15 Subdomain Takeover Detection
"""


from __future__ import annotations
import httpx
import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("recon.advanced")


# ─── #11 Technology Fingerprinting ────────────

class TechFingerprinter:
    """Detect web technologies via HTTP headers, cookies, and HTML signatures."""

    # Technology signatures from response headers/content
    TECH_SIGNATURES = {
        "headers": {
            "x-powered-by": {
                "Express": "express.js",
                "PHP": "php",
                "ASP.NET": "asp.net",
                "Next.js": "next.js",
                "Django": "django",
                "Flask": "flask",
            },
            "server": {
                "nginx": "nginx",
                "Apache": "apache",
                "cloudflare": "cloudflare",
                "AmazonS3": "aws-s3",
                "Microsoft-IIS": "iis",
                "Vercel": "vercel",
                "gunicorn": "gunicorn",
            },
            "x-frame-options": {"*": "x-frame-options"},
            "strict-transport-security": {"*": "hsts"},
            "content-security-policy": {"*": "csp"},
        },
        "cookies": {
            "PHPSESSID": "php",
            "JSESSIONID": "java",
            "csrftoken": "django",
            "ASP.NET_SessionId": "asp.net",
            "_rails_session": "ruby-on-rails",
            "express.sid": "express.js",
            "__cf_bm": "cloudflare",
            "_vercel_jwt": "vercel",
        },
    }

    def __init__(self):
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=10.0, follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; OfSec-V3)"},
            )
        return self._client

    async def fingerprint(self, url: str) -> dict:
        """Detect technologies used by a web target."""
        with tracer.start_as_current_span("tech_fingerprint") as span:
            span.set_attribute("target.url", url)

            if not url.startswith(("http://", "https://")):
                url = f"https://{url}"

            client = await self._get_client()
            technologies: list[str] = []
            security_headers: list[str] = []

            try:
                response = await client.get(url)
                headers = dict(response.headers)

                # Check headers
                for header_name, signatures in self.TECH_SIGNATURES["headers"].items():
                    header_val = headers.get(header_name, "")
                    if header_val:
                        for sig, tech in signatures.items():
                            if sig == "*" or sig.lower() in header_val.lower():
                                if header_name in ("x-frame-options", "strict-transport-security", "content-security-policy"):
                                    security_headers.append(tech)
                                else:
                                    technologies.append(tech)

                # Check cookies
                for cookie_name, tech in self.TECH_SIGNATURES["cookies"].items():
                    if cookie_name in response.headers.get("set-cookie", ""):
                        technologies.append(tech)

                return {
                    "url": url,
                    "status_code": response.status_code,
                    "technologies": list(set(technologies)),
                    "security_headers": security_headers,
                    "server": headers.get("server", ""),
                    "content_type": headers.get("content-type", ""),
                }
            except Exception as e:
                logger.error("recon.tech.error", url=url, error=str(e))
                return {"url": url, "error": str(e)}

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()


# ─── #12 Port & Service Discovery ────────────

class PortScanner:
    """Lightweight async TCP port scanner."""

    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888,
        9090, 9200, 27017,
    ]

    async def scan_ports(
        self, host: str, ports: list[int] | None = None, timeout: float = 2.0
    ) -> list[dict]:
        """Scan TCP ports on a host."""
        import asyncio

        target_ports = ports or self.COMMON_PORTS
        open_ports: list[dict] = []
        semaphore = asyncio.Semaphore(50)

        async def check_port(port: int):
            async with semaphore:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    open_ports.append({
                        "port": port,
                        "state": "open",
                        "service": self._guess_service(port),
                    })
                except (TimeoutError, ConnectionRefusedError, OSError):
                    pass

        tasks = [check_port(p) for p in target_ports]
        await asyncio.gather(*tasks, return_exceptions=True)

        logger.info("recon.port_scan.complete", host=host, open=len(open_ports))
        return sorted(open_ports, key=lambda x: x["port"])

    def _guess_service(self, port: int) -> str:
        services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
            1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
            6379: "redis", 8080: "http-proxy", 9200: "elasticsearch", 27017: "mongodb",
        }
        return services.get(port, "unknown")


# ─── #13 Cloud Asset Discovery ───────────────

class CloudAssetDiscovery:
    """Discover cloud-hosted assets (AWS, Azure, GCP)."""

    CLOUD_PATTERNS = {
        "aws_s3": [
            "{domain}.s3.amazonaws.com",
            "{domain}.s3-us-east-1.amazonaws.com",
        ],
        "azure_blob": [
            "{domain}.blob.core.windows.net",
            "{domain}.azurewebsites.net",
        ],
        "gcp_storage": [
            "storage.googleapis.com/{domain}",
            "{domain}.appspot.com",
        ],
    }

    def __init__(self):
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=8.0, follow_redirects=False)
        return self._client

    async def discover(self, domain: str) -> dict:
        """Check for cloud-hosted assets related to a domain."""
        import asyncio
        client = await self._get_client()
        found: list[dict] = []

        # Strip TLD for bucket names
        base = domain.split(".")[0]

        async def check_url(provider: str, url_template: str, name: str):
            url = url_template.format(domain=name)
            if not url.startswith("http"):
                url = f"https://{url}"
            try:
                resp = await client.head(url)
                if resp.status_code < 404:
                    found.append({
                        "provider": provider,
                        "url": url,
                        "status": resp.status_code,
                        "public": resp.status_code == 200,
                    })
            except Exception:
                pass

        tasks = []
        for provider, patterns in self.CLOUD_PATTERNS.items():
            for pattern in patterns:
                for name in [domain, base, base.replace("-", "")]:
                    tasks.append(check_url(provider, pattern, name))

        await asyncio.gather(*tasks, return_exceptions=True)

        logger.info("recon.cloud.discovery", domain=domain, found=len(found))
        return {"domain": domain, "cloud_assets": found, "count": len(found)}

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()


# ─── #15 Subdomain Takeover Detection ────────

class SubdomainTakeoverChecker:
    """Detect potentially vulnerable subdomains for takeover."""

    # CNAME fingerprints indicating possible takeover
    TAKEOVER_FINGERPRINTS = {
        "github.io": {"cname": "github.io", "service": "GitHub Pages"},
        "herokuapp.com": {"cname": "herokuapp.com", "service": "Heroku"},
        "s3.amazonaws.com": {"cname": "s3.amazonaws.com", "service": "AWS S3"},
        "azurewebsites.net": {"cname": "azurewebsites.net", "service": "Azure"},
        "cloudfront.net": {"cname": "cloudfront.net", "service": "AWS CloudFront"},
        "shopify.com": {"cname": "shops.myshopify.com", "service": "Shopify"},
        "surge.sh": {"cname": "surge.sh", "service": "Surge.sh"},
        "unbouncepages.com": {"cname": "unbouncepages.com", "service": "Unbounce"},
        "zendesk.com": {"cname": "zendesk.com", "service": "Zendesk"},
        "fastly.net": {"cname": "fastly.net", "service": "Fastly"},
    }

    def __init__(self):
        import dns.asyncresolver
        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.timeout = 5
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=8.0)
        return self._client

    async def check_subdomain(self, subdomain: str) -> dict | None:
        """Check if a subdomain is vulnerable to takeover."""
        try:
            answers = await self._resolver.resolve(subdomain, "CNAME")
            cname_target = str(answers[0]).rstrip(".")

            for pattern, info in self.TAKEOVER_FINGERPRINTS.items():
                if pattern in cname_target:
                    # Verify the CNAME target doesn't resolve
                    client = await self._get_client()
                    try:
                        resp = await client.get(f"https://{subdomain}", follow_redirects=False)
                        if resp.status_code in (404, 502, 503):
                            return {
                                "subdomain": subdomain,
                                "cname": cname_target,
                                "service": info["service"],
                                "vulnerable": True,
                                "severity": "high",
                            }
                    except Exception:
                        return {
                            "subdomain": subdomain,
                            "cname": cname_target,
                            "service": info["service"],
                            "vulnerable": True,
                            "severity": "high",
                        }
        except Exception:
            pass
        return None

    async def scan(self, subdomains: list[str]) -> list[dict]:
        """Check a list of subdomains for takeover vulnerability."""
        import asyncio
        results: list[dict] = []
        semaphore = asyncio.Semaphore(10)

        async def check(sub: str):
            async with semaphore:
                result = await self.check_subdomain(sub)
                if result:
                    results.append(result)

        tasks = [check(sub) for sub in subdomains]
        await asyncio.gather(*tasks, return_exceptions=True)

        logger.info("recon.takeover.scan", checked=len(subdomains), vulnerable=len(results))
        return results

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
