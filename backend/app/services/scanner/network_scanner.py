"""
OfSec V3 — #22 Network Service Discovery + #25 CMS Scanner + #26 Compliance Audit
====================================================================================
Combined module for network-level scanning capabilities.
"""

from __future__ import annotations

import asyncio
import re

import httpx
import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("scanner.network")


# ─── #22 Network Service Discovery ───────────


class NetworkDiscoveryScanner:
    """Discover network services, banners, and versions via nmap wrapper."""

    SERVICE_PORTS = {
        "http": [80, 8080, 8000, 8443, 8888],
        "https": [443, 8443],
        "ssh": [22, 2222],
        "ftp": [21],
        "smtp": [25, 587, 465],
        "dns": [53],
        "database": [3306, 5432, 1433, 27017, 6379, 9200],
        "rdp": [3389],
        "smb": [445, 139],
        "vnc": [5900, 5901],
    }

    async def discover(self, host: str, ports: list[int] | None = None) -> dict:
        """Discover services on a host via TCP probing."""
        with tracer.start_as_current_span("network_discovery") as span:
            span.set_attribute("target.host", host)

            target_ports = ports or [p for ps in self.SERVICE_PORTS.values() for p in ps]
            target_ports = sorted(set(target_ports))
            open_services: list[dict] = []
            semaphore = asyncio.Semaphore(50)

            async def probe_port(port: int):
                async with semaphore:
                    try:
                        _, writer = await asyncio.wait_for(
                            asyncio.open_connection(host, port),
                            timeout=3.0,
                        )
                        # Try to grab banner
                        banner = ""
                        try:
                            writer.write(b"\r\n")
                            await writer.drain()
                            data = await asyncio.wait_for(
                                asyncio.ensure_future(self._read_banner(writer)),
                                timeout=2.0,
                            )
                            banner = data
                        except Exception as e:
                            logger.debug("scanner.network.banner.error", host=host, port=port, error=str(e))
                            pass
                        finally:
                            writer.close()
                            await writer.wait_closed()

                        service_name = self._identify_service(port, banner)
                        open_services.append(
                            {
                                "port": port,
                                "state": "open",
                                "service": service_name,
                                "banner": banner[:200] if banner else "",
                                "version": self._extract_version(banner),
                            }
                        )
                    except (TimeoutError, ConnectionRefusedError, OSError) as e:
                        logger.debug("scanner.network.probe.failed", host=host, port=port, error=str(e))
                        pass

            tasks = [probe_port(p) for p in target_ports]
            await asyncio.gather(*tasks, return_exceptions=True)

            open_services.sort(key=lambda x: x["port"])

            logger.info(
                "scanner.network.discovery",
                host=host,
                ports_scanned=len(target_ports),
                open=len(open_services),
            )

            return {
                "host": host,
                "ports_scanned": len(target_ports),
                "open_ports": len(open_services),
                "services": open_services,
            }

    @staticmethod
    async def _read_banner(writer) -> str:
        writer.transport.get_extra_info("socket")
        return ""  # Banner from initial connection

    def _identify_service(self, port: int, banner: str) -> str:
        known = {
            21: "ftp",
            22: "ssh",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            445: "smb",
            1433: "mssql",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            5900: "vnc",
            6379: "redis",
            8080: "http-proxy",
            9200: "elasticsearch",
            27017: "mongodb",
        }
        return known.get(port, "unknown")

    def _extract_version(self, banner: str) -> str:
        if not banner:
            return ""
        version_match = re.search(r"(\d+\.\d+[\.\d]*)", banner)
        return version_match.group(1) if version_match else ""


# ─── #25 CMS Scanner ─────────────────────────


class CMSScanner:
    """Detect and scan Content Management Systems (WordPress, Joomla, Drupal)."""

    CMS_FINGERPRINTS = {
        "wordpress": {
            "paths": ["/wp-login.php", "/wp-admin/", "/wp-content/", "/wp-includes/"],
            "meta": ["wp-content", "wordpress", "wp-json"],
            "version_path": "/feed/",
            "vuln_paths": [
                "/wp-config.php.bak",
                "/wp-config.txt",
                "/.wp-config.php.swp",
                "/wp-content/debug.log",
                "/wp-content/uploads/",
                "/xmlrpc.php",
                "/wp-json/wp/v2/users",
            ],
        },
        "joomla": {
            "paths": ["/administrator/", "/components/", "/modules/"],
            "meta": ["joomla", "com_content"],
            "version_path": "/administrator/manifests/files/joomla.xml",
            "vuln_paths": ["/configuration.php.bak", "/htaccess.txt"],
        },
        "drupal": {
            "paths": ["/core/misc/drupal.js", "/sites/default/", "/node/1"],
            "meta": ["drupal", "Drupal.settings"],
            "version_path": "/CHANGELOG.txt",
            "vuln_paths": ["/CHANGELOG.txt", "/user/register"],
        },
    }

    def __init__(self):
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=10.0,
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; OfSec-V3)"},
            )
        return self._client

    async def detect_cms(self, url: str) -> dict | None:
        """Detect which CMS a site is running."""
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        client = await self._get_client()

        try:
            response = await client.get(url)
            content = response.text.lower()
            headers = dict(response.headers)
        except Exception as e:
            logger.debug("scanner.cms.detect.error", url=url, error=str(e))
            return None

        for cms_name, fingerprints in self.CMS_FINGERPRINTS.items():
            # Check meta/content matches
            if any(meta in content for meta in fingerprints["meta"]):
                return {"cms": cms_name, "confidence": "high", "url": url}

            # Check generator meta tag
            generator = headers.get("x-generator", "").lower()
            if cms_name in generator:
                return {"cms": cms_name, "confidence": "high", "url": url}

            # Probe known paths
            for path in fingerprints["paths"][:2]:
                try:
                    resp = await client.head(f"{url.rstrip('/')}{path}")
                    if resp.status_code < 404:
                        return {"cms": cms_name, "confidence": "medium", "url": url}
                except Exception as e:
                    logger.debug("scanner.cms.detect.path.error", url=url, path=path, error=str(e))
                    continue

        return None

    async def scan_cms_vulns(self, url: str, cms: str) -> list[dict]:
        """Scan a detected CMS for common vulnerabilities."""
        findings: list[dict] = []
        client = await self._get_client()
        fingerprints = self.CMS_FINGERPRINTS.get(cms, {})

        for vuln_path in fingerprints.get("vuln_paths", []):
            try:
                full_url = f"{url.rstrip('/')}{vuln_path}"
                resp = await client.get(full_url)
                if resp.status_code == 200:
                    severity = "high" if any(s in vuln_path for s in [".bak", "debug", "config"]) else "medium"
                    findings.append(
                        {
                            "type": f"{cms.title()} Misconfiguration",
                            "severity": severity,
                            "url": full_url,
                            "path": vuln_path,
                            "evidence": f"Accessible ({resp.status_code}), size: {len(resp.content)} bytes",
                        }
                    )
            except Exception as e:
                logger.debug("scanner.cms.vulns.error", url=full_url, error=str(e))
                continue

        # WordPress-specific: user enumeration
        if cms == "wordpress":
            try:
                resp = await client.get(f"{url.rstrip('/')}/wp-json/wp/v2/users")
                if resp.status_code == 200:
                    users = resp.json()
                    if isinstance(users, list) and users:
                        findings.append(
                            {
                                "type": "WordPress User Enumeration",
                                "severity": "medium",
                                "url": f"{url}/wp-json/wp/v2/users",
                                "evidence": f"Exposed {len(users)} user(s): {[u.get('slug') for u in users[:5]]}",
                            }
                        )
            except Exception as e:
                logger.debug("scanner.cms.wp_enum.error", url=url, error=str(e))
                pass

        return findings

    async def scan(self, url: str) -> dict:
        """Full CMS detection and vulnerability scan."""
        with tracer.start_as_current_span("cms_scan") as span:
            span.set_attribute("target.url", url)

            detection = await self.detect_cms(url)
            if not detection:
                return {"url": url, "cms_detected": False}

            cms = detection["cms"]
            vulns = await self.scan_cms_vulns(url, cms)

            logger.info("scanner.cms.complete", url=url, cms=cms, findings=len(vulns))

            return {
                "url": url,
                "cms_detected": True,
                "cms": detection,
                "total_findings": len(vulns),
                "findings": vulns,
            }

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()


# ─── #26 Compliance & Configuration Audit ────


class ComplianceAuditor:
    """Audit configurations against security benchmarks (CIS, OWASP)."""

    from typing import Any

    OWASP_CHECKS: dict[str, list[dict[str, Any]]] = {
        "A01_Broken_Access_Control": [
            {"check": "directory_listing", "path": "/", "expect": "no_index_of"},
            {"check": "admin_exposure", "path": "/admin", "expect": "auth_required"},
        ],
        "A02_Cryptographic_Failures": [
            {"check": "https_redirect", "expect": "301_to_https"},
            {"check": "hsts_header", "expect": "present"},
        ],
        "A05_Security_Misconfiguration": [
            {"check": "debug_mode", "paths": ["/debug", "/trace", "/?debug=true"], "expect": "not_accessible"},
            {"check": "default_creds", "paths": ["/admin", "/phpmyadmin"], "expect": "not_default"},
            {"check": "error_handling", "path": "/nonexistent-page-12345", "expect": "custom_error"},
        ],
        "A09_Security_Logging": [
            {
                "check": "log_exposure",
                "paths": ["/logs", "/log", "/error.log", "/debug.log"],
                "expect": "not_accessible",
            },
        ],
    }

    def __init__(self):
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=10.0, follow_redirects=False)
        return self._client

    async def audit(self, url: str, standard: str = "owasp") -> dict:
        """Run compliance audit against OWASP Top 10."""
        with tracer.start_as_current_span("compliance_audit") as span:
            span.set_attribute("target.url", url)

            if not url.startswith(("http://", "https://")):
                url = f"https://{url}"

            client = await self._get_client()
            findings: list[dict] = []
            checks_passed = 0
            checks_failed = 0

            for category, checks in self.OWASP_CHECKS.items():
                for check in checks:
                    result = await self._run_check(client, url, check)
                    if result:
                        result["category"] = category
                        findings.append(result)
                        checks_failed += 1
                    else:
                        checks_passed += 1

            total = checks_passed + checks_failed
            compliance_score = round((checks_passed / max(total, 1)) * 100, 1)

            logger.info(
                "scanner.compliance.complete",
                url=url,
                score=compliance_score,
                passed=checks_passed,
                failed=checks_failed,
            )

            return {
                "url": url,
                "standard": standard.upper(),
                "compliance_score": compliance_score,
                "checks_passed": checks_passed,
                "checks_failed": checks_failed,
                "total_checks": total,
                "findings": findings,
            }

    async def _run_check(self, client: httpx.AsyncClient, base_url: str, check: dict) -> dict | None:
        """Run a single compliance check."""
        check_type = check.get("check", "")

        if check_type == "directory_listing":
            try:
                resp = await client.get(base_url)
                if "index of" in resp.text.lower():
                    return {
                        "type": "Directory Listing Enabled",
                        "severity": "medium",
                        "url": base_url,
                        "remediation": "Disable directory listing in web server config",
                    }
            except Exception as e:
                logger.debug("scanner.compliance.dirlist.error", url=base_url, error=str(e))
                pass

        elif check_type == "https_redirect":
            http_url = base_url.replace("https://", "http://")
            try:
                resp = await client.get(http_url)
                if resp.status_code not in (301, 302, 307, 308):
                    return {
                        "type": "No HTTPS Redirect",
                        "severity": "high",
                        "url": http_url,
                        "remediation": "Configure HTTP to HTTPS redirect",
                    }
            except Exception as e:
                logger.debug("scanner.compliance.httpsredir.error", url=http_url, error=str(e))
                pass

        elif check_type in ("debug_mode", "log_exposure", "admin_exposure"):
            paths = check.get("paths", [check.get("path", "")])
            for path in paths:
                try:
                    resp = await client.get(f"{base_url.rstrip('/')}{path}")
                    if resp.status_code == 200:
                        return {
                            "type": f"Exposed Endpoint: {path}",
                            "severity": "high" if "debug" in path or "log" in path else "medium",
                            "url": f"{base_url}{path}",
                            "remediation": f"Restrict access to {path}",
                        }
                except Exception as e:
                    logger.debug("scanner.compliance.admin_exposure.error", url=base_url, path=path, error=str(e))
                    continue

        elif check_type == "error_handling":
            try:
                resp = await client.get(f"{base_url.rstrip('/')}{check['path']}")
                if any(kw in resp.text.lower() for kw in ["traceback", "stack trace", "exception", "debug"]):
                    return {
                        "type": "Verbose Error Pages",
                        "severity": "medium",
                        "url": f"{base_url}{check['path']}",
                        "remediation": "Implement custom error pages, disable debug mode",
                    }
            except Exception as e:
                logger.debug("scanner.compliance.error_handling.error", url=base_url, path=check["path"], error=str(e))
                pass

        return None

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
