"""
OfSec V3 — #20 Container Security + #21 Cloud Config + #23 Credential + #27-30 Advanced
==========================================================================================
"""

from __future__ import annotations

import asyncio
import re

import httpx
import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("scanner.advanced")


# ─── #20 Container Security Scanner ──────────

class ContainerSecurityScanner:
    """Scan Docker/container images for misconfigurations and vulnerabilities."""

    # Dockerfile security anti-patterns
    from typing import Any
    DOCKERFILE_CHECKS: list[dict[str, Any]] = [
        {
            "pattern": r"FROM\s+\S+:latest",
            "severity": "medium",
            "finding": "Using ':latest' tag — pin to specific versions for reproducibility",
        },
        {
            "pattern": r"USER\s+root",
            "severity": "high",
            "finding": "Running as root user — use a non-root user",
        },
        {
            "pattern": r"(ADD|COPY)\s+\.\s+",
            "severity": "medium",
            "finding": "Copying entire context — use specific paths and .dockerignore",
        },
        {
            "pattern": r"ENV\s+\S*(PASSWORD|SECRET|KEY|TOKEN)\S*\s*=",
            "severity": "critical",
            "finding": "Hardcoded secret in ENV — use Docker secrets or env files",
            "flags": re.IGNORECASE,
        },
        {
            "pattern": r"RUN\s+.*&&\s*rm\s+-rf\s+/var/lib/apt|apk\s+add\s+--no-cache",
            "severity": "info",
            "finding": "Good: cleaning package cache to reduce image size",
        },
        {
            "pattern": r"EXPOSE\s+(22|3389|5900)\b",
            "severity": "high",
            "finding": "Exposing management port (SSH/RDP/VNC) — avoid in containers",
        },
        {
            "pattern": r"RUN\s+chmod\s+777",
            "severity": "high",
            "finding": "World-writable permissions — use specific permissions",
        },
        {
            "pattern": r"RUN\s+.*curl\s+.*\|\s*(bash|sh)",
            "severity": "critical",
            "finding": "Piping curl to shell — download and verify before executing",
        },
    ]

    def scan_dockerfile(self, content: str) -> dict:
        """Scan a Dockerfile for security issues."""
        with tracer.start_as_current_span("container_scan"):
            findings: list[dict] = []
            lines = content.split("\n")

            has_user = False
            has_healthcheck = False

            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("USER") and "root" not in stripped.lower():
                    has_user = True
                if stripped.startswith("HEALTHCHECK"):
                    has_healthcheck = True

                for check in self.DOCKERFILE_CHECKS:
                    flags = check.get("flags", 0)
                    if re.search(check["pattern"], stripped, flags):
                        if check["severity"] != "info":
                            findings.append({
                                "type": "Dockerfile Issue",
                                "severity": check["severity"],
                                "line": i,
                                "content": stripped[:100],
                                "finding": check["finding"],
                            })

            if not has_user:
                findings.append({
                    "type": "Dockerfile Issue",
                    "severity": "high",
                    "finding": "No USER directive — container runs as root by default",
                })

            if not has_healthcheck:
                findings.append({
                    "type": "Dockerfile Issue",
                    "severity": "low",
                    "finding": "No HEALTHCHECK defined",
                })

            severity_counts: dict[str, int] = {}
            for f in findings:
                sev = f["severity"]
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            return {
                "type": "dockerfile",
                "total_findings": len(findings),
                "severity_summary": severity_counts,
                "findings": findings,
            }


# ─── #21 Cloud Configuration Auditor ─────────

class CloudConfigAuditor:
    """Audit cloud configurations (AWS, Azure, GCP) for misconfigurations."""

    # S3 bucket misconfiguration checks
    async def check_s3_bucket(self, bucket_name: str) -> dict:
        """Check S3 bucket for public access."""
        async with httpx.AsyncClient(timeout=8.0) as client:
            findings: list[dict] = []

            # Check direct public access
            for url in [
                f"https://{bucket_name}.s3.amazonaws.com",
                f"https://s3.amazonaws.com/{bucket_name}",
            ]:
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        findings.append({
                            "type": "Public S3 Bucket",
                            "severity": "critical",
                            "url": url,
                            "evidence": f"Bucket is publicly accessible (HTTP {resp.status_code})",
                            "remediation": "Enable S3 Block Public Access",
                        })
                    elif resp.status_code == 403:
                        findings.append({
                            "type": "S3 Bucket Exists",
                            "severity": "info",
                            "url": url,
                            "evidence": "Bucket exists but access denied (properly configured)",
                        })
                except Exception:
                    continue

            return {"bucket": bucket_name, "findings": findings}

    async def audit_cloud_exposure(self, domain: str) -> dict:
        """Check for exposed cloud resources."""
        with tracer.start_as_current_span("cloud_audit"):
            findings: list[dict] = []
            base = domain.split(".")[0]

            # Check common cloud resource patterns
            patterns = [
                f"{base}.s3.amazonaws.com",
                f"{base}-backup.s3.amazonaws.com",
                f"{base}-prod.s3.amazonaws.com",
                f"{base}-dev.s3.amazonaws.com",
                f"{base}.blob.core.windows.net",
            ]

            async with httpx.AsyncClient(timeout=5.0) as client:
                for pattern in patterns:
                    try:
                        resp = await client.head(f"https://{pattern}")
                        if resp.status_code != 404:
                            findings.append({
                                "type": "Cloud Resource Found",
                                "severity": "medium" if resp.status_code == 200 else "info",
                                "resource": pattern,
                                "status": resp.status_code,
                                "public": resp.status_code == 200,
                            })
                    except Exception:
                        continue

            return {"domain": domain, "findings": findings, "count": len(findings)}


# ─── #23 Credential & Authentication Tester ──

class CredentialTester:
    """Test for default credentials and weak authentication."""

    DEFAULT_CREDENTIALS = [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
        {"username": "admin", "password": "123456"},
        {"username": "root", "password": "root"},
        {"username": "root", "password": "toor"},
        {"username": "test", "password": "test"},
        {"username": "user", "password": "user"},
        {"username": "admin", "password": "admin123"},
        {"username": "administrator", "password": "administrator"},
        {"username": "guest", "password": "guest"},
    ]

    def __init__(self):
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=10.0, follow_redirects=False)
        return self._client

    async def test_http_basic(self, url: str) -> list[dict]:
        """Test for default HTTP Basic Auth credentials."""
        findings: list[dict] = []
        client = await self._get_client()

        for cred in self.DEFAULT_CREDENTIALS:
            try:
                resp = await client.get(
                    url,
                    auth=(cred["username"], cred["password"]),
                )
                if resp.status_code == 200:
                    findings.append({
                        "type": "Default Credentials",
                        "severity": "critical",
                        "url": url,
                        "auth_type": "HTTP Basic",
                        "username": cred["username"],
                        "evidence": f"Login successful with {cred['username']}:{cred['password']}",
                    })
                    break  # One hit is enough
            except Exception:
                continue

        return findings

    async def test_form_login(self, url: str, form_data_field: str = "username", pass_field: str = "password") -> list[dict]:
        """Test login forms for default credentials."""
        findings: list[dict] = []
        client = await self._get_client()

        for cred in self.DEFAULT_CREDENTIALS[:5]:  # Limit to avoid lockouts
            try:
                resp = await client.post(
                    url,
                    data={form_data_field: cred["username"], pass_field: cred["password"]},
                )
                # Check for successful login indicators
                if resp.status_code in (200, 302) and any(
                    kw in resp.text.lower()
                    for kw in ["dashboard", "welcome", "logout", "profile"]
                ):
                    findings.append({
                        "type": "Default Credentials",
                        "severity": "critical",
                        "url": url,
                        "auth_type": "Form Login",
                        "username": cred["username"],
                        "evidence": f"Login appears successful with {cred['username']}",
                    })
                    break
                await asyncio.sleep(0.5)  # Avoid rate limiting
            except Exception:
                continue

        return findings

    async def scan(self, url: str) -> dict:
        """Run all credential tests."""
        with tracer.start_as_current_span("credential_test") as span:
            span.set_attribute("target.url", url)

            basic_findings = await self.test_http_basic(url)
            form_findings = await self.test_form_login(url)
            all_findings = basic_findings + form_findings

            logger.info("scanner.cred.complete", url=url, findings=len(all_findings))

            return {
                "url": url,
                "total_findings": len(all_findings),
                "findings": all_findings,
            }

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()


# ─── #27-30 Advanced Scanner Modules ─────────

class WAFDetector:
    """#27 Detect Web Application Firewalls."""

    WAF_SIGNATURES = {
        "Cloudflare": ["cf-ray", "__cfduid", "cf-cache-status"],
        "AWS WAF": ["x-amzn-requestid", "x-amzn-trace-id"],
        "Akamai": ["akamai-grn", "x-akamai-transformed"],
        "Imperva/Incapsula": ["x-iinfo", "incap_ses", "visid_incap"],
        "F5 BIG-IP": ["bigipserver", "x-cnection"],
        "ModSecurity": ["mod_security", "NOYB"],
        "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
        "Barracuda": ["barra_counter_session"],
    }

    async def detect(self, url: str) -> dict:
        """Detect WAF by analyzing response headers and behavior."""
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            detected_wafs: list[str] = []

            try:
                response = await client.get(url)
                headers_str = str(dict(response.headers)).lower()
                cookies = response.headers.get("set-cookie", "").lower()

                for waf_name, signatures in self.WAF_SIGNATURES.items():
                    for sig in signatures:
                        if sig.lower() in headers_str or sig.lower() in cookies:
                            detected_wafs.append(waf_name)
                            break

                # Send malicious request to trigger WAF
                try:
                    resp_malicious = await client.get(
                        url, params={"id": "<script>alert(1)</script>"},
                    )
                    if resp_malicious.status_code in (403, 406, 429, 503):
                        if not detected_wafs:
                            detected_wafs.append("Unknown WAF")
                except Exception:
                    pass

            except Exception as e:
                return {"url": url, "error": str(e)}

            return {
                "url": url,
                "waf_detected": len(detected_wafs) > 0,
                "wafs": list(set(detected_wafs)),
                "severity": "info",
            }


class SubdomainBruteforcer:
    """#28 Subdomain brute-force discovery."""

    WORDLIST = [
        "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
        "blog", "shop", "store", "portal", "app", "m", "mobile",
        "vpn", "gateway", "cdn", "media", "static", "assets",
        "git", "jenkins", "ci", "docs", "wiki", "jira", "confluence",
        "grafana", "prometheus", "kibana", "elastic", "redis",
        "db", "mysql", "postgres", "mongo", "backup", "old",
        "beta", "alpha", "sandbox", "demo", "preview", "internal",
        "ns1", "ns2", "mx", "smtp", "imap", "pop", "webmail",
    ]

    async def bruteforce(self, domain: str, wordlist: list[str] | None = None) -> list[str]:
        """Brute-force subdomains via DNS resolution."""
        import dns.asyncresolver

        words = wordlist or self.WORDLIST
        found: list[str] = []
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 3
        semaphore = asyncio.Semaphore(20)

        async def check(word: str):
            async with semaphore:
                subdomain = f"{word}.{domain}"
                try:
                    await resolver.resolve(subdomain, "A")
                    found.append(subdomain)
                except Exception:
                    pass

        tasks = [check(w) for w in words]
        await asyncio.gather(*tasks, return_exceptions=True)

        logger.info("scanner.subdomain.complete", domain=domain, found=len(found))
        return sorted(found)


class VulnerabilityCorrelator:
    """#29-30 Correlates findings across modules and scores risk."""

    SEVERITY_WEIGHTS = {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 1,
        "info": 0,
    }

    def correlate(self, scan_results: dict) -> dict:
        """Aggregate and correlate findings across all scanner modules."""
        all_findings: list[dict] = []
        module_scores: dict[str, float] = {}

        for module_name, module_data in scan_results.items():
            if not isinstance(module_data, dict):
                continue

            findings = module_data.get("findings", [])
            score = sum(
                self.SEVERITY_WEIGHTS.get(f.get("severity", "info"), 0)
                for f in findings
            )
            module_scores[module_name] = score
            for f in findings:
                f["source_module"] = module_name
                all_findings.append(f)

        # Sort by severity weight
        all_findings.sort(
            key=lambda f: self.SEVERITY_WEIGHTS.get(f.get("severity", "info"), 0),
            reverse=True,
        )

        total_score = sum(module_scores.values())
        severity_counts: dict[str, int] = {}
        for f in all_findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Risk rating
        if total_score >= 50:
            risk_rating = "Critical"
        elif total_score >= 30:
            risk_rating = "High"
        elif total_score >= 15:
            risk_rating = "Medium"
        elif total_score > 0:
            risk_rating = "Low"
        else:
            risk_rating = "Minimal"

        return {
            "risk_rating": risk_rating,
            "risk_score": total_score,
            "total_findings": len(all_findings),
            "severity_summary": severity_counts,
            "module_scores": module_scores,
            "findings": all_findings[:100],  # Top 100
        }
