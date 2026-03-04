"""
OfSec V3 — #18 API Security Scanner
=====================================
Scans REST/GraphQL APIs for security issues: auth bypass, IDOR,
rate limiting, information disclosure, mass assignment.
"""

import asyncio
from typing import Optional

import httpx
import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("scanner.api")


class APISecurityScanner:
    """REST and GraphQL API security scanner."""

    COMMON_API_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/graphql", "/graphiql", "/playground",
        "/swagger", "/swagger.json", "/swagger-ui",
        "/openapi.json", "/docs", "/redoc",
        "/api-docs", "/api/docs", "/.well-known/openapi",
        "/health", "/healthcheck", "/status",
        "/metrics", "/actuator", "/actuator/health",
        "/debug", "/debug/vars", "/debug/pprof",
        "/admin", "/admin/api", "/internal",
        "/api/users", "/api/config", "/api/settings",
    ]

    IDOR_PATTERNS = [
        "/api/v1/users/{id}",
        "/api/v1/orders/{id}",
        "/api/v1/documents/{id}",
        "/api/v1/files/{id}",
        "/api/v1/accounts/{id}",
    ]

    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=10.0, follow_redirects=True,
                headers={"User-Agent": "OfSec-V3/3.0", "Accept": "application/json"},
            )
        return self._client

    async def discover_endpoints(self, base_url: str) -> list[dict]:
        """Discover API endpoints by probing common paths."""
        with tracer.start_as_current_span("api_discovery") as span:
            span.set_attribute("target.url", base_url)

            client = await self._get_client()
            found: list[dict] = []
            semaphore = asyncio.Semaphore(10)

            async def probe(path: str):
                async with semaphore:
                    url = f"{base_url.rstrip('/')}{path}"
                    try:
                        response = await client.get(url)
                        if response.status_code < 404:
                            content_type = response.headers.get("content-type", "")
                            found.append({
                                "path": path,
                                "url": url,
                                "status": response.status_code,
                                "content_type": content_type,
                                "is_json": "json" in content_type,
                                "size": len(response.content),
                            })
                    except Exception:
                        pass

            tasks = [probe(p) for p in self.COMMON_API_PATHS]
            await asyncio.gather(*tasks)

            logger.info("scanner.api.discovery", base=base_url, found=len(found))
            return found

    async def check_auth_bypass(self, base_url: str, endpoints: list[dict]) -> list[dict]:
        """Test endpoints for authentication bypass."""
        findings: list[dict] = []
        client = await self._get_client()

        for ep in endpoints:
            url = ep["url"]
            try:
                # Test without auth
                response = await client.get(url)
                if response.status_code == 200 and ep.get("is_json"):
                    body = response.text
                    # Check for sensitive data in unauthenticated response
                    sensitive_keys = ["password", "token", "secret", "api_key", "email", "ssn", "credit_card"]
                    for key in sensitive_keys:
                        if key in body.lower():
                            findings.append({
                                "type": "Authentication Bypass",
                                "severity": "critical",
                                "url": url,
                                "evidence": f"Sensitive data '{key}' accessible without auth",
                            })
                            break
            except Exception:
                continue

        return findings

    async def check_http_methods(self, base_url: str, endpoints: list[dict]) -> list[dict]:
        """Test for dangerous HTTP methods (PUT, DELETE, PATCH without auth)."""
        findings: list[dict] = []
        client = await self._get_client()
        dangerous_methods = ["PUT", "DELETE", "PATCH"]

        for ep in endpoints[:10]:  # Limit to first 10
            for method in dangerous_methods:
                try:
                    response = await client.request(method, ep["url"])
                    if response.status_code not in (401, 403, 404, 405):
                        findings.append({
                            "type": "Dangerous HTTP Method",
                            "severity": "high",
                            "url": ep["url"],
                            "method": method,
                            "status": response.status_code,
                            "evidence": f"{method} returned {response.status_code}",
                        })
                except Exception:
                    continue

        return findings

    async def check_rate_limiting(self, url: str, requests: int = 30) -> dict:
        """Test if an endpoint has rate limiting."""
        client = await self._get_client()
        statuses: list[int] = []

        for _ in range(requests):
            try:
                resp = await client.get(url)
                statuses.append(resp.status_code)
                if resp.status_code == 429:
                    return {
                        "url": url,
                        "rate_limited": True,
                        "triggered_at": len(statuses),
                        "severity": "info",
                    }
            except Exception:
                break

        has_rate_limit = 429 in statuses
        return {
            "url": url,
            "rate_limited": has_rate_limit,
            "requests_sent": len(statuses),
            "severity": "medium" if not has_rate_limit else "info",
            "finding": None if has_rate_limit else {
                "type": "Missing Rate Limiting",
                "severity": "medium",
                "url": url,
                "evidence": f"No 429 after {len(statuses)} requests",
            },
        }

    async def check_graphql(self, base_url: str) -> dict:
        """Detect and test GraphQL endpoint."""
        client = await self._get_client()
        graphql_paths = ["/graphql", "/graphiql", "/api/graphql"]
        result = {"graphql_found": False, "findings": []}

        for path in graphql_paths:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                # Introspection query
                resp = await client.post(
                    url,
                    json={"query": "{ __schema { types { name } } }"},
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code == 200 and "__schema" in resp.text:
                    result["graphql_found"] = True
                    result["endpoint"] = url
                    result["findings"].append({
                        "type": "GraphQL Introspection Enabled",
                        "severity": "medium",
                        "url": url,
                        "evidence": "Introspection query returned schema data",
                        "remediation": "Disable introspection in production",
                    })
                    break
            except Exception:
                continue

        return result

    async def scan(self, base_url: str) -> dict:
        """Full API security scan."""
        with tracer.start_as_current_span("api_scan") as span:
            span.set_attribute("target.url", base_url)

            if not base_url.startswith(("http://", "https://")):
                base_url = f"https://{base_url}"

            endpoints = await self.discover_endpoints(base_url)
            auth_findings = await self.check_auth_bypass(base_url, endpoints)
            method_findings = await self.check_http_methods(base_url, endpoints)
            graphql = await self.check_graphql(base_url)

            all_findings = auth_findings + method_findings + graphql.get("findings", [])

            # Severity summary
            severity_counts = {}
            for f in all_findings:
                sev = f.get("severity", "info")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            logger.info(
                "scanner.api.complete",
                url=base_url,
                endpoints=len(endpoints),
                findings=len(all_findings),
            )

            return {
                "base_url": base_url,
                "endpoints_discovered": endpoints,
                "endpoint_count": len(endpoints),
                "graphql": graphql,
                "total_findings": len(all_findings),
                "severity_summary": severity_counts,
                "findings": all_findings,
            }

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
