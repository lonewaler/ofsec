"""
OfSec V3 — #17 Header Security Analyzer
=========================================
Analyzes HTTP response headers for security misconfigurations.

Checks: HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy, CORS, cookie flags, server info leakage.
"""


import httpx
import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("scanner.headers")

# Security headers to check and their expected configurations
SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "HTTP Strict Transport Security (HSTS)",
        "severity": "high",
        "description": "Forces HTTPS connections, prevents downgrade attacks",
        "recommended": "max-age=31536000; includeSubDomains; preload",
    },
    "content-security-policy": {
        "name": "Content Security Policy (CSP)",
        "severity": "high",
        "description": "Prevents XSS and data injection attacks",
        "recommended": "default-src 'self'; script-src 'self'",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "medium",
        "description": "Prevents clickjacking attacks",
        "recommended": "DENY or SAMEORIGIN",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "medium",
        "description": "Prevents MIME-type sniffing",
        "recommended": "nosniff",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "low",
        "description": "Controls referrer information leakage",
        "recommended": "strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": "low",
        "description": "Controls browser feature access",
        "recommended": "camera=(), microphone=(), geolocation=()",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "severity": "low",
        "description": "Legacy XSS filter (deprecated but still checked)",
        "recommended": "0 (rely on CSP instead)",
    },
    "cross-origin-opener-policy": {
        "name": "Cross-Origin-Opener-Policy",
        "severity": "low",
        "description": "Prevents cross-origin window references",
        "recommended": "same-origin",
    },
    "cross-origin-resource-policy": {
        "name": "Cross-Origin-Resource-Policy",
        "severity": "low",
        "description": "Prevents cross-origin resource loading",
        "recommended": "same-origin",
    },
}

# Headers that should NOT be present (info leakage)
LEAKY_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]


class HeaderSecurityAnalyzer:
    """Analyze HTTP security headers for misconfigurations."""

    def __init__(self):
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=10.0, follow_redirects=True)
        return self._client

    async def analyze(self, url: str) -> dict:
        """Perform full header security analysis on a URL."""
        with tracer.start_as_current_span("header_analysis") as span:
            span.set_attribute("target.url", url)

            if not url.startswith(("http://", "https://")):
                url = f"https://{url}"

            client = await self._get_client()
            try:
                response = await client.get(url)
            except Exception as e:
                return {"url": url, "error": str(e)}

            headers = dict(response.headers)
            findings: list[dict] = []
            present_headers: list[str] = []
            missing_headers: list[str] = []

            # Check required security headers
            for header_key, info in SECURITY_HEADERS.items():
                value = headers.get(header_key)
                if value:
                    present_headers.append(header_key)
                    # Analyze the value quality
                    issues = self._analyze_header_value(header_key, value)
                    if issues:
                        findings.append({
                            "type": "Weak Security Header",
                            "header": info["name"],
                            "severity": "low",
                            "current_value": value,
                            "issue": issues,
                            "recommended": info["recommended"],
                        })
                else:
                    missing_headers.append(header_key)
                    findings.append({
                        "type": "Missing Security Header",
                        "header": info["name"],
                        "severity": info["severity"],
                        "recommended": info["recommended"],
                        "description": info["description"],
                    })

            # Check for leaky headers
            for header_key in LEAKY_HEADERS:
                value = headers.get(header_key)
                if value:
                    findings.append({
                        "type": "Information Disclosure",
                        "header": header_key,
                        "severity": "low",
                        "value": value,
                        "description": f"Server leaks {header_key}: {value}",
                        "remediation": f"Remove or obfuscate the '{header_key}' header",
                    })

            # Check cookie security
            cookie_findings = self._analyze_cookies(response)
            findings.extend(cookie_findings)

            # Check CORS configuration
            cors_findings = self._analyze_cors(headers)
            findings.extend(cors_findings)

            # Calculate security score (0-100)
            max_score = len(SECURITY_HEADERS) * 10
            score = max_score - sum(
                10 if h in ["strict-transport-security", "content-security-policy"] else 5
                for h in missing_headers
            )
            score = max(0, min(100, score))

            # Grade
            grade = "A" if score >= 90 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F"

            result = {
                "url": url,
                "status_code": response.status_code,
                "security_score": score,
                "grade": grade,
                "present_headers": present_headers,
                "missing_headers": missing_headers,
                "total_findings": len(findings),
                "findings": findings,
            }

            logger.info(
                "scanner.headers.complete",
                url=url,
                score=score,
                grade=grade,
                findings=len(findings),
            )
            return result

    def _analyze_header_value(self, header: str, value: str) -> str | None:
        """Check if a header value is configured properly."""
        if header == "strict-transport-security":
            if "max-age=0" in value:
                return "HSTS max-age is 0, effectively disabled"
            try:
                max_age = int(value.split("max-age=")[1].split(";")[0].strip())
                if max_age < 31536000:
                    return f"HSTS max-age ({max_age}s) is less than recommended 1 year"
            except (ValueError, IndexError):
                pass
        elif header == "x-frame-options":
            if value.upper() not in ["DENY", "SAMEORIGIN"]:
                return f"Unusual X-Frame-Options value: {value}"
        elif header == "content-security-policy":
            if "unsafe-inline" in value or "unsafe-eval" in value:
                return "CSP allows unsafe-inline or unsafe-eval, weakening XSS protection"
            if "default-src *" in value or "script-src *" in value:
                return "CSP has wildcard source, effectively disabled"
        return None

    def _analyze_cookies(self, response: httpx.Response) -> list[dict]:
        """Analyze Set-Cookie headers for security flags."""
        findings = []
        cookies = response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else []

        # Fallback: parse from raw headers
        if not cookies:
            for key, value in response.headers.multi_items():
                if key.lower() == "set-cookie":
                    cookies.append(value)

        for cookie in cookies:
            cookie_lower = cookie.lower()
            cookie_name = cookie.split("=")[0].strip()

            if "secure" not in cookie_lower:
                findings.append({
                    "type": "Insecure Cookie",
                    "severity": "medium",
                    "cookie": cookie_name,
                    "issue": "Cookie missing 'Secure' flag",
                    "remediation": "Add 'Secure' flag to prevent transmission over HTTP",
                })
            if "httponly" not in cookie_lower:
                findings.append({
                    "type": "Insecure Cookie",
                    "severity": "medium",
                    "cookie": cookie_name,
                    "issue": "Cookie missing 'HttpOnly' flag",
                    "remediation": "Add 'HttpOnly' flag to prevent JavaScript access",
                })
            if "samesite" not in cookie_lower:
                findings.append({
                    "type": "Insecure Cookie",
                    "severity": "low",
                    "cookie": cookie_name,
                    "issue": "Cookie missing 'SameSite' attribute",
                    "remediation": "Add 'SameSite=Strict' or 'SameSite=Lax'",
                })
        return findings

    def _analyze_cors(self, headers: dict) -> list[dict]:
        """Analyze CORS configuration."""
        findings = []
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")

        if acao == "*":
            if acac.lower() == "true":
                findings.append({
                    "type": "CORS Misconfiguration",
                    "severity": "critical",
                    "issue": "CORS allows all origins with credentials — high risk!",
                    "remediation": "Restrict Access-Control-Allow-Origin to specific domains",
                })
            else:
                findings.append({
                    "type": "CORS Misconfiguration",
                    "severity": "low",
                    "issue": "CORS allows all origins (wildcard *)",
                    "remediation": "Consider restricting to specific trusted origins",
                })
        return findings

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
