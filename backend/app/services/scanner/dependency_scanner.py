"""
OfSec V3 — #19 Dependency Vulnerability Scanner
=================================================
Scans project dependencies for known CVEs using OSV API and safety checks.

Supports: Python (pip), JavaScript (npm), Ruby (gem), Go, Rust (cargo).
"""


import httpx
import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("scanner.dependency")


class DependencyScanner:
    """Scan software dependencies for known vulnerabilities via OSV.dev."""

    OSV_API = "https://api.osv.dev/v1"

    def __init__(self):
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=15.0)
        return self._client

    async def scan_package(self, name: str, version: str, ecosystem: str = "PyPI") -> list[dict]:
        """Query OSV.dev for vulnerabilities in a specific package."""
        client = await self._get_client()
        try:
            response = await client.post(
                f"{self.OSV_API}/query",
                json={"package": {"name": name, "ecosystem": ecosystem}, "version": version},
            )
            response.raise_for_status()
            data = response.json()
            vulns = data.get("vulns", [])

            return [
                {
                    "id": v.get("id", ""),
                    "summary": v.get("summary", ""),
                    "severity": self._map_severity(v),
                    "aliases": v.get("aliases", []),
                    "published": v.get("published", ""),
                    "modified": v.get("modified", ""),
                    "references": [r.get("url") for r in v.get("references", [])[:3]],
                    "affected_ranges": [
                        {
                            "type": ar.get("type"),
                            "events": ar.get("events", []),
                        }
                        for affected in v.get("affected", [])
                        for ar in affected.get("ranges", [])
                    ][:3],
                }
                for v in vulns
            ]
        except Exception as e:
            logger.error("scanner.dep.osv_error", package=name, error=str(e))
            return []

    async def scan_requirements(self, requirements: str, ecosystem: str = "PyPI") -> dict:
        """Scan a requirements.txt-style string for vulnerabilities."""
        with tracer.start_as_current_span("dep_scan") as span:
            span.set_attribute("ecosystem", ecosystem)

            packages = self._parse_requirements(requirements)
            all_vulns: list[dict] = []
            scanned = 0
            vulnerable = 0

            for name, version in packages:
                if not version:
                    continue
                vulns = await self.scan_package(name, version, ecosystem)
                scanned += 1
                if vulns:
                    vulnerable += 1
                    for v in vulns:
                        v["package"] = name
                        v["version"] = version
                        all_vulns.append(v)

            severity_counts = {}
            for v in all_vulns:
                sev = v.get("severity", "unknown")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            logger.info(
                "scanner.dep.scan_complete",
                packages_scanned=scanned,
                vulnerable=vulnerable,
                total_vulns=len(all_vulns),
            )

            return {
                "ecosystem": ecosystem,
                "packages_scanned": scanned,
                "vulnerable_packages": vulnerable,
                "total_vulnerabilities": len(all_vulns),
                "severity_summary": severity_counts,
                "vulnerabilities": all_vulns,
            }

    def _parse_requirements(self, text: str) -> list[tuple[str, str]]:
        """Parse requirements.txt format into (name, version) tuples."""
        packages = []
        for line in text.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            if "==" in line:
                parts = line.split("==")
                packages.append((parts[0].strip(), parts[1].strip().split(";")[0].strip()))
            elif ">=" in line:
                parts = line.split(">=")
                packages.append((parts[0].strip(), parts[1].strip().split(",")[0].strip()))
            else:
                packages.append((line.split("[")[0].strip(), ""))
        return packages

    async def scan_npm(self, package_json: dict) -> dict:
        """Scan npm package.json dependencies."""
        deps = {}
        deps.update(package_json.get("dependencies", {}))
        deps.update(package_json.get("devDependencies", {}))

        req_lines = "\n".join(f"{name}=={ver.lstrip('^~')}" for name, ver in deps.items())
        return await self.scan_requirements(req_lines, ecosystem="npm")

    def _map_severity(self, vuln: dict) -> str:
        """Map OSV severity to our severity levels."""
        severity_data = vuln.get("database_specific", {}).get("severity")
        if severity_data:
            s = severity_data.upper()
            if "CRITICAL" in s:
                return "critical"
            elif "HIGH" in s:
                return "high"
            elif "MODERATE" in s or "MEDIUM" in s:
                return "medium"
            elif "LOW" in s:
                return "low"

        # Check CVSS from severity list
        for sev in vuln.get("severity", []):
            score = sev.get("score", "")
            if score:
                try:
                    cvss = float(score.split("/")[0].replace("CVSS:3.1/AV:", ""))
                except (ValueError, IndexError):
                    pass

        # Fallback: check aliases for CVE
        if any(a.startswith("CVE") for a in vuln.get("aliases", [])):
            return "medium"
        return "unknown"

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
