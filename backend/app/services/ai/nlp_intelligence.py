"""
OfSec V3 — #49-51 NLP Threat Intelligence
============================================
Natural Language Processing for threat report analysis, CVE parsing,
and dark web monitoring.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import UTC, datetime

import httpx
import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("ai.nlp")


# ─── #49 Threat Report Parser ────────────────

class ThreatReportParser:
    """Parse and extract intelligence from threat reports."""

    # IOC extraction patterns
    IOC_PATTERNS = {
        "ipv4": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        "ipv6": r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        "domain": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|xyz|info|ru|cn|tk|ml|ga|cf|top|pw)\b',
        "url": r'https?://[^\s<>"\'{}|\\^`\[\]]+',
        "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "md5": r'\b[a-fA-F0-9]{32}\b',
        "sha1": r'\b[a-fA-F0-9]{40}\b',
        "sha256": r'\b[a-fA-F0-9]{64}\b',
        "cve": r'CVE-\d{4}-\d{4,}',
        "mitre_technique": r'T\d{4}(?:\.\d{3})?',
        "bitcoin_address": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
        "registry_key": r'HKEY_[A-Z_]+\\[^\s]+',
        "file_path_unix": r'/(?:etc|tmp|var|usr|opt|home)/[^\s]+',
        "file_path_windows": r'[A-Z]:\\(?:[^\s\\]+\\)*[^\s\\]+',
    }

    # Threat actor name patterns
    KNOWN_ACTORS = [
        "APT28", "APT29", "APT38", "APT41", "Lazarus", "Cozy Bear",
        "Fancy Bear", "Turla", "Sandworm", "Kimsuky", "Charming Kitten",
        "DarkSide", "REvil", "LockBit", "BlackCat", "ALPHV",
        "Conti", "Cl0p", "Play", "Royal", "BlackBasta",
    ]

    def extract_iocs(self, text: str) -> dict:
        """Extract all IOCs from text."""
        with tracer.start_as_current_span("ioc_extraction"):
            iocs: dict[str, list[str]] = {}

            for ioc_type, pattern in self.IOC_PATTERNS.items():
                matches = list(set(re.findall(pattern, text)))
                if matches:
                    iocs[ioc_type] = matches[:50]  # Cap per type

            total = sum(len(v) for v in iocs.values())
            logger.info("ai.nlp.iocs_extracted", total=total)
            return {"total_iocs": total, "iocs": iocs}

    def extract_threat_actors(self, text: str) -> list[str]:
        """Identify threat actor mentions."""
        found = []
        text_lower = text.lower()
        for actor in self.KNOWN_ACTORS:
            if actor.lower() in text_lower:
                found.append(actor)
        return found

    def parse_report(self, text: str) -> dict:
        """Full threat report parsing."""
        with tracer.start_as_current_span("threat_report_parse"):
            iocs = self.extract_iocs(text)
            actors = self.extract_threat_actors(text)

            # Extract key sentences containing threat keywords
            threat_keywords = [
                "vulnerability", "exploit", "malware", "ransomware", "phishing",
                "backdoor", "trojan", "zero-day", "command and control", "lateral",
                "exfiltration", "persistence", "privilege escalation", "brute force",
            ]
            sentences = re.split(r'[.!?]\s+', text)
            key_sentences = [
                s.strip() for s in sentences
                if any(kw in s.lower() for kw in threat_keywords)
            ][:20]

            # Word frequency for topic detection
            words = re.findall(r'\b[a-zA-Z]{4,}\b', text.lower())
            word_freq = Counter(words).most_common(30)

            return {
                "iocs": iocs,
                "threat_actors": actors,
                "key_findings": key_sentences,
                "word_frequency": dict(word_freq),
                "text_length": len(text),
                "analyzed_at": datetime.now(UTC).isoformat(),
            }


# ─── #50 CVE Analyzer ───────────────────────

class CVEAnalyzer:
    """Analyze CVE data and assess impact."""

    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self):
        self._client: httpx.AsyncClient | None = None
        self._cache: dict[str, dict] = {}

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=15.0)
        return self._client

    async def lookup_cve(self, cve_id: str) -> dict:
        """Look up a CVE by ID from NVD."""
        if cve_id in self._cache:
            return self._cache[cve_id]

        client = await self._get_client()
        try:
            resp = await client.get(self.NVD_API, params={"cveId": cve_id})
            resp.raise_for_status()
            data = resp.json()

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return {"cve_id": cve_id, "found": False}

            vuln = vulns[0].get("cve", {})

            # Extract CVSS
            cvss_data = {}
            metrics = vuln.get("metrics", {})
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics:
                    metric = metrics[version][0]["cvssData"]
                    cvss_data = {
                        "version": metric.get("version"),
                        "base_score": metric.get("baseScore"),
                        "severity": metric.get("baseSeverity", "").upper(),
                        "vector": metric.get("vectorString"),
                    }
                    break

            result = {
                "cve_id": cve_id,
                "found": True,
                "description": vuln.get("descriptions", [{}])[0].get("value", ""),
                "published": vuln.get("published", ""),
                "modified": vuln.get("lastModified", ""),
                "cvss": cvss_data,
                "references": [
                    ref.get("url") for ref in vuln.get("references", [])[:5]
                ],
                "weaknesses": [
                    w.get("description", [{}])[0].get("value", "")
                    for w in vuln.get("weaknesses", [])
                ],
            }
            self._cache[cve_id] = result
            return result

        except Exception as e:
            logger.error("ai.nlp.cve_lookup_error", cve_id=cve_id, error=str(e))
            return {"cve_id": cve_id, "found": False, "error": str(e)}

    async def analyze_cves(self, cve_ids: list[str]) -> dict:
        """Analyze multiple CVEs and assess aggregate risk."""
        with tracer.start_as_current_span("cve_analysis"):
            results = []
            for cve_id in cve_ids[:20]:
                result = await self.lookup_cve(cve_id)
                results.append(result)

            # Aggregate risk
            critical = sum(1 for r in results if r.get("cvss", {}).get("severity") == "CRITICAL")
            high = sum(1 for r in results if r.get("cvss", {}).get("severity") == "HIGH")

            return {
                "total_cves": len(cve_ids),
                "analyzed": len(results),
                "risk_summary": {
                    "critical": critical,
                    "high": high,
                    "medium": sum(1 for r in results if r.get("cvss", {}).get("severity") == "MEDIUM"),
                    "low": sum(1 for r in results if r.get("cvss", {}).get("severity") == "LOW"),
                },
                "cves": results,
            }

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()


# ─── #51 Dark Web Monitor ───────────────────

class DarkWebMonitor:
    """Monitor dark web sources for leaked data and threat mentions."""

    # Simulated breach database check
    BREACH_CHECK_APIS = {
        "haveibeenpwned": "https://haveibeenpwned.com/api/v3",
        "dehashed": "https://api.dehashed.com/search",
    }

    def __init__(self):
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=10.0)
        return self._client

    async def check_breach(self, email: str) -> dict:
        """Check if an email appears in known data breaches."""
        client = await self._get_client()
        try:
            resp = await client.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={"User-Agent": "OfSec-V3", "hibp-api-key": ""},
            )
            if resp.status_code == 200:
                breaches = resp.json()
                return {
                    "email": email,
                    "breached": True,
                    "breach_count": len(breaches),
                    "breaches": [
                        {"name": b.get("Name"), "date": b.get("BreachDate"), "data_classes": b.get("DataClasses", [])}
                        for b in breaches[:10]
                    ],
                }
            elif resp.status_code == 404:
                return {"email": email, "breached": False}
            return {"email": email, "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"email": email, "error": str(e)}

    async def monitor_domain(self, domain: str) -> dict:
        """Monitor domain for dark web mentions and data leaks."""
        with tracer.start_as_current_span("darkweb_monitor"):
            # Check common email patterns
            prefixes = ["admin", "info", "support", "contact", "hr", "security"]
            results = []
            for prefix in prefixes:
                email = f"{prefix}@{domain}"
                result = await self.check_breach(email)
                if result.get("breached"):
                    results.append(result)

            return {
                "domain": domain,
                "emails_checked": len(prefixes),
                "breached_accounts": len(results),
                "results": results,
            }

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
