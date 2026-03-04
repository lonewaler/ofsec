"""
OfSec V3 — #72-74 Threat Hunting
===================================
Proactive threat hunting capabilities: hypothesis-driven, IOC sweeps,
and behavioral hunting.
"""

import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

import httpx
import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("defense.hunting")


# ─── #72 Hypothesis-Driven Hunting ──────────

class ThreatHuntingEngine:
    """Hypothesis-based threat hunting framework."""

    HUNT_HYPOTHESES = {
        "h001_apt_persistence": {
            "name": "APT Persistence Mechanisms",
            "hypothesis": "Adversaries have established persistence via scheduled tasks, registry keys, or startup items",
            "data_sources": ["process_logs", "registry_changes", "scheduled_tasks"],
            "indicators": [
                "New scheduled task with encoded command",
                "Registry Run key modified",
                "Startup folder file addition",
                "WMI event subscription created",
            ],
            "mitre": ["T1053", "T1547", "T1546"],
        },
        "h002_credential_theft": {
            "name": "Credential Theft Activity",
            "hypothesis": "Adversaries are harvesting credentials using memory dumping or keylogging",
            "data_sources": ["process_logs", "sysmon", "auth_logs"],
            "indicators": [
                "LSASS process access",
                "Mimikatz artifact detected",
                "Unusual DCSync traffic",
                "Kerberos ticket anomalies",
            ],
            "mitre": ["T1003", "T1558", "T1056"],
        },
        "h003_c2_communication": {
            "name": "Command & Control Communication",
            "hypothesis": "Compromised hosts are communicating with C2 infrastructure",
            "data_sources": ["dns_logs", "proxy_logs", "netflow"],
            "indicators": [
                "Beaconing patterns (regular interval connections)",
                "DNS queries to DGA domains",
                "HTTPS connections to uncategorized domains",
                "Data in DNS TXT records",
            ],
            "mitre": ["T1071", "T1568", "T1573"],
        },
        "h004_insider_threat": {
            "name": "Insider Threat Activity",
            "hypothesis": "An insider is exfiltrating data or abusing access privileges",
            "data_sources": ["dlp_logs", "file_access", "email_logs", "cloud_logs"],
            "indicators": [
                "Bulk file downloads off-hours",
                "USB device connections to sensitive servers",
                "Email forwarding rules to external domains",
                "Cloud storage uploads of sensitive files",
            ],
            "mitre": ["T1005", "T1567", "T1052"],
        },
    }

    def __init__(self):
        self._active_hunts: dict[str, dict] = {}
        self._hunt_results: dict[str, list[dict]] = defaultdict(list)

    def list_hypotheses(self) -> list[dict]:
        return [
            {"id": k, "name": v["name"], "mitre": v["mitre"]}
            for k, v in self.HUNT_HYPOTHESES.items()
        ]

    def start_hunt(self, hypothesis_id: str, hunter: str = "system") -> dict:
        """Start a threat hunt based on a hypothesis."""
        hyp = self.HUNT_HYPOTHESES.get(hypothesis_id)
        if not hyp:
            return {"error": f"Unknown hypothesis: {hypothesis_id}"}

        hunt_id = f"HUNT-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{hypothesis_id}"
        hunt = {
            "id": hunt_id,
            "hypothesis": hyp,
            "hunter": hunter,
            "status": "active",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "findings": [],
        }
        self._active_hunts[hunt_id] = hunt
        logger.info("defense.hunting.started", hunt_id=hunt_id, hypothesis=hypothesis_id)
        return hunt

    def add_finding(self, hunt_id: str, finding: dict) -> dict:
        hunt = self._active_hunts.get(hunt_id)
        if not hunt:
            return {"error": f"Hunt not found: {hunt_id}"}

        finding["found_at"] = datetime.now(timezone.utc).isoformat()
        hunt["findings"].append(finding)
        return finding

    def close_hunt(self, hunt_id: str, conclusion: str) -> dict:
        hunt = self._active_hunts.get(hunt_id)
        if not hunt:
            return {"error": f"Hunt not found: {hunt_id}"}

        hunt["status"] = "closed"
        hunt["conclusion"] = conclusion
        hunt["closed_at"] = datetime.now(timezone.utc).isoformat()
        return hunt


# ─── #73 IOC Sweep Engine ───────────────────

class IOCSweepEngine:
    """Sweep infrastructure for known Indicators of Compromise."""

    def __init__(self):
        self._ioc_database: dict[str, list[str]] = {
            "ip": [],
            "domain": [],
            "hash": [],
            "url": [],
        }

    def load_iocs(self, iocs: dict[str, list[str]]) -> dict:
        """Load IOCs for sweeping."""
        total = 0
        for ioc_type, values in iocs.items():
            if ioc_type in self._ioc_database:
                self._ioc_database[ioc_type].extend(values)
                total += len(values)
        return {"loaded": total, "types": {k: len(v) for k, v in self._ioc_database.items()}}

    async def sweep_logs(self, logs: list[str]) -> dict:
        """Sweep log entries for IOC matches."""
        with tracer.start_as_current_span("ioc_sweep"):
            matches = []
            for i, log in enumerate(logs):
                log_lower = log.lower()
                for ioc_type, iocs in self._ioc_database.items():
                    for ioc in iocs:
                        if ioc.lower() in log_lower:
                            matches.append({
                                "ioc": ioc,
                                "type": ioc_type,
                                "log_line": i + 1,
                                "log_excerpt": log[:200],
                            })

            return {
                "logs_scanned": len(logs),
                "matches": len(matches),
                "ioc_matches": matches[:100],
            }

    async def check_threat_feed(self, ioc_value: str) -> dict:
        """Check an IOC against threat intelligence feeds."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            results = []

            # Check AbuseIPDB
            try:
                resp = await client.get(
                    f"https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ioc_value},
                    headers={"Key": "", "Accept": "application/json"},
                )
                if resp.status_code == 200:
                    results.append({"feed": "AbuseIPDB", "data": resp.json()})
            except Exception:
                pass

            # Check VirusTotal (would need API key)
            try:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}",
                    headers={"x-apikey": ""},
                )
                if resp.status_code == 200:
                    results.append({"feed": "VirusTotal", "data": resp.json()})
            except Exception:
                pass

            return {"ioc": ioc_value, "feeds_checked": 2, "results": results}


# ─── #74 Behavioral Hunting ─────────────────

class BehavioralHunter:
    """Detect threats through behavioral analysis patterns."""

    BEHAVIORAL_RULES = {
        "beacon_detection": {
            "name": "C2 Beaconing Detection",
            "description": "Detect regular-interval network connections (C2 callbacks)",
            "method": "time_series_periodicity",
        },
        "dga_detection": {
            "name": "DGA Domain Detection",
            "description": "Detect algorithmically generated domains",
            "method": "entropy_analysis",
        },
        "process_hollowing": {
            "name": "Process Hollowing Detection",
            "description": "Detect process hollowing via memory analysis",
            "method": "process_comparison",
        },
        "living_off_land": {
            "name": "Living-off-the-Land Detection",
            "description": "Detect abuse of legitimate system tools",
            "method": "baseline_comparison",
        },
    }

    @staticmethod
    def detect_beaconing(timestamps: list[float], tolerance: float = 0.1) -> dict:
        """Detect periodic beaconing in connection timestamps."""
        if len(timestamps) < 3:
            return {"beaconing": False, "reason": "Insufficient data"}

        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        if not intervals:
            return {"beaconing": False}

        import statistics
        mean = statistics.mean(intervals)
        stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0

        cv = stdev / mean if mean > 0 else float("inf")

        return {
            "beaconing": cv < tolerance,
            "interval_mean": round(mean, 2),
            "interval_stdev": round(stdev, 2),
            "coefficient_of_variation": round(cv, 4),
            "confidence": "high" if cv < 0.05 else "medium" if cv < tolerance else "low",
        }

    @staticmethod
    def detect_dga(domain: str) -> dict:
        """Detect DGA domains via entropy and character analysis."""
        import math
        # Remove TLD
        parts = domain.split(".")
        name = parts[0] if parts else domain

        # Character frequency entropy
        freq: dict[str, int] = {}
        for c in name:
            freq[c] = freq.get(c, 0) + 1

        length = len(name)
        entropy = -sum((count/length) * math.log2(count/length) for count in freq.values()) if length > 0 else 0

        # Consonant/vowel ratio
        vowels = sum(1 for c in name.lower() if c in "aeiou")
        consonants = sum(1 for c in name.lower() if c.isalpha() and c not in "aeiou")
        ratio = consonants / max(vowels, 1)

        # Digit density
        digits = sum(1 for c in name if c.isdigit())
        digit_density = digits / max(length, 1)

        is_dga = entropy > 3.5 and (ratio > 4 or digit_density > 0.3 or length > 15)

        return {
            "domain": domain,
            "is_dga": is_dga,
            "entropy": round(entropy, 3),
            "consonant_vowel_ratio": round(ratio, 2),
            "digit_density": round(digit_density, 2),
            "length": length,
            "confidence": "high" if entropy > 4.0 else "medium" if entropy > 3.5 else "low",
        }

    def list_rules(self) -> list[dict]:
        return [{"id": k, **v} for k, v in self.BEHAVIORAL_RULES.items()]
