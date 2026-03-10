"""
OfSec V3 — #69-71 SIEM Integration
=====================================
Log aggregation, correlation rules, and security event management.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import UTC, datetime

import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("defense.siem")


# ─── #69 Log Aggregator ─────────────────────


class LogAggregator:
    """Centralized log aggregation and normalization."""

    NORMALIZERS = {
        "syslog": r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s*(?P<message>.*)",  # noqa: E501
        "apache": r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<bytes>\d+)',  # noqa: E501
        "json": None,  # JSON logs parsed directly
    }

    def __init__(self):
        self._logs: list[dict] = []
        self._sources: dict[str, int] = defaultdict(int)

    def ingest(self, raw_log: str, source: str = "unknown", log_format: str = "syslog") -> dict:
        """Ingest and normalize a log entry."""
        normalized = self._normalize(raw_log, log_format)
        normalized["source"] = source
        normalized["ingested_at"] = datetime.now(UTC).isoformat()

        self._logs.append(normalized)
        self._sources[source] += 1
        return normalized

    def ingest_batch(self, logs: list[str], source: str = "unknown", log_format: str = "syslog") -> dict:
        results = [self.ingest(log, source, log_format) for log in logs]
        return {"ingested": len(results), "source": source}

    def _normalize(self, raw: str, log_format: str) -> dict:
        if log_format == "json":
            import json

            try:
                return json.loads(raw)
            except Exception:
                return {"raw": raw, "format": "json_parse_error"}

        pattern = self.NORMALIZERS.get(log_format)
        if pattern:
            match = re.match(pattern, raw)
            if match:
                return {**match.groupdict(), "raw": raw, "format": log_format}

        return {"raw": raw, "format": log_format}

    def search(self, query: str, limit: int = 100) -> list[dict]:
        query_lower = query.lower()
        return [
            log
            for log in self._logs
            if query_lower in log.get("raw", "").lower() or query_lower in log.get("message", "").lower()
        ][:limit]

    def get_stats(self) -> dict:
        return {"total_logs": len(self._logs), "sources": dict(self._sources)}


# ─── #70 Correlation Rules Engine ────────────


class CorrelationEngine:
    """Security event correlation using detection rules."""

    RULES = {
        "brute_force": {
            "name": "Brute Force Detection",
            "description": "Multiple failed login attempts from same source",
            "conditions": {"event_type": "auth_failure", "threshold": 5, "window_seconds": 300},
            "severity": "high",
            "mitre": "T1110",
        },
        "port_scan": {
            "name": "Port Scan Detection",
            "description": "Connection attempts to multiple ports from same source",
            "conditions": {"event_type": "connection", "unique_ports_threshold": 10, "window_seconds": 60},
            "severity": "medium",
            "mitre": "T1046",
        },
        "data_exfil": {
            "name": "Data Exfiltration Indicator",
            "description": "Large outbound data transfer to unusual destination",
            "conditions": {"event_type": "network", "bytes_threshold": 104857600, "direction": "outbound"},
            "severity": "critical",
            "mitre": "T1048",
        },
        "lateral_movement": {
            "name": "Lateral Movement Detection",
            "description": "Authentication to multiple internal hosts in short window",
            "conditions": {"event_type": "auth_success", "unique_hosts_threshold": 3, "window_seconds": 600},
            "severity": "critical",
            "mitre": "T1021",
        },
        "privilege_escalation": {
            "name": "Privilege Escalation Attempt",
            "description": "User gaining elevated privileges",
            "conditions": {"event_type": "privilege_change", "to_privilege": "admin"},
            "severity": "critical",
            "mitre": "T1068",
        },
        "suspicious_process": {
            "name": "Suspicious Process Execution",
            "description": "Known attack tool or living-off-the-land binary executed",
            "conditions": {
                "event_type": "process_start",
                "suspicious_names": [
                    "mimikatz",
                    "psexec",
                    "lazagne",
                    "bloodhound",
                    "certutil",
                    "bitsadmin",
                    "mshta",
                    "regsvr32",
                    "rundll32",
                ],
            },
            "severity": "high",
            "mitre": "T1059",
        },
        "anomalous_dns": {
            "name": "Anomalous DNS Activity",
            "description": "Unusually long DNS queries or high volume (potential tunneling)",
            "conditions": {"event_type": "dns", "query_length_threshold": 50, "volume_threshold": 100},
            "severity": "high",
            "mitre": "T1071.004",
        },
    }

    def __init__(self):
        self._events: list[dict] = []
        self._triggered: list[dict] = []

    def add_event(self, event: dict) -> list[dict]:
        """Add a security event and check correlation rules."""
        self._events.append(
            {
                **event,
                "received_at": datetime.now(UTC).isoformat(),
            }
        )

        triggered = []
        for rule_id, rule in self.RULES.items():
            if self._check_rule(rule, event):
                alert = {
                    "rule_id": rule_id,
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "mitre": rule.get("mitre"),
                    "event": event,
                    "triggered_at": datetime.now(UTC).isoformat(),
                }
                triggered.append(alert)
                self._triggered.append(alert)
                logger.warning("defense.siem.rule_triggered", rule=rule_id, severity=rule["severity"])

        return triggered

    def _check_rule(self, rule: dict, event: dict) -> bool:
        conditions = rule["conditions"]
        event_type = conditions.get("event_type")

        if event.get("event_type") != event_type:
            return False

        # Threshold-based checks
        if "threshold" in conditions:
            similar = [
                e
                for e in self._events[-100:]
                if e.get("event_type") == event_type and e.get("source_ip") == event.get("source_ip")
            ]
            return len(similar) >= conditions["threshold"]

        # Process name check
        if "suspicious_names" in conditions:
            process = event.get("process_name", "").lower()
            return process in [n.lower() for n in conditions["suspicious_names"]]

        # Bytes threshold
        if "bytes_threshold" in conditions:
            return event.get("bytes", 0) >= conditions["bytes_threshold"]

        return False

    def list_rules(self) -> list[dict]:
        return [
            {"id": k, "name": v["name"], "severity": v["severity"], "mitre": v.get("mitre")}
            for k, v in self.RULES.items()
        ]

    def get_triggered(self, limit: int = 50) -> list[dict]:
        return self._triggered[-limit:]


# ─── #71 Security Dashboard Data ────────────


class SecurityDashboardData:
    """Aggregate security metrics for dashboard display."""

    def __init__(self):
        self._metrics: dict[str, list[dict]] = defaultdict(list)

    def record_metric(self, metric_name: str, value: float, dimensions: dict | None = None) -> None:
        self._metrics[metric_name].append(
            {
                "value": value,
                "dimensions": dimensions or {},
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )

    def get_summary(self) -> dict:
        summary = {}
        for name, values in self._metrics.items():
            recent = values[-100:]
            nums = [v["value"] for v in recent]
            summary[name] = {
                "current": nums[-1] if nums else 0,
                "avg": round(sum(nums) / len(nums), 2) if nums else 0,
                "min": min(nums) if nums else 0,
                "max": max(nums) if nums else 0,
                "data_points": len(recent),
            }
        return summary
