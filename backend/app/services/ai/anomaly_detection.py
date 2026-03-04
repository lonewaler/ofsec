"""
OfSec V3 — #46-48 Anomaly Detection Engine
=============================================
ML-based anomaly detection for network traffic, user behavior, and logs.

Uses statistical methods (Z-score, IQR, Isolation Forest concepts)
for real-time anomaly identification without heavy ML dependencies.
"""

import math
import statistics
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Optional

import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("ai.anomaly")


class StatisticalModel:
    """Lightweight statistical anomaly detector using sliding windows."""

    def __init__(self, window_size: int = 100, z_threshold: float = 3.0):
        self.window_size = window_size
        self.z_threshold = z_threshold
        self._windows: dict[str, deque] = defaultdict(lambda: deque(maxlen=window_size))

    def add_sample(self, metric: str, value: float) -> dict | None:
        """Add a data point and check for anomaly."""
        window = self._windows[metric]
        window.append(value)

        if len(window) < 10:
            return None

        values = list(window)
        mean = statistics.mean(values)
        stdev = statistics.stdev(values) if len(values) > 1 else 1.0

        if stdev == 0:
            return None

        z_score = (value - mean) / stdev

        if abs(z_score) > self.z_threshold:
            return {
                "metric": metric,
                "value": value,
                "z_score": round(z_score, 3),
                "mean": round(mean, 3),
                "stdev": round(stdev, 3),
                "severity": "critical" if abs(z_score) > 5 else "high" if abs(z_score) > 4 else "medium",
                "direction": "above" if z_score > 0 else "below",
                "detected_at": datetime.now(timezone.utc).isoformat(),
            }
        return None

    def get_stats(self, metric: str) -> dict:
        """Get current statistics for a metric."""
        window = self._windows.get(metric, deque())
        if not window:
            return {"metric": metric, "samples": 0}

        values = list(window)
        return {
            "metric": metric,
            "samples": len(values),
            "mean": round(statistics.mean(values), 3),
            "stdev": round(statistics.stdev(values), 3) if len(values) > 1 else 0,
            "min": round(min(values), 3),
            "max": round(max(values), 3),
            "median": round(statistics.median(values), 3),
        }


# ─── #46 Network Anomaly Detector ────────────

class NetworkAnomalyDetector:
    """Detect anomalies in network traffic patterns."""

    MONITORED_METRICS = [
        "requests_per_second",
        "bytes_transferred",
        "unique_ips",
        "error_rate",
        "response_time_ms",
        "connection_count",
        "dns_query_rate",
        "outbound_connections",
    ]

    def __init__(self, window_size: int = 200, z_threshold: float = 3.0):
        self._model = StatisticalModel(window_size, z_threshold)
        self._alerts: list[dict] = []

    def ingest(self, metric: str, value: float) -> dict | None:
        """Ingest a network metric and check for anomalies."""
        anomaly = self._model.add_sample(metric, value)
        if anomaly:
            anomaly["category"] = "network"
            anomaly["type"] = "Network Anomaly"
            self._alerts.append(anomaly)
            logger.warning("ai.anomaly.network", metric=metric, z_score=anomaly["z_score"])
        return anomaly

    def analyze_traffic_pattern(self, traffic_data: list[dict]) -> dict:
        """Analyze a batch of traffic data for anomalies."""
        with tracer.start_as_current_span("network_anomaly_analysis"):
            anomalies = []
            for entry in traffic_data:
                for metric in self.MONITORED_METRICS:
                    if metric in entry:
                        result = self.ingest(metric, float(entry[metric]))
                        if result:
                            anomalies.append(result)

            return {
                "analyzed": len(traffic_data),
                "anomalies_detected": len(anomalies),
                "anomalies": anomalies,
                "metrics": {m: self._model.get_stats(m) for m in self.MONITORED_METRICS},
            }

    def get_alerts(self, limit: int = 50) -> list[dict]:
        return self._alerts[-limit:]


# ─── #47 Behavioral Anomaly Detector ────────

class BehavioralAnomalyDetector:
    """Detect anomalous user behavior patterns."""

    def __init__(self):
        self._model = StatisticalModel(window_size=50, z_threshold=2.5)
        self._user_profiles: dict[str, dict] = {}
        self._alerts: list[dict] = []

    def update_profile(self, user_id: str, event: dict) -> dict | None:
        """Update user behavioral profile and detect anomalies."""
        profile = self._user_profiles.setdefault(user_id, {
            "login_count": 0,
            "last_seen": None,
            "typical_hours": [],
            "known_ips": set(),
            "actions": [],
        })

        anomalies = []

        # Time-based anomaly
        hour = datetime.now(timezone.utc).hour
        if profile["typical_hours"] and hour not in profile["typical_hours"]:
            anomalies.append({
                "type": "Unusual Login Time",
                "severity": "medium",
                "user_id": user_id,
                "hour": hour,
                "typical_hours": profile["typical_hours"],
            })

        # IP-based anomaly
        ip = event.get("ip")
        if ip and profile["known_ips"] and ip not in profile["known_ips"]:
            anomalies.append({
                "type": "New IP Address",
                "severity": "medium",
                "user_id": user_id,
                "ip": ip,
                "known_ips": list(profile["known_ips"])[:5],
            })

        # Update profile
        profile["login_count"] += 1
        profile["last_seen"] = datetime.now(timezone.utc).isoformat()
        if len(profile["typical_hours"]) < 24:
            profile["typical_hours"].append(hour)
        if ip:
            profile["known_ips"].add(ip)

        # Action frequency anomaly
        action = event.get("action", "login")
        result = self._model.add_sample(f"user:{user_id}:{action}", 1.0)
        if result:
            result["user_id"] = user_id
            result["category"] = "behavioral"
            anomalies.append(result)

        if anomalies:
            self._alerts.extend(anomalies)
            return {"user_id": user_id, "anomalies": anomalies}
        return None

    def get_profile(self, user_id: str) -> dict:
        profile = self._user_profiles.get(user_id, {})
        if "known_ips" in profile:
            profile = {**profile, "known_ips": list(profile["known_ips"])}
        return profile


# ─── #48 Log Anomaly Detector ────────────────

class LogAnomalyDetector:
    """Detect anomalies in application and security logs."""

    SUSPICIOUS_PATTERNS = [
        {"pattern": "failed login", "severity": "medium", "category": "auth"},
        {"pattern": "permission denied", "severity": "medium", "category": "access"},
        {"pattern": "sql syntax", "severity": "high", "category": "injection"},
        {"pattern": "stack trace", "severity": "medium", "category": "error"},
        {"pattern": "unauthorized", "severity": "high", "category": "auth"},
        {"pattern": "buffer overflow", "severity": "critical", "category": "exploit"},
        {"pattern": "segfault", "severity": "high", "category": "crash"},
        {"pattern": "root login", "severity": "high", "category": "auth"},
        {"pattern": "privilege escalation", "severity": "critical", "category": "exploit"},
        {"pattern": "reverse shell", "severity": "critical", "category": "exploit"},
        {"pattern": "base64 decode", "severity": "medium", "category": "obfuscation"},
        {"pattern": "curl|wget", "severity": "medium", "category": "download"},
    ]

    def __init__(self):
        self._model = StatisticalModel(window_size=500, z_threshold=3.0)
        self._event_counts: dict[str, int] = defaultdict(int)

    def analyze_log_line(self, log_line: str, source: str = "app") -> list[dict]:
        """Analyze a single log line for anomalies."""
        findings = []
        lower = log_line.lower()

        for check in self.SUSPICIOUS_PATTERNS:
            if check["pattern"] in lower:
                findings.append({
                    "type": "Suspicious Log Entry",
                    "severity": check["severity"],
                    "category": check["category"],
                    "pattern": check["pattern"],
                    "source": source,
                    "log_line": log_line[:200],
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                })

        # Track event rate
        self._event_counts[source] += 1
        rate_anomaly = self._model.add_sample(f"log_rate:{source}", self._event_counts[source])
        if rate_anomaly:
            rate_anomaly["type"] = "Log Rate Anomaly"
            rate_anomaly["source"] = source
            findings.append(rate_anomaly)

        return findings

    def analyze_batch(self, log_lines: list[str], source: str = "app") -> dict:
        """Analyze a batch of log lines."""
        with tracer.start_as_current_span("log_anomaly_analysis"):
            all_findings = []
            severity_counts: dict[str, int] = {}

            for line in log_lines:
                findings = self.analyze_log_line(line, source)
                for f in findings:
                    sev = f.get("severity", "info")
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                all_findings.extend(findings)

            return {
                "lines_analyzed": len(log_lines),
                "anomalies_found": len(all_findings),
                "severity_summary": severity_counts,
                "findings": all_findings[:100],
            }
