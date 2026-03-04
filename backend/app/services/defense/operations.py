"""
OfSec V3 — #75-77 Automated Remediation + #78-82 Continuous Monitoring
=========================================================================
Automated security remediation and 24/7 monitoring capabilities.
"""

import asyncio
import secrets
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

import httpx
import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("defense.ops")


# ─── #75 Firewall Rule Manager ──────────────

class FirewallRuleManager:
    """Automated firewall rule generation and management."""

    def __init__(self):
        self._rules: list[dict] = []

    def block_ip(self, ip: str, reason: str, duration_hours: int = 24) -> dict:
        rule = {
            "id": f"FW-{secrets.token_hex(4).upper()}",
            "action": "block",
            "type": "ip",
            "value": ip,
            "direction": "inbound",
            "reason": reason,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": None if duration_hours == 0 else datetime.now(timezone.utc).isoformat(),
            "status": "active",
        }
        self._rules.append(rule)
        logger.info("defense.firewall.block_ip", ip=ip, reason=reason)
        return rule

    def block_port(self, port: int, protocol: str = "tcp", reason: str = "") -> dict:
        rule = {
            "id": f"FW-{secrets.token_hex(4).upper()}",
            "action": "block",
            "type": "port",
            "port": port,
            "protocol": protocol,
            "reason": reason,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "active",
        }
        self._rules.append(rule)
        return rule

    def generate_iptables(self) -> list[str]:
        """Generate iptables commands from rules."""
        commands = []
        for rule in self._rules:
            if rule["status"] != "active":
                continue
            if rule["type"] == "ip":
                commands.append(f"iptables -A INPUT -s {rule['value']} -j DROP")
            elif rule["type"] == "port":
                commands.append(
                    f"iptables -A INPUT -p {rule.get('protocol', 'tcp')} --dport {rule['port']} -j DROP"
                )
        return commands

    def generate_nftables(self) -> list[str]:
        """Generate nftables commands."""
        commands = ["nft add table inet filter", "nft add chain inet filter input { type filter hook input priority 0 \\; }"]
        for rule in self._rules:
            if rule["status"] != "active":
                continue
            if rule["type"] == "ip":
                commands.append(f"nft add rule inet filter input ip saddr {rule['value']} drop")
        return commands

    def list_rules(self, status: str = "active") -> list[dict]:
        return [r for r in self._rules if r["status"] == status]


# ─── #76 Patch Manager ──────────────────────

class PatchManager:
    """Track and manage security patches."""

    def __init__(self):
        self._patches: list[dict] = []
        self._advisories: list[dict] = []

    def add_advisory(self, cve_id: str, affected_component: str, severity: str, patch_url: str = "") -> dict:
        advisory = {
            "id": f"ADV-{secrets.token_hex(4).upper()}",
            "cve_id": cve_id,
            "affected_component": affected_component,
            "severity": severity,
            "patch_url": patch_url,
            "status": "pending",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._advisories.append(advisory)
        return advisory

    def schedule_patch(self, advisory_id: str, scheduled_date: str, assignee: str = "") -> dict:
        advisory = next((a for a in self._advisories if a["id"] == advisory_id), None)
        if not advisory:
            return {"error": "Advisory not found"}

        patch = {
            "id": f"PATCH-{secrets.token_hex(4).upper()}",
            "advisory_id": advisory_id,
            "cve_id": advisory["cve_id"],
            "scheduled_date": scheduled_date,
            "assignee": assignee,
            "status": "scheduled",
        }
        self._patches.append(patch)
        advisory["status"] = "scheduled"
        return patch

    def get_patch_status(self) -> dict:
        status_counts: dict[str, int] = defaultdict(int)
        for p in self._patches:
            status_counts[p["status"]] += 1
        return {
            "total_patches": len(self._patches),
            "status_breakdown": dict(status_counts),
            "pending_advisories": sum(1 for a in self._advisories if a["status"] == "pending"),
        }


# ─── #77 Quarantine Manager ─────────────────

class QuarantineManager:
    """Manage quarantine of compromised assets."""

    def __init__(self):
        self._quarantined: dict[str, dict] = {}

    def quarantine_host(self, host: str, reason: str, severity: str = "high") -> dict:
        entry = {
            "host": host,
            "reason": reason,
            "severity": severity,
            "status": "quarantined",
            "quarantined_at": datetime.now(timezone.utc).isoformat(),
            "network_isolated": True,
            "actions_taken": ["Network isolation", "Agent communication only"],
        }
        self._quarantined[host] = entry
        logger.warning("defense.quarantine.host", host=host, reason=reason)
        return entry

    def release_host(self, host: str, cleared_by: str) -> dict:
        entry = self._quarantined.get(host)
        if not entry:
            return {"error": f"Host {host} not in quarantine"}

        entry["status"] = "released"
        entry["released_at"] = datetime.now(timezone.utc).isoformat()
        entry["cleared_by"] = cleared_by
        return entry

    def list_quarantined(self) -> list[dict]:
        return [v for v in self._quarantined.values() if v["status"] == "quarantined"]


# ─── #78-80 Health Monitor ──────────────────

class HealthMonitor:
    """Continuous health monitoring for infrastructure."""

    def __init__(self):
        self._checks: dict[str, dict] = {}
        self._history: dict[str, list[dict]] = defaultdict(list)

    async def check_endpoint(self, name: str, url: str, expected_status: int = 200) -> dict:
        """Check if an endpoint is healthy."""
        start = datetime.now(timezone.utc)
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url)
                elapsed = (datetime.now(timezone.utc) - start).total_seconds()
                healthy = resp.status_code == expected_status

                result = {
                    "name": name,
                    "url": url,
                    "status": "healthy" if healthy else "unhealthy",
                    "status_code": resp.status_code,
                    "response_time_ms": round(elapsed * 1000, 1),
                    "checked_at": datetime.now(timezone.utc).isoformat(),
                }
        except Exception as e:
            result = {
                "name": name,
                "url": url,
                "status": "down",
                "error": str(e),
                "checked_at": datetime.now(timezone.utc).isoformat(),
            }

        self._checks[name] = result
        self._history[name].append(result)
        return result

    async def check_all(self, endpoints: dict[str, str]) -> dict:
        """Check multiple endpoints concurrently."""
        tasks = [self.check_endpoint(name, url) for name, url in endpoints.items()]
        results = await asyncio.gather(*tasks)

        healthy = sum(1 for r in results if r.get("status") == "healthy")
        return {
            "total": len(results),
            "healthy": healthy,
            "unhealthy": len(results) - healthy,
            "results": results,
        }

    def get_uptime(self, name: str) -> dict:
        history = self._history.get(name, [])
        if not history:
            return {"name": name, "uptime": 0, "checks": 0}

        healthy_count = sum(1 for h in history if h.get("status") == "healthy")
        return {
            "name": name,
            "uptime_percent": round((healthy_count / len(history)) * 100, 2),
            "total_checks": len(history),
            "healthy_checks": healthy_count,
        }


# ─── #81 Compliance Drift Monitor ───────────

class ComplianceDriftMonitor:
    """Monitor for compliance configuration drift."""

    FRAMEWORKS = {
        "pci_dss": {
            "name": "PCI DSS",
            "controls": [
                {"id": "1.1", "description": "Firewall configuration standards", "category": "network"},
                {"id": "2.1", "description": "Change vendor defaults", "category": "system"},
                {"id": "3.4", "description": "Render PAN unreadable", "category": "data"},
                {"id": "6.5", "description": "Address common coding vulnerabilities", "category": "app"},
                {"id": "8.2", "description": "Authentication methods", "category": "access"},
                {"id": "10.1", "description": "Audit trails", "category": "monitoring"},
            ],
        },
        "nist_csf": {
            "name": "NIST Cybersecurity Framework",
            "controls": [
                {"id": "ID.AM", "description": "Asset Management", "category": "identify"},
                {"id": "PR.AC", "description": "Access Control", "category": "protect"},
                {"id": "DE.CM", "description": "Continuous Monitoring", "category": "detect"},
                {"id": "RS.RP", "description": "Response Planning", "category": "respond"},
                {"id": "RC.RP", "description": "Recovery Planning", "category": "recover"},
            ],
        },
        "iso_27001": {
            "name": "ISO 27001",
            "controls": [
                {"id": "A.5", "description": "Information security policies", "category": "governance"},
                {"id": "A.9", "description": "Access control", "category": "access"},
                {"id": "A.12", "description": "Operations security", "category": "operations"},
                {"id": "A.14", "description": "System acquisition, development", "category": "dev"},
                {"id": "A.16", "description": "Incident management", "category": "incident"},
            ],
        },
    }

    def __init__(self):
        self._baselines: dict[str, dict] = {}
        self._drift_events: list[dict] = []

    def set_baseline(self, framework: str, control_statuses: dict[str, str]) -> dict:
        self._baselines[framework] = {
            "framework": framework,
            "controls": control_statuses,
            "set_at": datetime.now(timezone.utc).isoformat(),
        }
        return {"framework": framework, "controls_baselined": len(control_statuses)}

    def check_drift(self, framework: str, current_statuses: dict[str, str]) -> dict:
        baseline = self._baselines.get(framework)
        if not baseline:
            return {"error": f"No baseline for {framework}"}

        drifts = []
        for control_id, current_status in current_statuses.items():
            baseline_status = baseline["controls"].get(control_id)
            if baseline_status and current_status != baseline_status:
                drifts.append({
                    "control": control_id,
                    "baseline": baseline_status,
                    "current": current_status,
                    "drift_type": "regression" if current_status == "non_compliant" else "improvement",
                })

        result = {
            "framework": framework,
            "total_controls": len(current_statuses),
            "drifts_detected": len(drifts),
            "drifts": drifts,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
        if drifts:
            self._drift_events.append(result)
        return result

    def list_frameworks(self) -> list[dict]:
        return [
            {"id": k, "name": v["name"], "controls": len(v["controls"])}
            for k, v in self.FRAMEWORKS.items()
        ]


# ─── #82 SLA Tracker ────────────────────────

class SLATracker:
    """Track SLA compliance for security operations."""

    DEFAULT_SLAS = {
        "critical_response": {"name": "Critical Incident Response", "target_minutes": 15},
        "high_response": {"name": "High Incident Response", "target_minutes": 60},
        "medium_response": {"name": "Medium Incident Response", "target_minutes": 240},
        "patch_critical": {"name": "Critical Patch Deployment", "target_minutes": 1440},
        "scan_frequency": {"name": "Vulnerability Scan Frequency", "target_days": 7},
    }

    def __init__(self):
        self._records: list[dict] = []

    def record_event(self, sla_type: str, actual_minutes: float) -> dict:
        sla = self.DEFAULT_SLAS.get(sla_type)
        if not sla:
            return {"error": f"Unknown SLA: {sla_type}"}

        target = sla.get("target_minutes", sla.get("target_days", 0) * 1440)
        met = actual_minutes <= target

        record = {
            "sla_type": sla_type,
            "sla_name": sla["name"],
            "target_minutes": target,
            "actual_minutes": actual_minutes,
            "met": met,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        self._records.append(record)
        return record

    def get_compliance_report(self) -> dict:
        if not self._records:
            return {"total": 0, "compliance_rate": 0}

        met = sum(1 for r in self._records if r["met"])
        by_type: dict[str, dict] = {}

        for r in self._records:
            t = r["sla_type"]
            if t not in by_type:
                by_type[t] = {"total": 0, "met": 0}
            by_type[t]["total"] += 1
            if r["met"]:
                by_type[t]["met"] += 1

        for t_data in by_type.values():
            t_data["rate"] = round((t_data["met"] / t_data["total"]) * 100, 1)

        return {
            "total_records": len(self._records),
            "overall_compliance": round((met / len(self._records)) * 100, 1),
            "by_type": by_type,
        }
