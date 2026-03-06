"""
OfSec V3 — #66-68 Incident Response Engine
=============================================
Automated incident response playbooks, alert triage, and evidence collection.
"""

from __future__ import annotations

import secrets
from collections import defaultdict
from datetime import UTC, datetime

import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("defense.incident")


# ─── #66 Incident Response Playbooks ────────

class PlaybookEngine:
    """Manage and execute incident response playbooks."""

    PLAYBOOKS = {
        "malware_detected": {
            "name": "Malware Detection Response",
            "severity": "critical",
            "steps": [
                {"order": 1, "action": "isolate_host", "description": "Isolate the infected host from the network"},
                {"order": 2, "action": "collect_evidence", "description": "Capture memory dump and disk image"},
                {"order": 3, "action": "identify_malware", "description": "Identify malware family and IOCs"},
                {"order": 4, "action": "scan_network", "description": "Scan network for lateral movement indicators"},
                {"order": 5, "action": "block_iocs", "description": "Block identified IOCs at firewall/proxy"},
                {"order": 6, "action": "remediate", "description": "Clean infected systems and restore from backup"},
                {"order": 7, "action": "post_incident", "description": "Document timeline and lessons learned"},
            ],
            "estimated_time_minutes": 120,
        },
        "data_breach": {
            "name": "Data Breach Response",
            "severity": "critical",
            "steps": [
                {"order": 1, "action": "assess_scope", "description": "Determine what data was accessed/exfiltrated"},
                {"order": 2, "action": "contain_breach", "description": "Revoke compromised credentials, block access"},
                {"order": 3, "action": "preserve_evidence", "description": "Preserve logs, network captures, and forensic images"},
                {"order": 4, "action": "notify_stakeholders", "description": "Notify legal, management, and affected users"},
                {"order": 5, "action": "investigate_root_cause", "description": "Identify entry point and attack vector"},
                {"order": 6, "action": "remediate_vulnerabilities", "description": "Patch exploited vulnerabilities"},
                {"order": 7, "action": "regulatory_notification", "description": "File regulatory notifications (GDPR, CCPA, etc.)"},
                {"order": 8, "action": "post_incident_review", "description": "Conduct post-incident review and update policies"},
            ],
            "estimated_time_minutes": 480,
        },
        "phishing_attack": {
            "name": "Phishing Incident Response",
            "severity": "high",
            "steps": [
                {"order": 1, "action": "identify_recipients", "description": "Identify all recipients of phishing email"},
                {"order": 2, "action": "block_sender", "description": "Block sender domain at email gateway"},
                {"order": 3, "action": "remove_emails", "description": "Purge phishing emails from all mailboxes"},
                {"order": 4, "action": "check_clicks", "description": "Identify users who clicked/submitted credentials"},
                {"order": 5, "action": "reset_credentials", "description": "Force password reset for affected accounts"},
                {"order": 6, "action": "scan_endpoints", "description": "Scan endpoints of users who clicked for malware"},
                {"order": 7, "action": "user_notification", "description": "Notify users and provide awareness training"},
            ],
            "estimated_time_minutes": 60,
        },
        "ddos_attack": {
            "name": "DDoS Attack Response",
            "severity": "high",
            "steps": [
                {"order": 1, "action": "activate_mitigation", "description": "Enable DDoS mitigation service (Cloudflare, AWS Shield)"},
                {"order": 2, "action": "rate_limiting", "description": "Apply aggressive rate limiting rules"},
                {"order": 3, "action": "geo_blocking", "description": "Block traffic from attack source regions"},
                {"order": 4, "action": "scale_infrastructure", "description": "Auto-scale backend infrastructure"},
                {"order": 5, "action": "monitor_recovery", "description": "Monitor service recovery and latency"},
                {"order": 6, "action": "post_attack_analysis", "description": "Analyze attack vectors for future prevention"},
            ],
            "estimated_time_minutes": 30,
        },
        "ransomware": {
            "name": "Ransomware Response",
            "severity": "critical",
            "steps": [
                {"order": 1, "action": "isolate_network", "description": "Immediately disconnect affected systems"},
                {"order": 2, "action": "assess_encryption", "description": "Determine ransomware variant and encryption scope"},
                {"order": 3, "action": "check_backups", "description": "Verify backup integrity and recency"},
                {"order": 4, "action": "report_law_enforcement", "description": "Report to FBI IC3 / local cyber crime unit"},
                {"order": 5, "action": "attempt_decryption", "description": "Check for available decryptors (NoMoreRansom)"},
                {"order": 6, "action": "restore_systems", "description": "Restore from clean backups"},
                {"order": 7, "action": "harden_defenses", "description": "Patch entry vector, enhance endpoint protection"},
            ],
            "estimated_time_minutes": 240,
        },
    }

    def __init__(self):
        self._active_incidents: dict[str, dict] = {}

    def list_playbooks(self) -> list[dict]:
        return [
            {"id": k, "name": v["name"], "severity": v["severity"], "steps": len(v["steps"])}
            for k, v in self.PLAYBOOKS.items()
        ]

    def start_incident(self, playbook_id: str, description: str, assignee: str = "") -> dict:
        """Start an incident using a playbook."""
        playbook = self.PLAYBOOKS.get(playbook_id)
        if not playbook:
            return {"error": f"Unknown playbook: {playbook_id}"}

        incident_id = f"INC-{secrets.token_hex(4).upper()}"
        incident = {
            "id": incident_id,
            "playbook": playbook_id,
            "playbook_name": playbook["name"],
            "description": description,
            "severity": playbook["severity"],
            "assignee": assignee,
            "status": "active",
            "created_at": datetime.now(UTC).isoformat(),
            "steps": [
                {**step, "status": "pending", "completed_at": None}
                for step in playbook["steps"]
            ],
            "current_step": 1,
        }
        self._active_incidents[incident_id] = incident
        logger.info("defense.incident.started", incident_id=incident_id, playbook=playbook_id)
        return incident

    def advance_step(self, incident_id: str, notes: str = "") -> dict:
        """Complete current step and advance to next."""
        incident = self._active_incidents.get(incident_id)
        if not incident:
            return {"error": f"Incident not found: {incident_id}"}

        current = incident["current_step"] - 1
        if current < len(incident["steps"]):
            incident["steps"][current]["status"] = "completed"
            incident["steps"][current]["completed_at"] = datetime.now(UTC).isoformat()
            incident["steps"][current]["notes"] = notes

        incident["current_step"] += 1
        if incident["current_step"] > len(incident["steps"]):
            incident["status"] = "resolved"

        return incident

    def get_incident(self, incident_id: str) -> dict:
        return self._active_incidents.get(incident_id, {"error": "Not found"})

    def list_incidents(self, status: str = "active") -> list[dict]:
        return [i for i in self._active_incidents.values() if i["status"] == status]


# ─── #67 Alert Triage Engine ────────────────

class AlertTriageEngine:
    """Automated alert triage and prioritization."""

    SEVERITY_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}

    def __init__(self):
        self._alerts: list[dict] = []
        self._suppression_rules: list[dict] = []

    def ingest_alert(self, alert: dict) -> dict:
        """Ingest and triage an alert."""
        with tracer.start_as_current_span("alert_triage"):
            # Check suppression rules
            for rule in self._suppression_rules:
                if self._matches_rule(alert, rule):
                    return {"alert": alert, "status": "suppressed", "rule": rule["name"]}

            # Calculate priority score
            severity = alert.get("severity", "info")
            base_score = self.SEVERITY_WEIGHTS.get(severity, 0)

            # Boost for repeated alerts
            similar_count = sum(
                1 for a in self._alerts
                if a.get("type") == alert.get("type") and a.get("source") == alert.get("source")
            )
            repeat_boost = min(similar_count * 0.5, 3.0)

            # Boost for critical assets
            asset_boost = 2.0 if alert.get("asset_criticality") == "high" else 0

            priority = base_score + repeat_boost + asset_boost

            triaged = {
                **alert,
                "priority_score": round(priority, 1),
                "priority_level": "P1" if priority >= 10 else "P2" if priority >= 7 else "P3" if priority >= 4 else "P4",
                "similar_alerts": similar_count,
                "triaged_at": datetime.now(UTC).isoformat(),
                "status": "open",
            }
            self._alerts.append(triaged)
            return triaged

    def add_suppression_rule(self, name: str, conditions: dict) -> dict:
        rule = {"name": name, "conditions": conditions, "created_at": datetime.now(UTC).isoformat()}
        self._suppression_rules.append(rule)
        return rule

    def _matches_rule(self, alert: dict, rule: dict) -> bool:
        for key, value in rule.get("conditions", {}).items():
            if alert.get(key) != value:
                return False
        return True

    def get_queue(self, limit: int = 50) -> list[dict]:
        open_alerts = [a for a in self._alerts if a.get("status") == "open"]
        open_alerts.sort(key=lambda x: -x.get("priority_score", 0))
        return open_alerts[:limit]


# ─── #68 Evidence Collection ────────────────

class EvidenceCollector:
    """Collect and preserve digital evidence for incident response."""

    def __init__(self):
        self._evidence_store: dict[str, list[dict]] = defaultdict(list)

    def collect(self, incident_id: str, evidence_type: str, data: dict) -> dict:
        """Collect evidence for an incident."""
        evidence = {
            "id": secrets.token_hex(6),
            "incident_id": incident_id,
            "type": evidence_type,
            "data": data,
            "collected_at": datetime.now(UTC).isoformat(),
            "hash": secrets.token_hex(32),  # In production, hash actual data
            "chain_of_custody": [
                {"action": "collected", "timestamp": datetime.now(UTC).isoformat(), "by": "system"}
            ],
        }
        self._evidence_store[incident_id].append(evidence)
        logger.info("defense.evidence.collected", incident_id=incident_id, type=evidence_type)
        return evidence

    def get_evidence(self, incident_id: str) -> list[dict]:
        return self._evidence_store.get(incident_id, [])

    def generate_chain_of_custody(self, incident_id: str) -> dict:
        evidence_list = self._evidence_store.get(incident_id, [])
        return {
            "incident_id": incident_id,
            "total_evidence": len(evidence_list),
            "evidence": evidence_list,
        }
