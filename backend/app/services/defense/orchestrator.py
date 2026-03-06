"""
OfSec V3 — Defense Engine Orchestrator
=========================================
Central orchestrator for all defense and operations modules (#66-82).
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog

from app.core.telemetry import get_tracer
from app.services.defense.incident_response import (
    AlertTriageEngine,
    EvidenceCollector,
    PlaybookEngine,
)
from app.services.defense.operations import (
    ComplianceDriftMonitor,
    FirewallRuleManager,
    HealthMonitor,
    PatchManager,
    QuarantineManager,
    SLATracker,
)
from app.services.defense.siem_integration import (
    CorrelationEngine,
    LogAggregator,
    SecurityDashboardData,
)
from app.services.defense.threat_hunting import (
    BehavioralHunter,
    IOCSweepEngine,
    ThreatHuntingEngine,
)

logger = structlog.get_logger()
tracer = get_tracer("defense.orchestrator")


class DefenseOrchestrator:
    """Central defense and operations orchestrator (Upgrades #66-82)."""

    def __init__(self):
        # Incident Response
        self.playbooks = PlaybookEngine()
        self.triage = AlertTriageEngine()
        self.evidence = EvidenceCollector()

        # SIEM
        self.log_aggregator = LogAggregator()
        self.correlation = CorrelationEngine()
        self.dashboard_data = SecurityDashboardData()

        # Threat Hunting
        self.hunting = ThreatHuntingEngine()
        self.ioc_sweep = IOCSweepEngine()
        self.behavioral = BehavioralHunter()

        # Remediation
        self.firewall = FirewallRuleManager()
        self.patch_mgr = PatchManager()
        self.quarantine = QuarantineManager()

        # Monitoring
        self.health = HealthMonitor()
        self.compliance = ComplianceDriftMonitor()
        self.sla = SLATracker()

    async def process_security_event(self, event: dict) -> dict:
        """Process a security event through the full defense pipeline."""
        with tracer.start_as_current_span("defense.pipeline"):
            results = {"event": event, "pipeline": []}

            # 1. Log aggregation
            self.log_aggregator.ingest(
                event.get("raw", str(event)),
                source=event.get("source", "unknown"),
            )
            results["pipeline"].append("log_ingested")

            # 2. Correlation
            triggered_rules = self.correlation.add_event(event)
            if triggered_rules:
                results["triggered_rules"] = triggered_rules
                results["pipeline"].append("rules_triggered")

            # 3. Alert triage
            if triggered_rules:
                for rule_alert in triggered_rules:
                    triaged = self.triage.ingest_alert(rule_alert)
                    results["triaged_alert"] = triaged
                    results["pipeline"].append("alert_triaged")

                    # 4. Auto-remediation for critical
                    if triaged.get("priority_level") == "P1":
                        source_ip = event.get("source_ip")
                        if source_ip:
                            fw_rule = self.firewall.block_ip(
                                source_ip,
                                reason=f"Auto-block: {rule_alert.get('rule_name', 'Critical alert')}",
                            )
                            results["auto_remediation"] = fw_rule
                            results["pipeline"].append("auto_blocked")

            # 5. Dashboard metrics
            self.dashboard_data.record_metric(
                "events_processed", 1.0,
                {"source": event.get("source", "unknown")},
            )

            return results

    async def run_health_check(self, endpoints: dict[str, str]) -> dict:
        """Run health checks on all endpoints."""
        return await self.health.check_all(endpoints)

    async def sweep_for_iocs(self, logs: list[str], iocs: dict) -> dict:
        """Load IOCs and sweep logs."""
        self.ioc_sweep.load_iocs(iocs)
        return await self.ioc_sweep.sweep_logs(logs)

    def get_security_posture(self) -> dict:
        """Get overall security posture summary."""
        return {
            "active_incidents": len(self.playbooks.list_incidents("active")),
            "open_alerts": len(self.triage.get_queue()),
            "quarantined_hosts": len(self.quarantine.list_quarantined()),
            "firewall_rules": len(self.firewall.list_rules()),
            "correlation_rules": len(self.correlation.list_rules()),
            "sla_compliance": self.sla.get_compliance_report(),
            "log_stats": self.log_aggregator.get_stats(),
            "generated_at": datetime.now(UTC).isoformat(),
        }
