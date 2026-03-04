"""OfSec V3 — Defense Services Package."""

from app.services.defense.orchestrator import DefenseOrchestrator
from app.services.defense.incident_response import (
    PlaybookEngine, AlertTriageEngine, EvidenceCollector,
)
from app.services.defense.siem_integration import (
    LogAggregator, CorrelationEngine, SecurityDashboardData,
)
from app.services.defense.threat_hunting import (
    ThreatHuntingEngine, IOCSweepEngine, BehavioralHunter,
)
from app.services.defense.operations import (
    FirewallRuleManager, PatchManager, QuarantineManager,
    HealthMonitor, ComplianceDriftMonitor, SLATracker,
)

__all__ = [
    "DefenseOrchestrator",
    "PlaybookEngine", "AlertTriageEngine", "EvidenceCollector",
    "LogAggregator", "CorrelationEngine", "SecurityDashboardData",
    "ThreatHuntingEngine", "IOCSweepEngine", "BehavioralHunter",
    "FirewallRuleManager", "PatchManager", "QuarantineManager",
    "HealthMonitor", "ComplianceDriftMonitor", "SLATracker",
]
