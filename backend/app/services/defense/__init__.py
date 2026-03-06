"""OfSec V3 — Defense Services Package."""

from __future__ import annotations
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
from app.services.defense.orchestrator import DefenseOrchestrator
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

__all__ = [
    "DefenseOrchestrator",
    "PlaybookEngine", "AlertTriageEngine", "EvidenceCollector",
    "LogAggregator", "CorrelationEngine", "SecurityDashboardData",
    "ThreatHuntingEngine", "IOCSweepEngine", "BehavioralHunter",
    "FirewallRuleManager", "PatchManager", "QuarantineManager",
    "HealthMonitor", "ComplianceDriftMonitor", "SLATracker",
]
