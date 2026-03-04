"""
OfSec V3 — Attack Services Package
=====================================
"""

from app.services.attack.orchestrator import AttackOrchestrator
from app.services.attack.payload_generator import PayloadGenerator
from app.services.attack.exploit_engine import ExploitFramework, BruteForceEngine
from app.services.attack.phishing_engine import PhishingSimulator, SocialEngineeringToolkit
from app.services.attack.post_exploitation import (
    PrivilegeEscalationScanner,
    LateralMovementSimulator,
    DataExfiltrationTester,
)
from app.services.attack.c2_framework import (
    C2Framework,
    WirelessAttackModule,
    MITREAttackMapper,
    AttackReportGenerator,
)

__all__ = [
    "AttackOrchestrator",
    "PayloadGenerator",
    "ExploitFramework",
    "BruteForceEngine",
    "PhishingSimulator",
    "SocialEngineeringToolkit",
    "PrivilegeEscalationScanner",
    "LateralMovementSimulator",
    "DataExfiltrationTester",
    "C2Framework",
    "WirelessAttackModule",
    "MITREAttackMapper",
    "AttackReportGenerator",
]
