"""
OfSec V3 — Attack Services Package
=====================================
"""

from __future__ import annotations
from app.services.attack.c2_framework import (
    AttackReportGenerator,
    C2Framework,
    MITREAttackMapper,
    WirelessAttackModule,
)
from app.services.attack.exploit_engine import BruteForceEngine, ExploitFramework
from app.services.attack.orchestrator import AttackOrchestrator
from app.services.attack.payload_generator import PayloadGenerator
from app.services.attack.phishing_engine import PhishingSimulator, SocialEngineeringToolkit
from app.services.attack.post_exploitation import (
    DataExfiltrationTester,
    LateralMovementSimulator,
    PrivilegeEscalationScanner,
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
