"""
OfSec V3 — Scanner Services Package
======================================
"""

from __future__ import annotations

from app.services.scanner.advanced_scanner import (
    CloudConfigAuditor,
    ContainerSecurityScanner,
    CredentialTester,
    SubdomainBruteforcer,
    VulnerabilityCorrelator,
    WAFDetector,
)
from app.services.scanner.api_scanner import APISecurityScanner
from app.services.scanner.dependency_scanner import DependencyScanner
from app.services.scanner.header_analyzer import HeaderSecurityAnalyzer
from app.services.scanner.network_scanner import (
    CMSScanner,
    ComplianceAuditor,
    NetworkDiscoveryScanner,
)
from app.services.scanner.orchestrator import ScannerOrchestrator
from app.services.scanner.ssl_auditor import SSLTLSAuditor
from app.services.scanner.web_scanner import WebApplicationScanner

__all__ = [
    "ScannerOrchestrator",
    "WebApplicationScanner",
    "HeaderSecurityAnalyzer",
    "APISecurityScanner",
    "DependencyScanner",
    "SSLTLSAuditor",
    "NetworkDiscoveryScanner",
    "CMSScanner",
    "ComplianceAuditor",
    "ContainerSecurityScanner",
    "CloudConfigAuditor",
    "CredentialTester",
    "WAFDetector",
    "SubdomainBruteforcer",
    "VulnerabilityCorrelator",
]
