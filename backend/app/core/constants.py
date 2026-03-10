"""
OfSec V3 — Constants & Enums
==============================
Application-wide constants, enums, and configuration values.
"""

from __future__ import annotations

from enum import StrEnum


# ─── Scan Types ───────────────────────────────
class ScanType(StrEnum):
    RECON = "recon"
    VULNERABILITY = "vulnerability"
    ATTACK = "attack"
    COMPLIANCE = "compliance"
    NETWORK = "network"
    WEB = "web"
    API = "api"
    CLOUD = "cloud"
    MOBILE = "mobile"
    IOT = "iot"


# ─── Severity Levels ─────────────────────────
class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ─── Scan Status ──────────────────────────────
class ScanStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# ─── Alert Status ─────────────────────────────
class AlertStatus(StrEnum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


# ─── Attack Status ────────────────────────────
class AttackStatus(StrEnum):
    PLANNED = "planned"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    ABORTED = "aborted"


# ─── User Roles ──────────────────────────────
class UserRole(StrEnum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


# ─── Recon Module IDs ────────────────────────
class ReconModule(StrEnum):
    CERT_TRANSPARENCY = "cert_transparency"
    PASSIVE_DNS = "passive_dns"
    CT_DASHBOARD = "ct_dashboard"
    DOMAIN_BLACKLIST = "domain_blacklist"
    WHOIS_CORRELATION = "whois_correlation"
    WEB_ARCHIVE = "web_archive"
    SEARCH_ENGINE = "search_engine"
    SOCIAL_MINING = "social_mining"
    OSINT_FEED = "osint_feed"
    RECON_REPORT = "recon_report"


# ─── Vector DB Collections ───────────────────
QDRANT_COLLECTIONS = {
    "threats": "ofsec_threats",
    "vulnerabilities": "ofsec_vulns",
    "scan_results": "ofsec_scans",
    "threat_intel": "ofsec_intel",
}

# ─── Default Embedding Dimension ─────────────
EMBEDDING_DIMENSION = 384  # sentence-transformers/all-MiniLM-L6-v2
