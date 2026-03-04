"""
OfSec V3 — Constants & Enums
==============================
Application-wide constants, enums, and configuration values.
"""

from enum import Enum


# ─── Scan Types ───────────────────────────────
class ScanType(str, Enum):
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
class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ─── Scan Status ──────────────────────────────
class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# ─── Alert Status ─────────────────────────────
class AlertStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


# ─── Attack Status ────────────────────────────
class AttackStatus(str, Enum):
    PLANNED = "planned"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    ABORTED = "aborted"


# ─── User Roles ──────────────────────────────
class UserRole(str, Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


# ─── Recon Module IDs ────────────────────────
class ReconModule(str, Enum):
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
