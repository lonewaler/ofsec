"""
OfSec V3 — Pydantic Schemas
=============================
Request/Response models for the API.
"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, EmailStr, Field

# ─── Common / Shared ─────────────────────────

class SuccessResponse(BaseModel):
    """Standard success response."""
    status: str = "success"
    message: str = ""
    data: Any = None


class PaginatedResponse(BaseModel):
    """Paginated response wrapper."""
    items: list[Any] = []
    total: int = 0
    page: int = 1
    per_page: int = 20
    pages: int = 0


class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str
    details: dict = {}


# ─── Auth Schemas ─────────────────────────────

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 86400  # 24 hours


class UserResponse(BaseModel):
    id: int
    email: str
    display_name: str | None = None
    role: str = "admin"
    is_active: bool = True
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Recon Schemas ────────────────────────────

class ReconScanRequest(BaseModel):
    """Request to start a recon scan."""
    target: str = Field(..., description="Target domain or IP", examples=["example.com"])
    modules: list[str] = Field(
        default=["all"],
        description="Recon modules to run",
        examples=[["cert_transparency", "passive_dns", "osint_feed"]],
    )
    config: dict = Field(default={}, description="Module-specific configuration")


class ReconResultResponse(BaseModel):
    """Recon scan result."""
    scan_id: int
    target: str
    status: str
    modules_completed: list[str] = []
    findings_count: int = 0
    started_at: datetime
    finished_at: datetime | None = None
    results: dict = {}

    model_config = {"from_attributes": True}


# ─── Scanner Schemas ──────────────────────────

class VulnScanRequest(BaseModel):
    """Request to start a vulnerability scan."""
    target: str = Field(..., description="Target URL, IP, or domain", examples=["https://example.com"])
    scan_type: str = Field(
        default="web",
        description="Type of scan",
        examples=["web", "network", "api", "cloud", "ssl"],
    )
    config: dict = Field(default={}, description="Scan configuration")


class VulnerabilityResponse(BaseModel):
    """Single vulnerability finding."""
    id: int
    title: str
    severity: str
    cwe: str | None = None
    cvss: float | None = None
    description: str | None = None
    url: str | None = None
    parameter: str | None = None
    evidence: dict = {}
    remediation: str | None = None
    discovered_at: datetime

    model_config = {"from_attributes": True}


class ScanResultResponse(BaseModel):
    """Scan result with findings."""
    scan_id: int
    target: str
    scan_type: str
    status: str
    vulnerabilities: list[VulnerabilityResponse] = []
    summary: dict = {}
    started_at: datetime
    finished_at: datetime | None = None

    model_config = {"from_attributes": True}


# ─── Alert Schemas ────────────────────────────

class AlertResponse(BaseModel):
    id: int
    severity: str
    source: str
    title: str
    message: str | None = None
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Dashboard Schemas ────────────────────────

class DashboardStats(BaseModel):
    """Main dashboard statistics."""
    total_scans: int = 0
    active_scans: int = 0
    total_vulnerabilities: int = 0
    critical_vulns: int = 0
    high_vulns: int = 0
    medium_vulns: int = 0
    low_vulns: int = 0
    total_alerts: int = 0
    unresolved_alerts: int = 0
    domains_monitored: int = 0
    threat_iocs: int = 0
