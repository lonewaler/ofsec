"""
OfSec V3 — Operations Orchestrator
=====================================
Central orchestrator for dashboard, reporting, scheduling, and security (#83-100).
"""

from datetime import UTC, datetime

import structlog

from app.core.telemetry import get_tracer
from app.services.ops.dashboard import DashboardAnalytics, NotificationSystem, ReportGenerator
from app.services.ops.scheduler import AssetManager, AuditLogger, JobScheduler, TeamManager
from app.services.ops.security import APIKeyManager, PlatformConfig, RateLimiter

logger = structlog.get_logger()
tracer = get_tracer("ops.orchestrator")


class OpsOrchestrator:
    """Central operations orchestrator (Upgrades #83-100)."""

    def __init__(self):
        # Dashboard & Reports
        self.dashboard = DashboardAnalytics()
        self.reports = ReportGenerator()
        self.notifications = NotificationSystem()

        # Scheduler & Audit
        self.scheduler = JobScheduler()
        self.audit = AuditLogger()
        self.assets = AssetManager()
        self.teams = TeamManager()

        # Security
        self.rate_limiter = RateLimiter()
        self.config = PlatformConfig()
        self.api_keys = APIKeyManager()

    def get_platform_status(self) -> dict:
        """Complete platform status."""
        return {
            "dashboard": self.dashboard.get_overview(),
            "scheduler": {"active_jobs": len(self.scheduler.list_jobs("active"))},
            "assets": self.assets.get_risk_summary(),
            "team": {"members": len(self.teams.list_members())},
            "security": {
                "rate_limiter": self.rate_limiter.get_stats(),
            },
            "generated_at": datetime.now(UTC).isoformat(),
        }
