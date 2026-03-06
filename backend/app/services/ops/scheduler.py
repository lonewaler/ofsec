"""
OfSec V3 — #89-95 Scheduler + Audit + Asset Management
=========================================================
Job scheduling, audit logging, asset inventory, and user management.
"""

from __future__ import annotations
import secrets
from collections import defaultdict
from datetime import UTC, datetime

import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("ops.scheduler")


# ─── #89-90 Job Scheduler ───────────────────

class JobScheduler:
    """Schedule and manage recurring security jobs."""

    def __init__(self):
        self._jobs: dict[str, dict] = {}

    def create_job(
        self,
        name: str,
        job_type: str,
        schedule: str,      # cron expression
        target: str = "",
        config: dict | None = None,
    ) -> dict:
        job_id = f"JOB-{secrets.token_hex(4).upper()}"
        job = {
            "id": job_id,
            "name": name,
            "type": job_type,
            "schedule": schedule,
            "target": target,
            "config": config or {},
            "status": "active",
            "created_at": datetime.now(UTC).isoformat(),
            "last_run": None,
            "next_run": None,
            "run_count": 0,
        }
        self._jobs[job_id] = job
        logger.info("ops.scheduler.job_created", job_id=job_id, name=name, schedule=schedule)
        return job

    def enable_job(self, job_id: str) -> dict:
        job = self._jobs.get(job_id)
        if not job:
            return {"error": "Job not found"}
        job["status"] = "active"
        return job

    def disable_job(self, job_id: str) -> dict:
        job = self._jobs.get(job_id)
        if not job:
            return {"error": "Job not found"}
        job["status"] = "paused"
        return job

    def record_run(self, job_id: str, result: dict) -> dict:
        job = self._jobs.get(job_id)
        if not job:
            return {"error": "Job not found"}
        job["last_run"] = datetime.now(UTC).isoformat()
        job["run_count"] += 1
        return {"job_id": job_id, "run_count": job["run_count"], "result": result}

    def list_jobs(self, status: str | None = None) -> list[dict]:
        if status:
            return [j for j in self._jobs.values() if j["status"] == status]
        return list(self._jobs.values())

    def delete_job(self, job_id: str) -> dict:
        if job_id in self._jobs:
            del self._jobs[job_id]
            return {"deleted": job_id}
        return {"error": "Job not found"}


# ─── #91-92 Audit Logger ────────────────────

class AuditLogger:
    """Comprehensive audit logging for all platform operations."""

    def __init__(self):
        self._log: list[dict] = []

    def log(self, action: str, user: str, resource: str,
            details: dict | None = None, result: str = "success") -> dict:
        entry = {
            "id": secrets.token_hex(6),
            "action": action,
            "user": user,
            "resource": resource,
            "details": details or {},
            "result": result,
            "timestamp": datetime.now(UTC).isoformat(),
            "ip_address": details.get("ip", "") if details else "",
        }
        self._log.append(entry)
        return entry

    def search(self, user: str | None = None, action: str | None = None,
               resource: str | None = None, limit: int = 100) -> list[dict]:
        results = self._log
        if user:
            results = [e for e in results if e["user"] == user]
        if action:
            results = [e for e in results if e["action"] == action]
        if resource:
            results = [e for e in results if resource in e["resource"]]
        return results[-limit:]

    def get_user_activity(self, user: str, limit: int = 50) -> dict:
        entries = [e for e in self._log if e["user"] == user][-limit:]
        action_counts: dict[str, int] = defaultdict(int)
        for e in entries:
            action_counts[e["action"]] += 1
        return {
            "user": user,
            "total_actions": len(entries),
            "action_breakdown": dict(action_counts),
            "recent": entries[-10:],
        }


# ─── #93-94 Asset Management ────────────────

class AssetManager:
    """Track and manage security assets and targets."""

    def __init__(self):
        self._assets: dict[str, dict] = {}

    def add_asset(self, name: str, asset_type: str, address: str,
                  tags: list[str] | None = None, criticality: str = "medium") -> dict:
        asset_id = f"ASSET-{secrets.token_hex(4).upper()}"
        asset = {
            "id": asset_id,
            "name": name,
            "type": asset_type,   # server, web_app, api, database, network
            "address": address,
            "tags": tags or [],
            "criticality": criticality,
            "status": "active",
            "last_scanned": None,
            "vulnerability_count": 0,
            "risk_score": 0,
            "created_at": datetime.now(UTC).isoformat(),
        }
        self._assets[asset_id] = asset
        return asset

    def update_scan_result(self, asset_id: str, vuln_count: int, risk_score: float) -> dict:
        asset = self._assets.get(asset_id)
        if not asset:
            return {"error": "Asset not found"}
        asset["last_scanned"] = datetime.now(UTC).isoformat()
        asset["vulnerability_count"] = vuln_count
        asset["risk_score"] = risk_score
        return asset

    def list_assets(self, asset_type: str | None = None, criticality: str | None = None) -> list[dict]:
        results = list(self._assets.values())
        if asset_type:
            results = [a for a in results if a["type"] == asset_type]
        if criticality:
            results = [a for a in results if a["criticality"] == criticality]
        return results

    def get_risk_summary(self) -> dict:
        assets = list(self._assets.values())
        return {
            "total_assets": len(assets),
            "by_criticality": {
                c: len([a for a in assets if a["criticality"] == c])
                for c in ("critical", "high", "medium", "low")
            },
            "by_type": {
                t: len([a for a in assets if a["type"] == t])
                for t in ("server", "web_app", "api", "database", "network")
            },
            "assets_with_vulns": len([a for a in assets if a["vulnerability_count"] > 0]),
            "avg_risk_score": round(
                sum(a["risk_score"] for a in assets) / max(len(assets), 1), 1
            ),
        }


# ─── #95 User & Team Management ─────────────

class TeamManager:
    """Manage security team members and roles."""

    ROLES = {
        "admin": {"name": "Administrator", "permissions": ["*"]},
        "analyst": {"name": "Security Analyst", "permissions": ["read", "scan", "report"]},
        "hunter": {"name": "Threat Hunter", "permissions": ["read", "scan", "attack", "hunt"]},
        "responder": {"name": "Incident Responder", "permissions": ["read", "scan", "defense", "incident"]},
        "viewer": {"name": "Viewer", "permissions": ["read"]},
    }

    def __init__(self):
        self._members: dict[str, dict] = {}

    def add_member(self, username: str, role: str, email: str = "") -> dict:
        if role not in self.ROLES:
            return {"error": f"Unknown role: {role}"}
        member = {
            "username": username,
            "role": role,
            "role_name": self.ROLES[role]["name"],
            "permissions": self.ROLES[role]["permissions"],
            "email": email,
            "status": "active",
            "added_at": datetime.now(UTC).isoformat(),
        }
        self._members[username] = member
        return member

    def list_members(self) -> list[dict]:
        return list(self._members.values())

    def list_roles(self) -> list[dict]:
        return [{"id": k, **v} for k, v in self.ROLES.items()]
