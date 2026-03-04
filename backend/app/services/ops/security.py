"""
OfSec V3 — #96-100 Security Hardening & Platform Config
==========================================================
Platform security, API rate limiting, and configuration management.
"""

import hashlib
import secrets
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("ops.security")


# ─── #96-97 API Security & Rate Limiter ─────

class RateLimiter:
    """Token bucket rate limiter for API endpoints."""

    def __init__(self, requests_per_minute: int = 60, burst: int = 10):
        self._rpm = requests_per_minute
        self._burst = burst
        self._buckets: dict[str, dict] = {}

    def check(self, client_id: str) -> dict:
        """Check if a request should be allowed."""
        now = time.time()
        bucket = self._buckets.get(client_id)

        if not bucket:
            self._buckets[client_id] = {
                "tokens": self._burst - 1,
                "last_refill": now,
            }
            return {"allowed": True, "remaining": self._burst - 1}

        # Refill tokens
        elapsed = now - bucket["last_refill"]
        refill = elapsed * (self._rpm / 60.0)
        bucket["tokens"] = min(self._burst, bucket["tokens"] + refill)
        bucket["last_refill"] = now

        if bucket["tokens"] >= 1:
            bucket["tokens"] -= 1
            return {"allowed": True, "remaining": int(bucket["tokens"])}
        else:
            return {"allowed": False, "remaining": 0, "retry_after_seconds": round((1 - bucket["tokens"]) * 60 / self._rpm, 1)}

    def get_stats(self) -> dict:
        return {
            "active_clients": len(self._buckets),
            "config": {"rpm": self._rpm, "burst": self._burst},
        }


# ─── #98 Platform Configuration ─────────────

class PlatformConfig:
    """Centralized platform configuration management."""

    DEFAULTS = {
        "scan.concurrency": 5,
        "scan.timeout_seconds": 300,
        "scan.max_targets": 100,
        "attack.require_approval": True,
        "attack.max_brute_force_attempts": 100,
        "defense.auto_block_threshold": "P1",
        "defense.quarantine_enabled": True,
        "ai.llm_provider": "gemini",
        "ai.anomaly_z_threshold": 3.0,
        "reporting.default_format": "json",
        "reporting.auto_generate": True,
        "notification.channels": ["email"],
        "scheduler.enabled": True,
        "security.mfa_required": False,
        "security.session_timeout_minutes": 30,
        "security.api_rate_limit_rpm": 60,
    }

    def __init__(self):
        self._config: dict[str, object] = dict(self.DEFAULTS)
        self._history: list[dict] = []

    def get(self, key: str, default=None):
        return self._config.get(key, default)

    def set(self, key: str, value, changed_by: str = "system") -> dict:
        old = self._config.get(key)
        self._config[key] = value
        change = {
            "key": key,
            "old_value": old,
            "new_value": value,
            "changed_by": changed_by,
            "changed_at": datetime.now(timezone.utc).isoformat(),
        }
        self._history.append(change)
        logger.info("ops.config.changed", key=key, value=value)
        return change

    def get_all(self) -> dict:
        return dict(self._config)

    def get_history(self, limit: int = 50) -> list[dict]:
        return self._history[-limit:]


# ─── #99-100 API Key Manager & Security ─────

class APIKeyManager:
    """Manage API keys for platform access."""

    def __init__(self):
        self._keys: dict[str, dict] = {}

    def create_key(self, name: str, role: str = "analyst", scopes: list[str] | None = None) -> dict:
        key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(key.encode()).hexdigest()

        entry = {
            "id": key_hash[:12],
            "name": name,
            "role": role,
            "scopes": scopes or ["read", "scan"],
            "key_prefix": key[:8] + "...",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_used": None,
            "status": "active",
            "usage_count": 0,
        }
        self._keys[key_hash] = entry

        return {**entry, "api_key": key}  # Return full key only on creation

    def validate_key(self, key: str) -> dict | None:
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        entry = self._keys.get(key_hash)
        if entry and entry["status"] == "active":
            entry["last_used"] = datetime.now(timezone.utc).isoformat()
            entry["usage_count"] += 1
            return entry
        return None

    def revoke_key(self, key_id: str) -> dict:
        for k_hash, entry in self._keys.items():
            if entry["id"] == key_id:
                entry["status"] = "revoked"
                return entry
        return {"error": "Key not found"}

    def list_keys(self) -> list[dict]:
        return [
            {k: v for k, v in entry.items() if k != "api_key"}
            for entry in self._keys.values()
        ]
