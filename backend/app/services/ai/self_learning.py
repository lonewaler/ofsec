"""
OfSec V3 — #55-57 Self-Learning + #58-60 ML Pipeline
=======================================================
Adaptive scanning, feedback loops, model management, and feature engineering.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import UTC, datetime

import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("ai.learning")


# ─── #55 Feedback Loop Manager ──────────────


class FeedbackLoopManager:
    """Manage feedback loops for continuous model improvement."""

    def __init__(self):
        self._feedback: list[dict] = []
        self._accuracy_history: dict[str, list[float]] = defaultdict(list)
        self._false_positives: list[dict] = []
        self._true_positives: list[dict] = []

    def submit_feedback(
        self,
        finding_id: str,
        module: str,
        is_true_positive: bool,
        analyst_notes: str = "",
        severity_override: str | None = None,
    ) -> dict:
        """Submit analyst feedback on a finding."""
        feedback = {
            "finding_id": finding_id,
            "module": module,
            "is_true_positive": is_true_positive,
            "analyst_notes": analyst_notes,
            "severity_override": severity_override,
            "submitted_at": datetime.now(UTC).isoformat(),
        }
        self._feedback.append(feedback)

        if is_true_positive:
            self._true_positives.append(feedback)
        else:
            self._false_positives.append(feedback)

        # Track accuracy per module
        accuracy = len(self._true_positives) / max(len(self._feedback), 1)
        self._accuracy_history[module].append(accuracy)

        logger.info(
            "ai.feedback.submitted",
            module=module,
            tp=is_true_positive,
            accuracy=round(accuracy, 3),
        )

        return {
            "feedback_id": hashlib.md5(json.dumps(feedback, default=str).encode()).hexdigest()[:12],  # noqa: S324
            "status": "accepted",
            "current_accuracy": round(accuracy, 3),
        }

    def get_accuracy_report(self) -> dict:
        """Get accuracy metrics across all modules."""
        total = len(self._feedback)
        tp = len(self._true_positives)
        fp = len(self._false_positives)

        module_accuracy = {}
        for module, history in self._accuracy_history.items():
            module_accuracy[module] = {
                "current": round(history[-1], 3) if history else 0,
                "trend": "improving" if len(history) > 1 and history[-1] > history[0] else "stable",
                "samples": len(history),
            }

        return {
            "total_feedback": total,
            "true_positives": tp,
            "false_positives": fp,
            "overall_accuracy": round(tp / max(total, 1), 3),
            "precision": round(tp / max(tp + fp, 1), 3),
            "module_accuracy": module_accuracy,
        }


# ─── #56 Adaptive Scanner ───────────────────


class AdaptiveScanner:
    """Adaptive scanning that adjusts based on past results and feedback."""

    def __init__(self):
        self._target_profiles: dict[str, dict] = {}
        self._module_effectiveness: dict[str, float] = defaultdict(lambda: 1.0)

    def update_effectiveness(self, module: str, findings: int, false_positives: int) -> None:
        """Update module effectiveness based on results."""
        if findings == 0:
            return
        fp_rate = false_positives / findings
        effectiveness = max(0.1, 1.0 - fp_rate)
        self._module_effectiveness[module] = round(0.7 * self._module_effectiveness[module] + 0.3 * effectiveness, 3)

    def recommend_modules(self, target: str, available_modules: list[str]) -> list[dict]:
        """Recommend which modules to run based on target profile and effectiveness."""
        profile = self._target_profiles.get(target, {})
        profile.get("finding_types", [])

        recommendations = []
        for module in available_modules:
            effectiveness = self._module_effectiveness.get(module, 1.0)
            priority = effectiveness

            # Boost modules that found things before
            if module in profile.get("productive_modules", []):
                priority *= 1.3

            recommendations.append(
                {
                    "module": module,
                    "priority": round(min(priority, 1.0), 2),
                    "effectiveness": effectiveness,
                    "reason": "Previously productive" if priority > 1.0 else "Standard",
                }
            )

        recommendations.sort(key=lambda x: -x["priority"])
        return recommendations

    def update_target_profile(self, target: str, scan_result: dict) -> None:
        """Update target profile after a scan."""
        profile = self._target_profiles.setdefault(
            target,
            {
                "scan_count": 0,
                "finding_types": [],
                "productive_modules": [],
                "last_scanned": None,
            },
        )
        profile["scan_count"] += 1
        profile["last_scanned"] = datetime.now(UTC).isoformat()

        findings = scan_result.get("findings", [])
        for f in findings:
            f_type = f.get("type", "")
            if f_type and f_type not in profile["finding_types"]:
                profile["finding_types"].append(f_type)

        module = scan_result.get("module")
        if module and findings and module not in profile["productive_modules"]:
            profile["productive_modules"].append(module)


# ─── #57 Model Retrainer ────────────────────


class ModelRetrainer:
    """Manage model retraining schedules and versioning."""

    def __init__(self):
        self._model_registry: dict[str, dict] = {}
        self._training_runs: list[dict] = []

    def register_model(
        self,
        name: str,
        version: str,
        model_type: str,
        metrics: dict,
    ) -> dict:
        """Register a model version."""
        model = {
            "name": name,
            "version": version,
            "type": model_type,
            "metrics": metrics,
            "registered_at": datetime.now(UTC).isoformat(),
            "status": "active",
        }
        self._model_registry[f"{name}:{version}"] = model
        logger.info("ai.model.registered", name=name, version=version)
        return model

    def get_active_model(self, name: str) -> dict | None:
        """Get the active version of a model."""
        active = [m for k, m in self._model_registry.items() if m["name"] == name and m["status"] == "active"]
        return active[-1] if active else None

    def should_retrain(self, name: str, accuracy_threshold: float = 0.85) -> dict:
        """Check if a model should be retrained."""
        model = self.get_active_model(name)
        if not model:
            return {"name": name, "should_retrain": True, "reason": "No active model"}

        accuracy = model.get("metrics", {}).get("accuracy", 1.0)
        if accuracy < accuracy_threshold:
            return {
                "name": name,
                "should_retrain": True,
                "reason": f"Accuracy {accuracy} below threshold {accuracy_threshold}",
                "current_version": model["version"],
            }

        return {
            "name": name,
            "should_retrain": False,
            "current_accuracy": accuracy,
            "current_version": model["version"],
        }


# ─── #58-60 Feature Engineering & Pipeline ──


class FeatureEngineering:
    """Extract and transform features from security data for ML models."""

    @staticmethod
    def extract_scan_features(scan_result: dict) -> dict:
        """Extract ML features from a scan result."""
        findings = scan_result.get("findings", [])
        severity_counts = defaultdict(int)
        type_counts = defaultdict(int)

        for f in findings:
            severity_counts[f.get("severity", "info")] += 1
            type_counts[f.get("type", "unknown")] += 1

        return {
            "total_findings": len(findings),
            "critical_vulns": severity_counts.get("critical", 0),
            "high_vulns": severity_counts.get("high", 0),
            "medium_vulns": severity_counts.get("medium", 0),
            "low_vulns": severity_counts.get("low", 0),
            "unique_vuln_types": len(type_counts),
            "has_rce": 1 if any("rce" in t.lower() or "command" in t.lower() for t in type_counts) else 0,
            "has_sqli": 1 if any("sql" in t.lower() for t in type_counts) else 0,
            "has_xss": 1 if any("xss" in t.lower() for t in type_counts) else 0,
            "has_auth_issue": 1 if any("credential" in t.lower() or "auth" in t.lower() for t in type_counts) else 0,
        }

    @staticmethod
    def extract_network_features(network_data: dict) -> dict:
        """Extract features from network scan data."""
        services = network_data.get("services", [])
        return {
            "open_ports": len(services),
            "exposed_ports": len([s for s in services if s.get("port", 0) < 1024]),
            "has_ssh": 1 if any(s.get("service") == "ssh" for s in services) else 0,
            "has_database": 1
            if any(s.get("service") in ("mysql", "postgresql", "mongodb", "redis") for s in services)
            else 0,
            "has_web": 1 if any(s.get("service") in ("http", "https") for s in services) else 0,
            "attack_surface_size": len(services) * 2,  # Weighted
        }

    @staticmethod
    def normalize_features(features: dict, min_vals: dict = None, max_vals: dict = None) -> dict:
        """Min-max normalize features to [0, 1]."""
        normalized = {}
        for key, value in features.items():
            if isinstance(value, (int, float)):
                lo = (min_vals or {}).get(key, 0)
                hi = (max_vals or {}).get(key, max(value, 10))
                if hi > lo:
                    normalized[key] = round((value - lo) / (hi - lo), 4)
                else:
                    normalized[key] = 0.0
            else:
                normalized[key] = value
        return normalized
