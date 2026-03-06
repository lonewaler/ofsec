"""
OfSec V3 — #52-54 Predictive Models
======================================
Attack prediction, vulnerability forecasting, and ML-based risk scoring.
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict
from datetime import UTC, datetime

import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("ai.predictive")


# ─── #52 Attack Prediction Engine ────────────

class AttackPredictionEngine:
    """Predict likely attack vectors based on scan data and historical patterns."""

    # Attack probability weights based on observed indicators
    INDICATOR_WEIGHTS = {
        # Recon findings → likely next attack
        "exposed_service": {"brute_force": 0.7, "exploit": 0.8, "lateral": 0.5},
        "default_credentials": {"brute_force": 0.9, "privesc": 0.7, "lateral": 0.8},
        "weak_ssl": {"mitm": 0.8, "data_intercept": 0.7},
        "xss_vuln": {"session_hijack": 0.8, "phishing": 0.6, "data_steal": 0.7},
        "sqli_vuln": {"data_exfil": 0.9, "privesc": 0.6, "rce": 0.5},
        "outdated_software": {"exploit": 0.9, "rce": 0.7},
        "open_ports": {"scanning": 0.6, "brute_force": 0.5, "exploit": 0.4},
        "no_waf": {"xss": 0.7, "sqli": 0.7, "cmdi": 0.6},
        "weak_headers": {"clickjacking": 0.8, "xss": 0.5},
        "public_cloud_resource": {"data_exposure": 0.8, "account_takeover": 0.5},
    }

    def predict(self, findings: list[dict]) -> dict:
        """Predict likely attacks based on current findings."""
        with tracer.start_as_current_span("attack_prediction"):
            # Classify findings into indicators
            indicators = self._classify_findings(findings)

            # Calculate attack probabilities
            attack_probs: dict[str, float] = defaultdict(float)
            for indicator in indicators:
                weights = self.INDICATOR_WEIGHTS.get(indicator, {})
                for attack, weight in weights.items():
                    attack_probs[attack] = max(attack_probs[attack], weight)

            # Sort by probability
            predictions = [
                {
                    "attack_type": attack,
                    "probability": round(prob, 2),
                    "confidence": "high" if prob > 0.7 else "medium" if prob > 0.4 else "low",
                    "based_on": [i for i in indicators if attack in self.INDICATOR_WEIGHTS.get(i, {})],
                }
                for attack, prob in sorted(attack_probs.items(), key=lambda x: -x[1])
            ]

            return {
                "indicators_found": indicators,
                "predictions": predictions,
                "highest_risk": predictions[0] if predictions else None,
                "analyzed_at": datetime.now(UTC).isoformat(),
            }

    def _classify_findings(self, findings: list[dict]) -> list[str]:
        """Classify scan findings into attack indicator categories."""
        indicators = set()
        for finding in findings:
            f_type = finding.get("type", "").lower()
            severity = finding.get("severity", "").lower()

            if "credential" in f_type or "default" in f_type:
                indicators.add("default_credentials")
            if "xss" in f_type:
                indicators.add("xss_vuln")
            if "sql" in f_type:
                indicators.add("sqli_vuln")
            if "ssl" in f_type or "tls" in f_type or "cipher" in f_type:
                indicators.add("weak_ssl")
            if "header" in f_type:
                indicators.add("weak_headers")
            if "port" in f_type or "service" in f_type:
                indicators.add("exposed_service")
                indicators.add("open_ports")
            if "outdated" in f_type or "version" in f_type:
                indicators.add("outdated_software")
            if "waf" in f_type and "not" in f_type:
                indicators.add("no_waf")
            if "cloud" in f_type or "s3" in f_type or "bucket" in f_type:
                indicators.add("public_cloud_resource")

        return list(indicators)


# ─── #53 Vulnerability Forecaster ────────────

class VulnerabilityForecaster:
    """Forecast future vulnerability trends using time series analysis."""

    def __init__(self):
        self._history: dict[str, list[dict]] = defaultdict(list)

    def add_scan_result(self, target: str, vuln_count: int, severity_breakdown: dict) -> None:
        """Record a scan result for trend analysis."""
        self._history[target].append({
            "timestamp": datetime.now(UTC).isoformat(),
            "total_vulns": vuln_count,
            "severity": severity_breakdown,
        })

    def forecast(self, target: str, periods: int = 3) -> dict:
        """Forecast future vulnerability counts using linear regression."""
        with tracer.start_as_current_span("vuln_forecast"):
            history = self._history.get(target, [])
            if len(history) < 3:
                return {
                    "target": target,
                    "status": "insufficient_data",
                    "message": f"Need at least 3 data points, have {len(history)}",
                }

            # Simple linear regression
            values = [h["total_vulns"] for h in history]
            n = len(values)
            x_values = list(range(n))
            x_mean = statistics.mean(x_values)
            y_mean = statistics.mean(values)

            numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_values, values))
            denominator = sum((x - x_mean) ** 2 for x in x_values)

            if denominator == 0:
                slope = 0
                intercept = y_mean
            else:
                slope = numerator / denominator
                intercept = y_mean - slope * x_mean

            # Forecast
            forecasts = []
            for i in range(1, periods + 1):
                predicted = max(0, round(slope * (n + i - 1) + intercept))
                forecasts.append({
                    "period": i,
                    "predicted_vulns": predicted,
                    "trend": "increasing" if slope > 0.5 else "decreasing" if slope < -0.5 else "stable",
                })

            return {
                "target": target,
                "historical_data_points": n,
                "current_vulns": values[-1],
                "trend_slope": round(slope, 3),
                "forecasts": forecasts,
            }


# ─── #54 ML Risk Scorer ─────────────────────

class MLRiskScorer:
    """Machine learning-based risk scoring using weighted feature vectors."""

    # Feature weights derived from security domain knowledge
    FEATURE_WEIGHTS = {
        "critical_vulns": 15.0,
        "high_vulns": 8.0,
        "medium_vulns": 3.0,
        "low_vulns": 1.0,
        "exposed_ports": 2.0,
        "weak_auth": 12.0,
        "missing_encryption": 10.0,
        "outdated_components": 6.0,
        "public_exposure": 8.0,
        "attack_surface_size": 4.0,
        "data_sensitivity": 7.0,
        "compliance_gaps": 5.0,
    }

    # Industry benchmarks for normalization
    BENCHMARKS = {
        "critical_vulns": {"low": 0, "medium": 2, "high": 5, "critical": 10},
        "exposed_ports": {"low": 3, "medium": 10, "high": 20, "critical": 50},
    }

    def score(self, features: dict) -> dict:
        """Calculate risk score from features."""
        with tracer.start_as_current_span("risk_scoring"):
            weighted_sum = 0.0
            max_possible = 0.0
            feature_scores: dict[str, float] = {}

            for feature, weight in self.FEATURE_WEIGHTS.items():
                value = features.get(feature, 0)
                # Sigmoid normalization to [0, 1]
                normalized = 1 / (1 + math.exp(-0.5 * (value - 3)))
                contribution = normalized * weight
                feature_scores[feature] = round(contribution, 2)
                weighted_sum += contribution
                max_possible += weight

            # Normalize to 0-100
            risk_score = round((weighted_sum / max_possible) * 100, 1) if max_possible > 0 else 0

            # Risk level
            if risk_score >= 80:
                risk_level = "Critical"
            elif risk_score >= 60:
                risk_level = "High"
            elif risk_score >= 40:
                risk_level = "Medium"
            elif risk_score >= 20:
                risk_level = "Low"
            else:
                risk_level = "Minimal"

            # Top risk factors
            top_factors = sorted(feature_scores.items(), key=lambda x: -x[1])[:5]

            return {
                "risk_score": risk_score,
                "risk_level": risk_level,
                "feature_contributions": feature_scores,
                "top_risk_factors": [
                    {"feature": f, "contribution": s} for f, s in top_factors
                ],
                "scored_at": datetime.now(UTC).isoformat(),
            }

    def compare_scans(self, previous: dict, current: dict) -> dict:
        """Compare risk between two scans."""
        prev_score = self.score(previous)
        curr_score = self.score(current)
        delta = curr_score["risk_score"] - prev_score["risk_score"]

        return {
            "previous": prev_score,
            "current": curr_score,
            "delta": round(delta, 1),
            "trend": "worsening" if delta > 5 else "improving" if delta < -5 else "stable",
        }
