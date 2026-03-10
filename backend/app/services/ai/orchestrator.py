"""
OfSec V3 — AI/ML Engine Orchestrator
=======================================
Central orchestrator for all AI/ML modules (#46-65).
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog

from app.core.telemetry import get_tracer
from app.services.ai.anomaly_detection import (
    BehavioralAnomalyDetector,
    LogAnomalyDetector,
    NetworkAnomalyDetector,
)
from app.services.ai.llm_engine import (
    AIReportGenerator,
    EmbeddingSearch,
    LLMIntegration,
)
from app.services.ai.nlp_intelligence import (
    CVEAnalyzer,
    DarkWebMonitor,
    ThreatReportParser,
)
from app.services.ai.predictive_models import (
    AttackPredictionEngine,
    MLRiskScorer,
    VulnerabilityForecaster,
)
from app.services.ai.self_learning import (
    AdaptiveScanner,
    FeatureEngineering,
    FeedbackLoopManager,
    ModelRetrainer,
)

logger = structlog.get_logger()
tracer = get_tracer("ai.orchestrator")


class AIOrchestrator:
    """Central AI/ML orchestrator coordinating all intelligence modules."""

    def __init__(self, llm_provider: str = "gemini", llm_api_key: str = ""):
        # Anomaly detection
        self.network_anomaly = NetworkAnomalyDetector()
        self.behavioral_anomaly = BehavioralAnomalyDetector()
        self.log_anomaly = LogAnomalyDetector()

        # NLP
        self.threat_parser = ThreatReportParser()
        self.cve_analyzer = CVEAnalyzer()
        self.darkweb_monitor = DarkWebMonitor()

        # Predictive
        self.attack_predictor = AttackPredictionEngine()
        self.vuln_forecaster = VulnerabilityForecaster()
        self.risk_scorer = MLRiskScorer()

        # Self-learning
        self.feedback = FeedbackLoopManager()
        self.adaptive = AdaptiveScanner()
        self.retrainer = ModelRetrainer()
        self.features = FeatureEngineering()

        # LLM & embeddings
        self.llm = LLMIntegration(provider=llm_provider, api_key=llm_api_key)
        self.embedding_search = EmbeddingSearch()
        self.report_gen = AIReportGenerator(llm=self.llm)

    async def analyze_scan_results(self, scan_data: dict) -> dict:
        """Run AI analysis on scan results."""
        with tracer.start_as_current_span("ai.analyze") as span:
            target = scan_data.get("target", "")
            span.set_attribute("target", target)

            # Extract features
            features = self.features.extract_scan_features(scan_data)

            # Risk scoring
            risk = self.risk_scorer.score(features)

            # Attack prediction
            predictions = self.attack_predictor.predict(scan_data.get("findings", []))

            # Update adaptive scanner
            self.adaptive.update_target_profile(target, scan_data)

            # Record for forecasting
            severity = scan_data.get("severity_summary", {})
            self.vuln_forecaster.add_scan_result(
                target,
                len(scan_data.get("findings", [])),
                severity,
            )

            return {
                "target": target,
                "risk_assessment": risk,
                "attack_predictions": predictions,
                "features": features,
                "analyzed_at": datetime.now(UTC).isoformat(),
            }

    async def parse_threat_report(self, text: str) -> dict:
        """Parse a threat intelligence report."""
        parsed = self.threat_parser.parse_report(text)

        # Look up any CVEs found
        cve_ids = parsed.get("iocs", {}).get("iocs", {}).get("cve", [])
        if cve_ids:
            cve_analysis = await self.cve_analyzer.analyze_cves(cve_ids)
            parsed["cve_analysis"] = cve_analysis

        return parsed

    async def run_module(self, module_name: str, data: dict) -> dict:
        """Run a specific AI module."""
        with tracer.start_as_current_span(f"ai.{module_name}"):
            try:
                if module_name == "network_anomaly":
                    return self.network_anomaly.analyze_traffic_pattern(data.get("traffic", []))
                elif module_name == "behavioral_anomaly":
                    result = self.behavioral_anomaly.update_profile(
                        data.get("user_id", ""),
                        data,
                    )
                    return result or {"anomalies": []}
                elif module_name == "log_anomaly":
                    return self.log_anomaly.analyze_batch(data.get("logs", []))
                elif module_name == "threat_parser":
                    return await self.parse_threat_report(data.get("text", ""))
                elif module_name == "cve_analyzer":
                    return await self.cve_analyzer.analyze_cves(data.get("cve_ids", []))
                elif module_name == "darkweb_monitor":
                    return await self.darkweb_monitor.monitor_domain(data.get("domain", ""))
                elif module_name == "attack_predictor":
                    return self.attack_predictor.predict(data.get("findings", []))
                elif module_name == "risk_scorer":
                    return self.risk_scorer.score(data.get("features", {}))
                elif module_name == "feedback":
                    return self.feedback.submit_feedback(**data)
                elif module_name == "llm_analyze":
                    return await self.llm.analyze_findings(data.get("findings", []))
                elif module_name == "llm_remediation":
                    return await self.llm.generate_remediation(data.get("finding", {}))
                elif module_name == "llm_explain":
                    return await self.llm.explain_vulnerability(data.get("vuln_type", ""))
                elif module_name == "ai_report":
                    return await self.report_gen.generate_executive_report(data)
                elif module_name == "embedding_search":
                    query = data.get("query", "")
                    embedding = self.embedding_search.simple_embedding(query)
                    return {"results": await self.embedding_search.search_similar(embedding)}
                else:
                    return {"error": f"Unknown module: {module_name}"}

            except Exception as e:
                logger.error(f"ai.{module_name}.error", error=str(e), exc_info=True)
                return {"error": str(e), "module": module_name}

    async def close(self):
        await self.cve_analyzer.close()
        await self.darkweb_monitor.close()
        await self.llm.close()
        await self.embedding_search.close()
