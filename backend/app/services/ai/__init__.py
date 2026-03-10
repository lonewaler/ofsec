"""OfSec V3 — AI/ML Services Package."""

from __future__ import annotations

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
from app.services.ai.orchestrator import AIOrchestrator
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

__all__ = [
    "AIOrchestrator",
    "NetworkAnomalyDetector",
    "BehavioralAnomalyDetector",
    "LogAnomalyDetector",
    "ThreatReportParser",
    "CVEAnalyzer",
    "DarkWebMonitor",
    "AttackPredictionEngine",
    "VulnerabilityForecaster",
    "MLRiskScorer",
    "FeedbackLoopManager",
    "AdaptiveScanner",
    "ModelRetrainer",
    "FeatureEngineering",
    "LLMIntegration",
    "EmbeddingSearch",
    "AIReportGenerator",
]
