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


import json

import openai
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.api.v1.vault import ACTIVE_MASTER_PASSWORD
from app.core.encryption import decrypt_secret
from app.models.vault import SecretVault
from app.services.ai.memory import RAGMemory
from app.services.ops.installer import AutoInstaller


class AgenticBrain:
    """The central intelligence orchestrating pentesting tools autonomous usage."""

    def __init__(self):
        self.memory = RAGMemory()
    
    async def _get_openai_client(self, db_session: AsyncSession) -> openai.AsyncOpenAI:
        """Retrieve the API key from the vault and initialize the OpenAI client."""
        if not ACTIVE_MASTER_PASSWORD:
            raise ValueError("Vault is locked. ACTIVE_MASTER_PASSWORD is not set.")

        query = select(SecretVault).where(SecretVault.service_name == "openai")
        result = await db_session.execute(query)
        secret_record = result.scalar_one_or_none()

        if not secret_record:
            raise ValueError("OpenAI API key not found in the vault.")

        api_key = decrypt_secret(secret_record.encrypted_key, ACTIVE_MASTER_PASSWORD)
        return openai.AsyncOpenAI(api_key=api_key)

    async def _generate_embedding(self, client: openai.AsyncOpenAI, text: str) -> list[float]:
        """Generate a vector embedding using OpenAI."""
        response = await client.embeddings.create(
            input=text,
            model="text-embedding-3-small"
        )
        return response.data[0].embedding

    async def plan_action(self, user_goal: str, db_session: AsyncSession) -> dict:
        """
        Analyze the goal, retrieve past experiences, and decide the next CLI command.
        """
        client = await self._get_openai_client(db_session)
        
        # 1. Generate an embedding for the goal
        embedding = await self._generate_embedding(client, user_goal)

        # 2. Query Qdrant for past experiences
        memory_results = await self.memory.search_experience(embedding, limit=3)
        fmt_memory = "\n".join([f"- {json.dumps(m)}" for m in memory_results]) if memory_results else "None"

        # 3. Available external tools
        available_tools = list(AutoInstaller.TOOL_REGISTRY.keys())

        # 4. Construct System Prompt
        system_prompt = (
            "You are an expert autonomous pentester.\n"
            f"The user wants to: {user_goal}\n\n"
            f"Available OS tools for execution: {available_tools}\n\n"
            "Past experiences from memory:\n"
            f"{fmt_memory}\n\n"
            "You must return a JSON object with 'tool' (string) and 'args' (list of strings) to execute.\n"
            "Only use tools from the available OS tools list."
        )

        logger.info("agentic_brain.planning_action", goal=user_goal)

        # 5. Call LLM for planning
        response = await client.chat.completions.create(
            model="gpt-4o-mini",
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": "Generate the next best CLI execution payload as JSON."}
            ],
            temperature=0.2
        )

        content = response.choices[0].message.content
        if not content:
            raise ValueError("Failed to generate an action from the LLM.")

        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            logger.error("agentic_brain.json_decode_error", error=str(e), content=content)
            raise ValueError("LLM returned malformed JSON.")

