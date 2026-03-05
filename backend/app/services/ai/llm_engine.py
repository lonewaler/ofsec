"""
OfSec V3 — #61-65 LLM Integration + Embedding Search + AI Reports
====================================================================
Advanced AI capabilities using LLM APIs, vector embeddings, and
AI-powered report generation.
"""

import hashlib
import json
from datetime import UTC, datetime

import httpx
import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("ai.llm")


# ─── #61-62 LLM Integration ─────────────────

class LLMIntegration:
    """
    LLM-powered security analysis using Google Gemini / OpenAI / local models.
    Provides intelligent vulnerability analysis, remediation advice, and threat assessment.
    """

    PROVIDERS = {
        "gemini": {
            "base_url": "https://generativelanguage.googleapis.com/v1beta",
            "model": "gemini-2.0-flash",
        },
        "openai": {
            "base_url": "https://api.openai.com/v1",
            "model": "gpt-4o-mini",
        },
        "local": {
            "base_url": "http://localhost:11434/api",
            "model": "llama3",
        },
    }

    SECURITY_SYSTEM_PROMPT = """You are an expert cybersecurity analyst. Analyze the provided security 
findings and give actionable, technical advice. Be specific about remediation steps, 
reference CWE/CVE IDs when applicable, and prioritize findings by risk. 
Keep responses concise and professional."""

    def __init__(self, provider: str = "gemini", api_key: str = ""):
        self._provider = provider
        self._api_key = api_key
        self._client: httpx.AsyncClient | None = None
        self._config = self.PROVIDERS.get(provider, self.PROVIDERS["gemini"])

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=60.0)
        return self._client

    async def analyze_findings(self, findings: list[dict], context: str = "") -> dict:
        """Use LLM to analyze security findings."""
        with tracer.start_as_current_span("llm_analyze"):
            prompt = f"""Analyze these security findings and provide:
1. Risk assessment summary
2. Top 3 critical items to address immediately
3. Remediation steps for each finding category
4. Strategic recommendations

Context: {context}

Findings:
{json.dumps(findings[:20], indent=2, default=str)}"""

            response = await self._call_llm(prompt)

            return {
                "analysis": response,
                "findings_analyzed": len(findings[:20]),
                "provider": self._provider,
                "model": self._config["model"],
                "analyzed_at": datetime.now(UTC).isoformat(),
            }

    async def generate_remediation(self, finding: dict) -> dict:
        """Generate specific remediation steps for a finding."""
        prompt = f"""Provide detailed remediation steps for this security finding:

Type: {finding.get('type', 'Unknown')}
Severity: {finding.get('severity', 'unknown')}
Evidence: {finding.get('evidence', 'N/A')}
URL: {finding.get('url', 'N/A')}

Provide:
1. Step-by-step fix instructions
2. Code examples if applicable
3. Verification steps
4. Prevention measures"""

        response = await self._call_llm(prompt)
        return {"finding": finding, "remediation": response}

    async def explain_vulnerability(self, vuln_type: str) -> dict:
        """Generate educational explanation of a vulnerability type."""
        prompt = f"""Explain the "{vuln_type}" vulnerability:
1. What it is (technical description)
2. How attackers exploit it
3. Real-world impact examples
4. How to detect it
5. How to prevent it
Keep the explanation technical but clear."""

        response = await self._call_llm(prompt)
        return {"vulnerability": vuln_type, "explanation": response}

    async def _call_llm(self, prompt: str) -> str:
        """Call the configured LLM provider."""
        client = await self._get_client()

        try:
            if self._provider == "gemini":
                resp = await client.post(
                    f"{self._config['base_url']}/models/{self._config['model']}:generateContent",
                    params={"key": self._api_key},
                    json={
                        "contents": [{"parts": [{"text": prompt}]}],
                        "systemInstruction": {"parts": [{"text": self.SECURITY_SYSTEM_PROMPT}]},
                        "generationConfig": {"temperature": 0.3, "maxOutputTokens": 2048},
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                return data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")

            elif self._provider == "openai":
                resp = await client.post(
                    f"{self._config['base_url']}/chat/completions",
                    headers={"Authorization": f"Bearer {self._api_key}"},
                    json={
                        "model": self._config["model"],
                        "messages": [
                            {"role": "system", "content": self.SECURITY_SYSTEM_PROMPT},
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": 0.3,
                        "max_tokens": 2048,
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                return data.get("choices", [{}])[0].get("message", {}).get("content", "")

            elif self._provider == "local":
                resp = await client.post(
                    f"{self._config['base_url']}/generate",
                    json={
                        "model": self._config["model"],
                        "prompt": f"{self.SECURITY_SYSTEM_PROMPT}\n\n{prompt}",
                        "stream": False,
                    },
                )
                resp.raise_for_status()
                return resp.json().get("response", "")

        except Exception as e:
            logger.error("ai.llm.error", provider=self._provider, error=str(e))
            return f"[LLM Error: {str(e)}]"

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()


# ─── #63 Embedding Search ───────────────────

class EmbeddingSearch:
    """
    Vector embedding search for security knowledge base.
    Uses Qdrant for similarity search over vulnerability descriptions,
    threat intel, and historical findings.
    """

    def __init__(self, qdrant_host: str = "localhost", qdrant_port: int = 6333):
        self._qdrant_host = qdrant_host
        self._qdrant_port = qdrant_port
        self._client: httpx.AsyncClient | None = None
        self._collection = "security_knowledge"

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=f"http://{self._qdrant_host}:{self._qdrant_port}",
                timeout=10.0,
            )
        return self._client

    async def ensure_collection(self, vector_size: int = 384) -> dict:
        """Create the security knowledge collection if it doesn't exist."""
        client = await self._get_client()
        try:
            resp = await client.get(f"/collections/{self._collection}")
            if resp.status_code == 200:
                return {"status": "exists"}
        except Exception:
            pass

        try:
            resp = await client.put(
                f"/collections/{self._collection}",
                json={
                    "vectors": {"size": vector_size, "distance": "Cosine"},
                },
            )
            return {"status": "created", "vector_size": vector_size}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def index_finding(self, finding: dict, embedding: list[float]) -> dict:
        """Index a security finding with its embedding."""
        client = await self._get_client()
        point_id = hashlib.md5(json.dumps(finding, default=str).encode()).hexdigest()

        try:
            resp = await client.put(
                f"/collections/{self._collection}/points",
                json={
                    "points": [{
                        "id": point_id,
                        "vector": embedding,
                        "payload": finding,
                    }],
                },
            )
            return {"status": "indexed", "id": point_id}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def search_similar(self, query_embedding: list[float], limit: int = 10) -> list[dict]:
        """Search for similar findings using embedding."""
        client = await self._get_client()
        try:
            resp = await client.post(
                f"/collections/{self._collection}/points/search",
                json={
                    "vector": query_embedding,
                    "limit": limit,
                    "with_payload": True,
                },
            )
            results = resp.json().get("result", [])
            return [
                {
                    "score": r.get("score", 0),
                    "finding": r.get("payload", {}),
                }
                for r in results
            ]
        except Exception as e:
            logger.error("ai.embedding.search_error", error=str(e))
            return []

    def simple_embedding(self, text: str, dim: int = 384) -> list[float]:
        """
        Generate a simple hash-based embedding for development.
        In production, replace with sentence-transformers or Gemini embedding API.
        """
        h = hashlib.sha512(text.encode()).digest()
        raw = [b / 255.0 for b in h]
        # Pad or truncate to dim
        embedding = (raw * (dim // len(raw) + 1))[:dim]
        # L2 normalize
        norm = sum(x ** 2 for x in embedding) ** 0.5
        if norm > 0:
            embedding = [x / norm for x in embedding]
        return embedding

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()


# ─── #64-65 AI Report Generator ─────────────

class AIReportGenerator:
    """AI-powered comprehensive security report generation."""

    def __init__(self, llm: LLMIntegration | None = None):
        self._llm = llm

    async def generate_executive_report(self, scan_data: dict) -> dict:
        """Generate an executive-level security report."""
        with tracer.start_as_current_span("ai_report"):
            findings = scan_data.get("findings", [])
            modules = scan_data.get("modules_run", [])

            severity_counts = {}
            for f in findings:
                sev = f.get("severity", "info")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            critical = severity_counts.get("critical", 0)
            high = severity_counts.get("high", 0)

            # Risk score
            weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}
            risk_score = sum(
                weights.get(f.get("severity", "info"), 0) for f in findings
            )
            risk_score = min(risk_score, 100)

            # AI analysis if LLM available
            ai_analysis = None
            if self._llm:
                try:
                    result = await self._llm.analyze_findings(findings)
                    ai_analysis = result.get("analysis")
                except Exception as e:
                    ai_analysis = f"AI analysis unavailable: {str(e)}"

            report = {
                "report_type": "executive",
                "generated_at": datetime.now(UTC).isoformat(),
                "target": scan_data.get("target", ""),
                "executive_summary": {
                    "risk_score": risk_score,
                    "risk_level": "Critical" if risk_score >= 80 else "High" if risk_score >= 60 else "Medium" if risk_score >= 30 else "Low",
                    "total_findings": len(findings),
                    "severity_breakdown": severity_counts,
                    "modules_tested": modules,
                },
                "critical_findings": [f for f in findings if f.get("severity") == "critical"][:10],
                "high_findings": [f for f in findings if f.get("severity") == "high"][:10],
                "ai_analysis": ai_analysis,
                "recommendations": self._auto_recommendations(findings),
            }

            logger.info("ai.report.generated", risk_score=risk_score, findings=len(findings))
            return report

    def _auto_recommendations(self, findings: list[dict]) -> list[dict]:
        """Generate prioritized recommendations."""
        recs = []
        types_seen = set()

        priority_map = {
            "credential": ("critical", "Implement strong authentication: enforce complex passwords, enable MFA, remove default accounts"),
            "sql": ("critical", "Use parameterized queries/ORMs, validate inputs, implement WAF rules for SQLi"),
            "xss": ("high", "Implement CSP headers, use output encoding, sanitize user inputs"),
            "rce": ("critical", "Patch vulnerable components immediately, restrict command execution, sandbox processes"),
            "ssl": ("high", "Upgrade to TLS 1.3, disable weak ciphers, enable HSTS with preload"),
            "header": ("medium", "Configure security headers: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy"),
            "port": ("medium", "Close unnecessary ports, implement network segmentation, use firewalls"),
            "outdated": ("high", "Establish automated dependency update pipeline, subscribe to security advisories"),
            "cloud": ("high", "Enable cloud security posture management, review IAM policies, enable bucket encryption"),
        }

        for finding in findings:
            f_type = finding.get("type", "").lower()
            for key, (priority, rec) in priority_map.items():
                if key in f_type and key not in types_seen:
                    types_seen.add(key)
                    recs.append({"priority": priority, "category": key, "recommendation": rec})

        recs.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["priority"], 4))
        return recs

    async def close(self):
        if self._llm:
            await self._llm.close()
