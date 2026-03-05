"""
OfSec V3 — Application Configuration
=====================================
Pydantic Settings for environment management.
"""


from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # ─── App ──────────────────────────────────────
    APP_NAME: str = "OfSec V3"
    VERSION: str = "3.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"

    # ─── Security ─────────────────────────────────
    SECRET_KEY: str = "change-me-in-production"
    API_KEY: str = "dev-api-key"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 1440  # 24 hours

    # ─── Database (PostgreSQL 17 + TimescaleDB) ───
    DATABASE_URL: str = "postgresql+asyncpg://ofsec:ofsec_secret@localhost:5432/ofsec"
    POSTGRES_DB: str = "ofsec"
    POSTGRES_USER: str = "ofsec"
    POSTGRES_PASSWORD: str = "ofsec_secret"
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_TIMEOUT: int = 30

    # ─── Redis ────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ─── Qdrant Vector DB ─────────────────────────
    QDRANT_HOST: str = "localhost"
    QDRANT_PORT: int = 6333
    QDRANT_GRPC_PORT: int = 6334

    # ─── LLM / AI ────────────────────────────────
    GEMINI_API_KEY: str = ""
    OLLAMA_BASE_URL: str = "http://localhost:11434"

    # ─── OSINT API Keys ──────────────────────────
    SHODAN_API_KEY: str = ""
    CENSYS_API_ID: str = ""
    CENSYS_API_SECRET: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    PASSIVETOTAL_API_KEY: str = ""
    BINARYEDGE_API_KEY: str = ""

    # ─── Additional Free-Tier OSINT Keys ─────────
    ABUSEIPDB_API_KEY: str = ""
    NVD_API_KEY: str = ""
    OTX_API_KEY: str = ""
    HUNTER_API_KEY: str = ""
    SECURITYTRAILS_API_KEY: str = ""
    URLSCAN_API_KEY: str = ""
    FULLHUNT_API_KEY: str = ""
    GREYNOISE_API_KEY: str = ""

    # ─── Observability ────────────────────────────
    OTEL_EXPORTER_OTLP_ENDPOINT: str = "http://localhost:9090"
    OTEL_SERVICE_NAME: str = "ofsec-backend"

    # ─── Alerting ─────────────────────────────────
    ALERT_EMAIL_ENABLED: bool = False
    ALERT_EMAIL_SMTP_HOST: str = "smtp.gmail.com"
    ALERT_EMAIL_SMTP_PORT: int = 587
    ALERT_EMAIL_USERNAME: str = ""
    ALERT_EMAIL_PASSWORD: str = ""
    ALERT_EMAIL_FROM: str = "OfSec V3 <alerts@ofsec.io>"
    ALERT_EMAIL_TO: str = ""          # comma-separated recipients

    ALERT_WEBHOOK_ENABLED: bool = False
    ALERT_WEBHOOK_URL: str = ""
    ALERT_WEBHOOK_URL_2: str = ""     # optional second webhook

    # ─── CORS / Hosts ────────────────────────────
    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:80",
        "http://localhost",
    ]
    ALLOWED_HOSTS: list[str] = ["localhost", "127.0.0.1"]

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore",
    }

    @property
    def cors_origins_list(self) -> list[str]:
        """Return CORS origins — locked down in production."""
        if self.ENVIRONMENT == "production":
            # In production, only allow the configured origins (no wildcards)
            return [o for o in self.CORS_ORIGINS if "localhost" not in o] or self.CORS_ORIGINS
        return self.CORS_ORIGINS


# Global settings instance
settings = Settings()
