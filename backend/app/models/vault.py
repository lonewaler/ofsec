"""
OfSec V3 — Vault Models
=========================
Database model for storing encrypted API keys and credentials.
"""

from sqlalchemy import Column, Integer, String

from app.database import Base


class SecretVault(Base):
    __tablename__ = "secret_vault"

    id = Column(Integer, primary_key=True, autoincrement=True)
    service_name = Column(String(50), unique=True, nullable=False, index=True)
    encrypted_key = Column(String(512), nullable=False)
