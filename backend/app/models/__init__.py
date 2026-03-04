"""
OfSec V3 — SQLAlchemy ORM Models
==================================
All database models for the platform.
Compatible with both SQLite (dev) and PostgreSQL (production).
"""

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from app.database import Base


# ─── Utility ──────────────────────────────────
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ─── Asset Models ─────────────────────────────

class Domain(Base):
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), unique=True, nullable=False, index=True)
    discovered_at = Column(DateTime, default=utcnow)
    risk_score = Column(Float, default=0.0)
    metadata_ = Column("metadata", JSON, default={})

    certificates = relationship("Certificate", back_populates="domain", lazy="selectin")
    ip_addresses = relationship("IPAddress", back_populates="domain", lazy="selectin")

    __table_args__ = (
        Index("ix_domains_risk_score", "risk_score"),
    )


class IPAddress(Base):
    __tablename__ = "ip_addresses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    address = Column(String(45), unique=True, nullable=False, index=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=True)
    asn = Column(String(64))
    geo = Column(JSON, default={})
    discovered_at = Column(DateTime, default=utcnow)

    domain = relationship("Domain", back_populates="ip_addresses")


class Certificate(Base):
    __tablename__ = "certificates"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)
    serial = Column(String(128))
    issuer = Column(String(256))
    subject = Column(String(256))
    san = Column(JSON, default=[])
    not_before = Column(DateTime)
    not_after = Column(DateTime)
    fingerprint_sha256 = Column(String(64))
    discovered_at = Column(DateTime, default=utcnow)

    domain = relationship("Domain", back_populates="certificates")


# ─── Scan & Vulnerability Models ──────────────

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_type = Column(String(32), nullable=False, index=True)
    target = Column(String(512), nullable=False)
    status = Column(String(16), default="pending", index=True)
    config = Column(JSON, default={})
    result_summary = Column(JSON, default={})
    started_at = Column(DateTime, default=utcnow)
    finished_at = Column(DateTime)
    error_message = Column(Text)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    vulnerabilities = relationship("Vulnerability", back_populates="scan", lazy="selectin")

    __table_args__ = (
        Index("ix_scans_type_status", "scan_type", "status"),
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    title = Column(String(512), nullable=False)
    severity = Column(String(16), nullable=False, index=True)
    cwe = Column(String(16))
    cvss = Column(Float)
    description = Column(Text)
    evidence = Column(JSON, default={})
    remediation = Column(Text)
    url = Column(String(1024))
    parameter = Column(String(256))
    discovered_at = Column(DateTime, default=utcnow)

    scan = relationship("Scan", back_populates="vulnerabilities")

    __table_args__ = (
        Index("ix_vulns_severity", "severity"),
    )


# ─── Attack Models ────────────────────────────

class AttackSimulation(Base):
    __tablename__ = "attack_simulations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    attack_type = Column(String(64), nullable=False, index=True)
    target = Column(String(512), nullable=False)
    success = Column(Boolean, default=False)
    status = Column(String(16), default="planned")
    steps = Column(JSON, default=[])
    result = Column(JSON, default={})
    started_at = Column(DateTime, default=utcnow)
    finished_at = Column(DateTime)


# ─── Alert & Incident Models ─────────────────

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    severity = Column(String(16), nullable=False, index=True)
    source = Column(String(64), nullable=False)
    title = Column(String(256), nullable=False)
    message = Column(Text)
    status = Column(String(20), default="new", index=True)
    metadata_ = Column("metadata", JSON, default={})
    created_at = Column(DateTime, default=utcnow)
    resolved_at = Column(DateTime)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(256), nullable=False)
    status = Column(String(20), default="new")
    severity = Column(String(16), default="medium")
    description = Column(Text)
    alert_ids = Column(JSON, default=[])
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=utcnow)
    resolved_at = Column(DateTime)


# ─── User & Auth Models ──────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(128), nullable=False)
    display_name = Column(String(128))
    role = Column(String(16), default="admin")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    last_login = Column(DateTime)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(64), nullable=False)
    resource = Column(String(128))
    details = Column(JSON, default={})
    ip_address = Column(String(45))
    timestamp = Column(DateTime, default=utcnow, index=True)


# ─── Threat Intelligence ─────────────────────

class ThreatIOC(Base):
    __tablename__ = "threat_iocs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc_type = Column(String(32), nullable=False, index=True)
    value = Column(String(512), nullable=False, index=True)
    source = Column(String(64), nullable=False)
    confidence = Column(Float, default=0.5)
    tags = Column(JSON, default=[])
    first_seen = Column(DateTime, default=utcnow)
    last_seen = Column(DateTime, default=utcnow)
    metadata_ = Column("metadata", JSON, default={})

    __table_args__ = (
        Index("ix_iocs_type_value", "ioc_type", "value"),
    )
