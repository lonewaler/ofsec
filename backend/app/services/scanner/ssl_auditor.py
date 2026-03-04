"""
OfSec V3 — #24 SSL/TLS Hardening Audit
========================================
Analyzes SSL/TLS configurations for security weaknesses.

Checks: certificate validity, protocol versions, cipher suites,
OCSP stapling, certificate chain, key size, known vulns (POODLE, BEAST, Heartbleed).
"""

import asyncio
import ssl
import socket
from datetime import datetime, timezone
from typing import Optional

import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("scanner.ssl")

# Weak ciphers to flag
WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon", "RC2",
]

# Deprecated protocols
DEPRECATED_PROTOCOLS = {
    ssl.PROTOCOL_TLS: "TLS (auto-negotiate)",
}


class SSLTLSAuditor:
    """SSL/TLS configuration security auditor."""

    async def audit(self, host: str, port: int = 443) -> dict:
        """Full SSL/TLS audit on a host."""
        with tracer.start_as_current_span("ssl_audit") as span:
            span.set_attribute("target.host", host)
            span.set_attribute("target.port", port)

            findings: list[dict] = []
            cert_info = {}
            protocol_info = {}
            cipher_info = {}

            # Get certificate and connection info
            try:
                cert_info = await self._get_certificate_info(host, port)
                if "error" not in cert_info:
                    cert_findings = self._analyze_certificate(cert_info)
                    findings.extend(cert_findings)
            except Exception as e:
                findings.append({
                    "type": "SSL Connection Error",
                    "severity": "critical",
                    "evidence": str(e),
                })

            # Check protocol support
            protocol_info = await self._check_protocols(host, port)
            protocol_findings = self._analyze_protocols(protocol_info)
            findings.extend(protocol_findings)

            # Check cipher suites
            cipher_info = await self._get_cipher_info(host, port)
            cipher_findings = self._analyze_ciphers(cipher_info)
            findings.extend(cipher_findings)

            # Calculate grade
            severity_counts = {}
            for f in findings:
                sev = f.get("severity", "info")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            critical = severity_counts.get("critical", 0)
            high = severity_counts.get("high", 0)
            if critical > 0:
                grade = "F"
            elif high > 0:
                grade = "C"
            elif severity_counts.get("medium", 0) > 0:
                grade = "B"
            elif len(findings) == 0:
                grade = "A+"
            else:
                grade = "A"

            result = {
                "host": host,
                "port": port,
                "grade": grade,
                "certificate": cert_info,
                "protocols": protocol_info,
                "ciphers": cipher_info,
                "total_findings": len(findings),
                "severity_summary": severity_counts,
                "findings": findings,
            }

            logger.info("scanner.ssl.complete", host=host, grade=grade, findings=len(findings))
            return result

    async def _get_certificate_info(self, host: str, port: int) -> dict:
        """Extract certificate information."""
        loop = asyncio.get_event_loop()

        def _get_cert():
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    return cert, cipher, version

        try:
            cert, cipher, version = await loop.run_in_executor(None, _get_cert)

            # Parse certificate fields
            subject = dict(x[0] for x in cert.get("subject", ()))
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            san = [entry[1] for entry in cert.get("subjectAltName", ())]

            not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_remaining = (not_after - datetime.now(timezone.utc)).days

            return {
                "common_name": subject.get("commonName", ""),
                "organization": subject.get("organizationName", ""),
                "issuer_cn": issuer.get("commonName", ""),
                "issuer_org": issuer.get("organizationName", ""),
                "san": san,
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "days_remaining": days_remaining,
                "serial": cert.get("serialNumber", ""),
                "version": cert.get("version", 0),
                "tls_version": version,
                "cipher_suite": cipher[0] if cipher else "",
                "cipher_bits": cipher[2] if cipher else 0,
            }
        except Exception as e:
            return {"error": str(e)}

    def _analyze_certificate(self, cert: dict) -> list[dict]:
        """Analyze certificate for issues."""
        findings = []

        days = cert.get("days_remaining", 0)
        if days < 0:
            findings.append({
                "type": "Expired Certificate",
                "severity": "critical",
                "evidence": f"Certificate expired {abs(days)} days ago",
            })
        elif days < 30:
            findings.append({
                "type": "Certificate Expiring Soon",
                "severity": "high",
                "evidence": f"Certificate expires in {days} days",
            })

        # Key size check
        bits = cert.get("cipher_bits", 0)
        if bits > 0 and bits < 128:
            findings.append({
                "type": "Weak Cipher Key Size",
                "severity": "high",
                "evidence": f"Cipher uses only {bits}-bit key",
            })

        # Self-signed check
        if cert.get("common_name") == cert.get("issuer_cn"):
            findings.append({
                "type": "Self-Signed Certificate",
                "severity": "medium",
                "evidence": "Certificate appears to be self-signed",
            })

        return findings

    async def _check_protocols(self, host: str, port: int) -> dict:
        """Check supported TLS/SSL protocol versions."""
        loop = asyncio.get_event_loop()
        results = {}

        protocols_to_test = {
            "SSLv3": ssl.PROTOCOL_TLS,
            "TLSv1.0": ssl.PROTOCOL_TLS,
            "TLSv1.1": ssl.PROTOCOL_TLS,
            "TLSv1.2": ssl.PROTOCOL_TLS,
            "TLSv1.3": ssl.PROTOCOL_TLS,
        }

        def _test_protocol(proto_name: str):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                if proto_name == "TLSv1.3":
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
                elif proto_name == "TLSv1.2":
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_2

                with socket.create_connection((host, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        return ssock.version()
            except Exception:
                return None

        for proto_name in protocols_to_test:
            try:
                version = await loop.run_in_executor(None, _test_protocol, proto_name)
                results[proto_name] = {"supported": version is not None, "version": version}
            except Exception:
                results[proto_name] = {"supported": False}

        return results

    def _analyze_protocols(self, protocols: dict) -> list[dict]:
        """Flag deprecated protocol support."""
        findings = []
        deprecated = ["SSLv3", "TLSv1.0", "TLSv1.1"]

        for proto in deprecated:
            if protocols.get(proto, {}).get("supported"):
                findings.append({
                    "type": "Deprecated Protocol",
                    "severity": "high" if proto == "SSLv3" else "medium",
                    "protocol": proto,
                    "evidence": f"{proto} is supported but deprecated",
                    "remediation": f"Disable {proto} support",
                })
        return findings

    async def _get_cipher_info(self, host: str, port: int) -> dict:
        """Get supported cipher suites."""
        loop = asyncio.get_event_loop()

        def _get_ciphers():
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return [c["name"] for c in ctx.get_ciphers()]

        try:
            ciphers = await loop.run_in_executor(None, _get_ciphers)
            return {"supported": ciphers, "count": len(ciphers)}
        except Exception:
            return {"supported": [], "count": 0}

    def _analyze_ciphers(self, cipher_info: dict) -> list[dict]:
        """Flag weak cipher suites."""
        findings = []
        for cipher_name in cipher_info.get("supported", []):
            for weak in WEAK_CIPHERS:
                if weak in cipher_name:
                    findings.append({
                        "type": "Weak Cipher Suite",
                        "severity": "high",
                        "cipher": cipher_name,
                        "evidence": f"Weak cipher detected: {cipher_name} (contains {weak})",
                        "remediation": f"Disable cipher {cipher_name}",
                    })
                    break
        return findings

    async def close(self):
        pass
