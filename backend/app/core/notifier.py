"""
OfSec V3 — Alert Dispatcher
==============================
Async notification dispatcher for email (SMTP) and webhooks.

`dispatch_alert()` is the single entry point — call it from anywhere
in the backend when a critical event occurs. It fans out to all
configured channels concurrently and never raises (failures are logged).

Usage:
    from app.core.notifier import dispatch_alert

    await dispatch_alert(
        title="Critical vulnerability detected",
        message="CVE-2024-1234 found on target example.com",
        severity="critical",
        metadata={"target": "example.com", "scan_id": 42},
    )
"""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import httpx
import structlog

from app.config import settings

logger = structlog.get_logger()


# ─── Severity colour map (for Slack/Discord attachments) ─────────────
_SEVERITY_COLORS = {
    "critical": "#FF0000",
    "high":     "#FF8C00",
    "medium":   "#FFD700",
    "low":      "#00BFFF",
    "info":     "#808080",
}


# ─── Email ────────────────────────────────────────────────────────────

async def _send_email(
    title: str,
    message: str,
    severity: str,
    metadata: dict[str, Any],
) -> None:
    """Send an alert email via SMTP with STARTTLS."""
    if not settings.ALERT_EMAIL_ENABLED:
        return
    if not all([
        settings.ALERT_EMAIL_SMTP_HOST,
        settings.ALERT_EMAIL_USERNAME,
        settings.ALERT_EMAIL_PASSWORD,
        settings.ALERT_EMAIL_TO,
    ]):
        logger.warning("notifier.email.skipped", reason="incomplete SMTP config")
        return

    try:
        import aiosmtplib

        recipients = [r.strip() for r in settings.ALERT_EMAIL_TO.split(",") if r.strip()]

        # Build HTML body
        color = _SEVERITY_COLORS.get(severity.lower(), "#808080")
        meta_rows = "".join(
            f"<tr><td style='color:#888;padding:2px 8px'>{k}</td>"
            f"<td style='padding:2px 8px'>{v}</td></tr>"
            for k, v in metadata.items()
        )
        html_body = f"""
<html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9;padding:24px">
  <div style="max-width:600px;margin:0 auto">
    <div style="border-left:4px solid {color};padding:12px 16px;
                background:#161b22;border-radius:4px;margin-bottom:16px">
      <h2 style="margin:0 0 8px;color:{color}">[{severity.upper()}] {title}</h2>
      <pre style="margin:0;white-space:pre-wrap;color:#c9d1d9">{message}</pre>
    </div>
    {"<table style='border-collapse:collapse;width:100%'>" + meta_rows + "</table>" if meta_rows else ""}
    <p style="font-size:11px;color:#484f58;margin-top:16px">
      OfSec V3 · {datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")}
    </p>
  </div>
</body></html>"""

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[OfSec {severity.upper()}] {title}"
        msg["From"]    = settings.ALERT_EMAIL_FROM
        msg["To"]      = ", ".join(recipients)
        msg.attach(MIMEText(message, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        await aiosmtplib.send(
            msg,
            hostname=settings.ALERT_EMAIL_SMTP_HOST,
            port=settings.ALERT_EMAIL_SMTP_PORT,
            username=settings.ALERT_EMAIL_USERNAME,
            password=settings.ALERT_EMAIL_PASSWORD,
            start_tls=True,
        )
        logger.info("notifier.email.sent", recipients=len(recipients), title=title)

    except Exception as e:
        logger.error("notifier.email.failed", error=str(e))


# ─── Webhook ──────────────────────────────────────────────────────────

async def _send_webhook(
    url: str,
    title: str,
    message: str,
    severity: str,
    metadata: dict[str, Any],
) -> None:
    """POST a JSON alert payload to a webhook URL."""
    if not url:
        return

    color = _SEVERITY_COLORS.get(severity.lower(), "#808080")
    timestamp = datetime.now(UTC).isoformat()

    # Universal payload — works with Slack, Discord, Teams, and custom endpoints
    payload = {
        # ── Slack / Mattermost format ──
        "text": f"*[{severity.upper()}]* {title}",
        "attachments": [{
            "color": color,
            "title": title,
            "text": message,
            "fields": [
                {"title": k, "value": str(v), "short": True}
                for k, v in list(metadata.items())[:6]
            ],
            "footer": "OfSec V3",
            "ts": int(datetime.now(UTC).timestamp()),
        }],
        # ── Discord format ──
        "embeds": [{
            "title": f"[{severity.upper()}] {title}",
            "description": message,
            "color": int(color.lstrip("#"), 16),
            "timestamp": timestamp,
            "fields": [
                {"name": k, "value": str(v), "inline": True}
                for k, v in list(metadata.items())[:6]
            ],
        }],
        # ── Generic / custom ──
        "ofsec_alert": {
            "title": title,
            "message": message,
            "severity": severity,
            "timestamp": timestamp,
            "metadata": metadata,
        },
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
        logger.info("notifier.webhook.sent", url=url[:60], status=resp.status_code)
    except Exception as e:
        logger.error("notifier.webhook.failed", url=url[:60], error=str(e))


# ─── Public API ───────────────────────────────────────────────────────

async def dispatch_alert(
    title: str,
    message: str,
    severity: str = "high",
    metadata: dict[str, Any] | None = None,
) -> dict:
    """
    Fire-and-forget alert dispatch to all configured channels.
    Never raises — channel failures are logged but swallowed.

    Returns a summary of which channels were attempted.
    """
    meta = metadata or {}
    attempted: list[str] = []

    tasks = []

    if settings.ALERT_EMAIL_ENABLED:
        attempted.append("email")
        tasks.append(_send_email(title, message, severity, meta))

    if settings.ALERT_WEBHOOK_ENABLED and settings.ALERT_WEBHOOK_URL:
        attempted.append("webhook")
        tasks.append(_send_webhook(
            settings.ALERT_WEBHOOK_URL, title, message, severity, meta
        ))

    if settings.ALERT_WEBHOOK_ENABLED and settings.ALERT_WEBHOOK_URL_2:
        attempted.append("webhook_2")
        tasks.append(_send_webhook(
            settings.ALERT_WEBHOOK_URL_2, title, message, severity, meta
        ))

    if not tasks:
        logger.debug("notifier.dispatch.no_channels_configured")
        return {"channels": [], "status": "no_channels_configured"}

    await asyncio.gather(*tasks, return_exceptions=True)

    logger.info("notifier.dispatch.complete", title=title, severity=severity, channels=attempted)
    return {"channels": attempted, "status": "dispatched"}


async def send_test_alert() -> dict:
    """Send a test notification to all configured channels."""
    return await dispatch_alert(
        title="OfSec V3 — Test Alert",
        message="This is a test notification from OfSec V3.\n"
                "If you received this, alerting is configured correctly.",
        severity="info",
        metadata={"source": "manual_test", "platform": "OfSec V3"},
    )
