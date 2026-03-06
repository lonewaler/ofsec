"""
OfSec V3 — #34 Phishing Simulator + #35 Social Engineering Toolkit
=====================================================================
Phishing campaign simulation and social engineering assessment tools.
"""

from __future__ import annotations
import hashlib
import secrets
from datetime import UTC, datetime

import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("attack.phishing")


class PhishingSimulator:
    """Simulate phishing campaigns for security awareness testing."""

    # Phishing email templates
    EMAIL_TEMPLATES = {
        "password_reset": {
            "subject": "Urgent: Your password expires in 24 hours",
            "body": """
Dear {name},

Your account password will expire in 24 hours. To avoid losing access,
please reset your password immediately by clicking the link below:

{phishing_url}

If you did not request this change, please contact IT support.

Best regards,
IT Security Team
""",
            "pretext": "IT password expiry notification",
        },
        "invoice": {
            "subject": "Invoice #{invoice_id} - Payment Required",
            "body": """
Hello {name},

Please find attached your invoice #{invoice_id} for the amount of ${amount}.
Payment is due within 5 business days.

View Invoice: {phishing_url}

Thank you for your business.

Accounts Department
""",
            "pretext": "Financial invoice notification",
        },
        "security_alert": {
            "subject": "Security Alert: Unauthorized login attempt detected",
            "body": """
Dear {name},

We detected an unauthorized login attempt on your account from:
- IP: 185.243.{octet1}.{octet2}
- Location: {location}
- Time: {time}

If this wasn't you, secure your account immediately:
{phishing_url}

Security Operations Center
""",
            "pretext": "Account security alert",
        },
        "shared_document": {
            "subject": "{sender} shared a document with you",
            "body": """
{sender} has shared a document with you:

"{document_name}"

Click here to view: {phishing_url}

This link will expire in 48 hours.
""",
            "pretext": "Document sharing notification",
        },
        "mfa_reset": {
            "subject": "Action Required: Verify your identity",
            "body": """
Hello {name},

We need to verify your identity for security purposes.
Please complete the verification by clicking below:

{phishing_url}

This is a mandatory security requirement.

IT Security
""",
            "pretext": "Multi-factor authentication verification",
        },
    }

    def generate_campaign(
        self,
        template_name: str,
        targets: list[dict],
        phishing_url: str,
        **kwargs,
    ) -> dict:
        """Generate a phishing campaign."""
        with tracer.start_as_current_span("phishing_campaign"):
            template = self.EMAIL_TEMPLATES.get(template_name)
            if not template:
                return {"error": f"Unknown template: {template_name}"}

            campaign_id = secrets.token_hex(8)
            emails: list[dict] = []

            for target in targets:
                tracking_id = hashlib.md5(
                    f"{campaign_id}:{target.get('email', '')}".encode()
                ).hexdigest()[:12]

                tracked_url = f"{phishing_url}?t={tracking_id}"

                email_body = template["body"].format(
                    name=target.get("name", "User"),
                    phishing_url=tracked_url,
                    invoice_id=kwargs.get("invoice_id", "INV-" + secrets.token_hex(3).upper()),
                    amount=kwargs.get("amount", "1,249.99"),
                    octet1=secrets.randbelow(256),
                    octet2=secrets.randbelow(256),
                    location=kwargs.get("location", "Moscow, Russia"),
                    time=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
                    sender=kwargs.get("sender", "John Smith"),
                    document_name=kwargs.get("document_name", "Q4 Financial Report.xlsx"),
                )

                emails.append({
                    "to": target.get("email"),
                    "subject": template["subject"].format(
                        invoice_id=kwargs.get("invoice_id", "INV-" + secrets.token_hex(3).upper()),
                        sender=kwargs.get("sender", "John Smith"),
                    ),
                    "body": email_body,
                    "tracking_id": tracking_id,
                    "pretext": template["pretext"],
                })

            logger.info(
                "attack.phishing.campaign_generated",
                campaign_id=campaign_id,
                template=template_name,
                targets=len(emails),
            )

            return {
                "campaign_id": campaign_id,
                "template": template_name,
                "emails_generated": len(emails),
                "emails": emails,
                "tracking_url": phishing_url,
            }

    def list_templates(self) -> list[dict]:
        """List available phishing templates."""
        return [
            {
                "id": name,
                "subject": tmpl["subject"],
                "pretext": tmpl["pretext"],
            }
            for name, tmpl in self.EMAIL_TEMPLATES.items()
        ]


class SocialEngineeringToolkit:
    """Social engineering assessment tools."""

    # Pretext scenarios
    PRETEXT_SCENARIOS = {
        "it_support": {
            "name": "IT Support Call",
            "description": "Impersonate IT helpdesk to gather credentials",
            "script": [
                "Hello, this is {name} from IT Support.",
                "We've detected unusual activity on your workstation.",
                "I need to verify your identity to resolve this.",
                "Can you confirm your employee ID and username?",
                "I'll need to reset your password — what would you like it to be?",
            ],
            "risk_level": "high",
        },
        "delivery_person": {
            "name": "Package Delivery",
            "description": "Gain physical access via delivery pretext",
            "script": [
                "Hi, I have a package for {department}.",
                "The recipient isn't answering — can someone sign for it?",
                "I also need to deliver to the server room — can you show me where it is?",
            ],
            "risk_level": "medium",
        },
        "new_employee": {
            "name": "New Employee",
            "description": "Pretext as a new employee to gain access",
            "script": [
                "Hi, I'm {name}, I just started in {department}.",
                "IT hasn't set up my access yet — could you let me into the office?",
                "I need to access {system} but don't have my credentials yet.",
            ],
            "risk_level": "medium",
        },
        "vendor_audit": {
            "name": "Vendor/Auditor Visit",
            "description": "Impersonate an auditor to access restricted areas",
            "script": [
                "Good morning, I'm {name} from {company}.",
                "We have a scheduled security audit today.",
                "I need access to your network infrastructure.",
            ],
            "risk_level": "high",
        },
    }

    def get_scenario(self, scenario_id: str) -> dict | None:
        return self.PRETEXT_SCENARIOS.get(scenario_id)

    def list_scenarios(self) -> list[dict]:
        return [
            {"id": k, "name": v["name"], "risk": v["risk_level"]}
            for k, v in self.PRETEXT_SCENARIOS.items()
        ]

    def generate_domain_variants(self, domain: str) -> list[dict]:
        """Generate typosquatting/lookalike domain variants."""
        parts = domain.split(".")
        name = parts[0]
        tld = ".".join(parts[1:]) if len(parts) > 1 else "com"

        variants: list[dict] = []

        # Character substitution
        homoglyphs = {"a": "а", "e": "е", "o": "о", "c": "с", "p": "р", "i": "і"}
        for i, char in enumerate(name):
            if char.lower() in homoglyphs:
                variant = name[:i] + homoglyphs[char.lower()] + name[i + 1:]
                variants.append({"domain": f"{variant}.{tld}", "type": "homoglyph", "char": char})

        # Missing/extra character
        for i in range(len(name)):
            # Missing char
            variant = name[:i] + name[i + 1:]
            if variant:
                variants.append({"domain": f"{variant}.{tld}", "type": "omission"})
            # Double char
            variant = name[:i] + name[i] + name[i:]
            variants.append({"domain": f"{variant}.{tld}", "type": "repetition"})

        # Adjacent key swaps (QWERTY)
        qwerty_adjacent = {
            "a": "sq", "s": "awd", "d": "sfe", "f": "dgr",
            "g": "fht", "h": "gjy", "j": "hku", "k": "jli",
            "l": "ko", "q": "wa", "w": "qse", "e": "wrd",
            "r": "etf", "t": "ryg", "y": "tuh", "u": "yij",
            "i": "uok", "o": "ipl",
        }
        for i, char in enumerate(name):
            if char.lower() in qwerty_adjacent:
                for adj in qwerty_adjacent[char.lower()]:
                    variant = name[:i] + adj + name[i + 1:]
                    variants.append({"domain": f"{variant}.{tld}", "type": "typosquat"})

        # Different TLD
        for alt_tld in ["net", "org", "io", "co", "info", "xyz"]:
            if alt_tld != tld:
                variants.append({"domain": f"{name}.{alt_tld}", "type": "tld_swap"})

        logger.info("attack.se.domain_variants", domain=domain, variants=len(variants))
        return variants[:50]
