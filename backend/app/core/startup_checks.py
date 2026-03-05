"""
OfSec V3 — Startup Validation
================================
Validates required config and connectivity before accepting traffic.
Fails fast with clear error messages.
"""
import os
import sys

import structlog

logger = structlog.get_logger()


# Keys that MUST be set for the app to be useful in production
REQUIRED_IN_PRODUCTION = [
    "SECRET_KEY",
    "DATABASE_URL",
]

# Keys that are strongly recommended but not fatal
RECOMMENDED = [
    "GEMINI_API_KEY",
    "SHODAN_API_KEY",
    "VIRUSTOTAL_API_KEY",
]

# Insecure default values that must be changed in production
INSECURE_DEFAULTS = {
    "SECRET_KEY": "change-me-in-production",
    "API_KEY": "dev-api-key",
    "POSTGRES_PASSWORD": "ofsec_secret",
}


def validate_environment(environment: str) -> None:
    """
    Run all startup validation checks.
    Call this in the lifespan startup block BEFORE anything else.
    """
    errors = []
    warnings = []

    # 1. Required keys in production
    if environment == "production":
        for key in REQUIRED_IN_PRODUCTION:
            val = os.environ.get(key, "")
            if not val:
                errors.append(f"  [FAIL] {key} is not set (required in production)")

        # 2. Insecure defaults check
        for key, bad_value in INSECURE_DEFAULTS.items():
            val = os.environ.get(key, "")
            if val == bad_value:
                errors.append(
                    f"  [FAIL] {key} is still set to the insecure default value '{bad_value}'"
                )

    # 3. Recommended keys (warnings only)
    for key in RECOMMENDED:
        if not os.environ.get(key):
            warnings.append(f"  [WARN] {key} not set -- related features will be disabled")

    # 4. DATABASE_URL sanity check
    db_url = os.environ.get("DATABASE_URL", "")
    if db_url and "sqlite" not in db_url and "postgresql" not in db_url:
        errors.append(f"  [FAIL] DATABASE_URL format not recognized: {db_url[:40]}")

    # 5. Log warnings
    if warnings:
        logger.warning("ofsec.startup.config_warnings", warnings=warnings)
        for w in warnings:
            print(w, file=sys.stderr)

    # 6. Fatal errors — exit immediately in production, warn in dev
    if errors:
        print("\n[OfSec] ── STARTUP CONFIGURATION ERRORS ──", file=sys.stderr)
        for e in errors:
            print(e, file=sys.stderr)
        print("", file=sys.stderr)

        if environment == "production":
            print(
                "[OfSec] Refusing to start in production with invalid configuration.",
                file=sys.stderr,
            )
            sys.exit(1)
        else:
            logger.warning("ofsec.startup.config_errors_ignored_in_dev", errors=errors)
