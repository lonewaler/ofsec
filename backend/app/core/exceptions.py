"""
OfSec V3 — Custom Exceptions
==============================
Application-level exceptions and FastAPI error handlers.
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import structlog

logger = structlog.get_logger()


class OfSecError(Exception):
    """Base exception for OfSec application."""

    def __init__(self, message: str, status_code: int = 500, details: dict | None = None):
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(self.message)


class ScanError(OfSecError):
    """Error during scan execution."""

    def __init__(self, message: str, scan_id: str | None = None):
        super().__init__(message, status_code=500, details={"scan_id": scan_id})


class ReconError(OfSecError):
    """Error during reconnaissance."""

    def __init__(self, message: str, target: str | None = None):
        super().__init__(message, status_code=500, details={"target": target})


class AuthError(OfSecError):
    """Authentication/authorization error."""

    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message, status_code=401)


class RateLimitError(OfSecError):
    """Rate limit exceeded for external API."""

    def __init__(self, service: str, retry_after: int = 60):
        super().__init__(
            f"Rate limit exceeded for {service}",
            status_code=429,
            details={"service": service, "retry_after": retry_after},
        )


class ExternalAPIError(OfSecError):
    """Error calling external API (Shodan, Censys, etc)."""

    def __init__(self, service: str, message: str):
        super().__init__(
            f"{service} API error: {message}",
            status_code=502,
            details={"service": service},
        )


def register_exception_handlers(app: FastAPI) -> None:
    """Register global exception handlers on the FastAPI app."""

    @app.exception_handler(OfSecError)
    async def ofsec_error_handler(request: Request, exc: OfSecError) -> JSONResponse:
        logger.error(
            "ofsec.error",
            error=exc.message,
            status_code=exc.status_code,
            details=exc.details,
            path=str(request.url),
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.message,
                "details": exc.details,
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.error(
            "ofsec.unhandled_error",
            error=str(exc),
            path=str(request.url),
            exc_info=True,
        )
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error"},
        )
