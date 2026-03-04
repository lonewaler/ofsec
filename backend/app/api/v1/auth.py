"""
OfSec V3 — Auth API Endpoints
===============================
Authentication and user management.
"""

from fastapi import APIRouter, HTTPException, status

from app.api.deps import DbSession, CurrentUser
from app.core.security import hash_password, verify_password, create_access_token
from app.schemas import LoginRequest, TokenResponse, UserResponse, SuccessResponse

import structlog

logger = structlog.get_logger()

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, db: DbSession) -> TokenResponse:
    """Authenticate and receive JWT token."""
    # TODO: Look up user in DB
    # For now, using hardcoded admin for solo project
    logger.info("api.auth.login", email=request.email)

    # Solo project: simple auth
    if request.email == "admin@ofsec.io" and request.password == "admin123":
        token = create_access_token({"sub": "admin", "role": "admin"})
        return TokenResponse(access_token=token)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(user: CurrentUser) -> dict:
    """Get current authenticated user info."""
    return {
        "id": 1,
        "email": "admin@ofsec.io",
        "display_name": "Admin",
        "role": user["role"],
        "is_active": True,
        "created_at": "2025-01-01T00:00:00Z",
    }
