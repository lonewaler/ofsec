"""
OfSec V3 — Auth API (DB-backed)
=================================
Login, register, profile, change-password, list-users.
"""

import structlog
from fastapi import APIRouter, HTTPException, status

from app.api.deps import CurrentUser, DbSession
from app.core.security import create_access_token
from app.repositories.user_repo import UserRepository
from app.schemas import LoginRequest, SuccessResponse, TokenResponse, UserResponse

logger = structlog.get_logger()
router = APIRouter(prefix="/auth", tags=["Authentication"])


def _user_dict(u) -> dict:
    return {
        "id": u.id,
        "email": u.email,
        "display_name": u.display_name,
        "role": u.role,
        "is_active": u.is_active,
        "created_at": u.created_at.isoformat() if u.created_at else None,
    }


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, db: DbSession) -> TokenResponse:
    """Email + password → JWT."""
    repo = UserRepository(db)
    user = await repo.authenticate(request.email, request.password)
    if not user:
        logger.warning("api.auth.login_failed", email=request.email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    token = create_access_token({
        "sub": str(user.id), "role": user.role, "email": user.email
    })
    logger.info("api.auth.login_ok", user_id=user.id, email=user.email)
    return TokenResponse(access_token=token)


@router.post("/register", response_model=UserResponse)
async def register(
    email: str,
    password: str,
    display_name: str = "",
    db: DbSession = None,
    current_user: CurrentUser = None,
) -> dict:
    """Create a new user — admin only."""
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    repo = UserRepository(db)
    if await repo.get_by_email(email):
        raise HTTPException(status_code=409, detail="Email already registered")

    user = await repo.create(email, password, display_name)
    logger.info("api.auth.user_created", email=email)
    return _user_dict(user)


@router.get("/me", response_model=UserResponse)
async def me(db: DbSession, user: CurrentUser) -> dict:
    """Authenticated user's profile from DB."""
    repo = UserRepository(db)
    try:
        db_user = await repo.get_by_id(int(user["user_id"]))
    except (ValueError, TypeError, KeyError):
        db_user = None

    if not db_user:
        # API key auth fallback (no numeric user_id)
        return {
            "id": 0, "email": "admin@ofsec.io",
            "display_name": "Admin (API Key)",
            "role": user.get("role", "admin"),
            "is_active": True, "created_at": None,
        }
    return _user_dict(db_user)


@router.post("/change-password")
async def change_password(
    old_password: str,
    new_password: str,
    db: DbSession,
    user: CurrentUser,
) -> SuccessResponse:
    try:
        user_id = int(user["user_id"])
    except (ValueError, TypeError, KeyError):
        raise HTTPException(status_code=400, detail="Cannot change password for API key auth")

    repo = UserRepository(db)
    ok, err = await repo.change_password(user_id, old_password, new_password)
    if not ok:
        raise HTTPException(status_code=400, detail=err)

    logger.info("api.auth.password_changed", user_id=user_id)
    return SuccessResponse(message="Password changed successfully")


@router.get("/users")
async def list_users(db: DbSession, user: CurrentUser) -> dict:
    """List all users — admin only."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    repo = UserRepository(db)
    users = await repo.list_all()
    return {"users": [_user_dict(u) for u in users]}
