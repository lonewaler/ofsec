"""
OfSec V3 — Security Module
============================
JWT authentication, password hashing, API key validation, and RBAC.
"""

from __future__ import annotations
from datetime import UTC, datetime, timedelta

import jwt
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext

from app.config import settings

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security schemes
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain, hashed)


def create_access_token(
    data: dict,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(UTC) + (
        expires_delta or timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "iat": datetime.now(UTC)})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )


async def verify_api_key(
    api_key: str | None = Security(api_key_header),
) -> str:
    """Validate API key from X-API-Key header."""
    if not api_key or api_key != settings.API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key",
        )
    return api_key


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    api_key: str | None = Security(api_key_header),
) -> dict:
    """
    Authenticate via JWT Bearer token OR API key.
    Solo project: simplified auth with dual strategy.
    """
    # Try JWT first
    if credentials:
        payload = decode_access_token(credentials.credentials)
        return {"user_id": payload.get("sub"), "role": payload.get("role", "admin")}

    # Fall back to API key
    if api_key and api_key == settings.API_KEY:
        return {"user_id": "admin", "role": "admin"}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated — provide Bearer token or X-API-Key",
        headers={"WWW-Authenticate": "Bearer"},
    )
