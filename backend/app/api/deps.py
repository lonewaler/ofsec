"""
OfSec V3 — API Dependencies
=============================
Shared dependencies for FastAPI route injection.
"""

from __future__ import annotations
from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user
from app.database import get_db

# Type aliases for dependency injection
DbSession = Annotated[AsyncSession, Depends(get_db)]
CurrentUser = Annotated[dict, Depends(get_current_user)]
