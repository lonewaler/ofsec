"""
OfSec V3 — Worker DB Utilities
================================
Provides database session access for Taskiq workers that run
outside the FastAPI request/response lifecycle.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory


@asynccontextmanager
async def worker_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Async context manager for DB sessions inside Taskiq workers.

    Usage:
        async with worker_db_session() as db:
            repo = ScanRepository(db)
            scan = await repo.create_scan(...)
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
