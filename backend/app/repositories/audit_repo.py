"""Audit log persistence."""
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog


class AuditRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def log(
        self,
        action: str,
        resource: str = "",
        details: dict | None = None,
        ip_address: str = "",
        user_id: int | None = None,
    ) -> AuditLog:
        entry = AuditLog(
            user_id=user_id,
            action=action,
            resource=resource,
            details=details or {},
            ip_address=ip_address,
            timestamp=datetime.now(UTC),
        )
        self.db.add(entry)
        await self.db.flush()
        return entry
