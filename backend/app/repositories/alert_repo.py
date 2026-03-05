"""Alert and Incident persistence."""
from datetime import UTC, datetime

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Alert


class AlertRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_alert(
        self,
        severity: str,
        source: str,
        title: str,
        message: str = "",
        metadata: dict | None = None,
    ) -> Alert:
        alert = Alert(
            severity=severity.lower(),
            source=source,
            title=title,
            message=message,
            status="new",
            metadata_=metadata or {},
            created_at=datetime.now(UTC),
        )
        self.db.add(alert)
        await self.db.flush()
        return alert

    async def list_alerts(
        self,
        status: str | None = None,
        severity: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Alert], int]:
        q = select(Alert)
        filters = []
        if status:
            filters.append(Alert.status == status)
        if severity:
            filters.append(Alert.severity == severity.lower())
        if filters:
            q = q.where(and_(*filters))

        total = (await self.db.execute(
            select(func.count()).select_from(q.subquery())
        )).scalar_one()

        q = q.order_by(Alert.created_at.desc()).limit(limit).offset(offset)
        result = await self.db.execute(q)
        return result.scalars().all(), total

    async def update_alert_status(self, alert_id: int, status: str) -> Alert | None:
        alert = await self.db.get(Alert, alert_id)
        if not alert:
            return None
        alert.status = status
        if status == "resolved":
            alert.resolved_at = datetime.now(UTC)
        return alert

    async def count_open(self) -> int:
        result = await self.db.execute(
            select(func.count()).where(Alert.status.in_(["new", "open"]))
        )
        return result.scalar_one()
