"""Threat IOC persistence."""
from datetime import UTC, datetime

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ThreatIOC


class IOCRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def upsert_ioc(
        self,
        ioc_type: str,
        value: str,
        source: str,
        confidence: float = 0.5,
        tags: list | None = None,
        metadata: dict | None = None,
    ) -> ThreatIOC:
        """Insert or update (refresh last_seen) an IOC."""
        # Check for existing
        result = await self.db.execute(
            select(ThreatIOC).where(
                and_(ThreatIOC.ioc_type == ioc_type, ThreatIOC.value == value)
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            existing.last_seen = datetime.now(UTC)
            existing.confidence = max(existing.confidence, confidence)
            return existing

        ioc = ThreatIOC(
            ioc_type=ioc_type,
            value=value,
            source=source,
            confidence=confidence,
            tags=tags or [],
            metadata_=metadata or {},
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
        )
        self.db.add(ioc)
        await self.db.flush()
        return ioc

    async def list_iocs(
        self,
        ioc_type: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[ThreatIOC], int]:
        q = select(ThreatIOC)
        if ioc_type:
            q = q.where(ThreatIOC.ioc_type == ioc_type)

        total = (await self.db.execute(
            select(func.count()).select_from(q.subquery())
        )).scalar_one()

        q = q.order_by(ThreatIOC.last_seen.desc()).limit(limit).offset(offset)
        result = await self.db.execute(q)
        return result.scalars().all(), total
