"""Scan and Vulnerability persistence."""

from datetime import UTC, datetime

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Scan, Vulnerability


class ScanRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_scan(
        self,
        target: str,
        scan_type: str,
        config: dict | None = None,
    ) -> Scan:
        """Create a new scan record (status=running)."""
        scan = Scan(
            target=target,
            scan_type=scan_type,
            status="running",
            config=config or {},
            started_at=datetime.now(UTC),
        )
        self.db.add(scan)
        await self.db.flush()  # get the auto-increment id without committing
        return scan

    async def complete_scan(
        self,
        scan_id: int,
        result_summary: dict,
        error: str | None = None,
    ) -> Scan | None:
        """Mark a scan completed or failed."""
        scan = await self.db.get(Scan, scan_id)
        if not scan:
            return None
        scan.status = "failed" if error else "completed"  # type: ignore[assignment]
        scan.finished_at = datetime.now(UTC)  # type: ignore[assignment]
        scan.result_summary = result_summary  # type: ignore[assignment]
        if error:
            scan.error_message = error  # type: ignore[assignment]
        return scan

    async def add_vulnerabilities(self, scan_id: int, findings: list[dict]) -> list[Vulnerability]:
        """Bulk insert vulnerability findings for a scan."""
        vulns = []
        for f in findings:
            vuln = Vulnerability(
                scan_id=scan_id,
                title=f.get("title") or f.get("name") or f.get("type") or "Finding",
                severity=f.get("severity", "INFO").upper(),
                cwe=f.get("cwe"),
                cvss=float(f.get("cvss") or f.get("cvss_score") or 0) or None,
                description=f.get("description") or f.get("details"),
                evidence=f.get("evidence") or {},
                remediation=f.get("remediation"),
                url=f.get("url") or f.get("target_url"),
                parameter=f.get("parameter"),
                discovered_at=datetime.now(UTC),
            )
            self.db.add(vuln)
            vulns.append(vuln)
        await self.db.flush()
        return vulns

    async def get_scan(self, scan_id: int) -> Scan | None:
        return await self.db.get(Scan, scan_id)

    async def list_scans(
        self,
        scan_type: str | None = None,
        target: str | None = None,
        status: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[Scan], int]:
        """Return (items, total_count) with optional filters."""
        q = select(Scan)
        filters = []
        if scan_type:
            filters.append(Scan.scan_type == scan_type)
        if target:
            filters.append(Scan.target.ilike(f"%{target}%"))
        if status:
            filters.append(Scan.status == status)
        if filters:
            q = q.where(and_(*filters))

        total = (await self.db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()

        q = q.order_by(Scan.started_at.desc()).limit(limit).offset(offset)
        result = await self.db.execute(q)
        return list(result.scalars().all()), total

    async def list_vulnerabilities(
        self,
        severity: str | None = None,
        scan_id: int | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Vulnerability], int]:
        q = select(Vulnerability)
        filters = []
        if severity:
            filters.append(Vulnerability.severity == severity.upper())
        if scan_id:
            filters.append(Vulnerability.scan_id == scan_id)
        if filters:
            q = q.where(and_(*filters))

        total = (await self.db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()

        q = q.order_by(Vulnerability.discovered_at.desc()).limit(limit).offset(offset)
        result = await self.db.execute(q)
        return list(result.scalars().all()), total
