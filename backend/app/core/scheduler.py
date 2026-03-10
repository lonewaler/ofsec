"""
OfSec V3 — APScheduler with SQLAlchemy Job Store
==================================================
Schedules survive server restarts because jobs are persisted
in the `apscheduler_jobs` table in the application database.

SQLite note: APScheduler uses a synchronous SQLAlchemy connection
for the job store (not async). The sync URL is derived automatically
from the async DATABASE_URL by stripping the +asyncpg / +aiosqlite driver.
"""

from __future__ import annotations

import re

import structlog
from apscheduler.executors.asyncio import AsyncIOExecutor
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from app.config import settings

logger = structlog.get_logger()

_scheduler: AsyncIOScheduler | None = None


def _sync_db_url() -> str:
    """
    Convert async DB URL to sync for APScheduler's job store.
    postgresql+asyncpg://... → postgresql://...
    sqlite+aiosqlite://...   → sqlite:///...
    """
    url = settings.DATABASE_URL
    url = re.sub(r"\+asyncpg", "", url)
    url = re.sub(r"\+aiosqlite", "", url)
    return url


def get_scheduler() -> AsyncIOScheduler:
    global _scheduler
    if _scheduler is None:
        sync_url = _sync_db_url()
        if "sqlite" in sync_url:
            jobstore = SQLAlchemyJobStore(
                url=sync_url,
                engine_options={"connect_args": {"check_same_thread": False}},
            )
        else:
            jobstore = SQLAlchemyJobStore(url=sync_url)
        _scheduler = AsyncIOScheduler(
            jobstores={"default": jobstore},
            executors={"default": AsyncIOExecutor()},
            job_defaults={
                "coalesce": True,  # merge missed runs into one
                "max_instances": 1,  # no overlapping runs of same job
                "misfire_grace_time": 120,  # allow 2-min late start
            },
            timezone="UTC",
        )
    return _scheduler


def start_scheduler() -> None:
    sched = get_scheduler()
    if not sched.running:
        sched.start()
        logger.info("scheduler.started", store="sqlalchemy", db=_sync_db_url().split("@")[-1])


def stop_scheduler() -> None:
    sched = get_scheduler()
    if sched.running:
        sched.shutdown(wait=False)
        logger.info("scheduler.stopped")


async def _dispatch(
    target: str,
    scan_type: str,
    modules: list[str] | None,
    job_id: str,
) -> None:
    """Executed by APScheduler — fires a Taskiq task."""
    from app.workers.recon_tasks import run_full_recon
    from app.workers.scan_tasks import run_full_vulnerability_scan

    logger.info("scheduler.firing", job_id=job_id, target=target, scan_type=scan_type)
    try:
        if scan_type == "recon":
            await run_full_recon.kiq(target, modules)
        elif scan_type == "vuln":
            await run_full_vulnerability_scan.kiq(target, modules)
        else:
            await run_full_recon.kiq(target, modules)
            await run_full_vulnerability_scan.kiq(target, modules)
        logger.info("scheduler.fired", job_id=job_id)
    except Exception as e:
        logger.error("scheduler.dispatch_failed", job_id=job_id, error=str(e))


async def _dispatch_threat_sweep() -> None:
    """
    Executed by APScheduler daily — runs the threat intel IOC sweep.
    This is registered automatically by Feature 2 on startup.
    """
    from app.workers.intel_tasks import run_threat_intel_sweep

    logger.info("scheduler.threat_sweep.firing")
    try:
        await run_threat_intel_sweep.kiq()
        logger.info("scheduler.threat_sweep.fired")
    except Exception as e:
        logger.error("scheduler.threat_sweep.failed", error=str(e))


def add_scan_job(
    job_id: str,
    target: str,
    scan_type: str,
    schedule_type: str,
    schedule_value: str,
    modules: list[str] | None = None,
) -> dict:
    sched = get_scheduler()

    if schedule_type == "cron":
        parts = schedule_value.strip().split()
        if len(parts) != 5:
            raise ValueError(f"Expected 5-field cron expression, got: '{schedule_value}'")
        trigger = CronTrigger(
            minute=parts[0],
            hour=parts[1],
            day=parts[2],
            month=parts[3],
            day_of_week=parts[4],
            timezone="UTC",
        )
    else:
        try:
            seconds = int(schedule_value)
        except ValueError:
            raise ValueError(f"Interval schedule_value must be integer seconds, got: '{schedule_value}'")  # noqa: B904
        trigger = IntervalTrigger(seconds=seconds)

    sched.add_job(
        _dispatch,
        trigger=trigger,
        id=job_id,
        kwargs={
            "target": target,
            "scan_type": scan_type,
            "modules": modules,
            "job_id": job_id,
        },
        replace_existing=True,
    )

    job = sched.get_job(job_id)
    return {
        "job_id": job_id,
        "target": target,
        "scan_type": scan_type,
        "schedule_type": schedule_type,
        "schedule_value": schedule_value,
        "next_run": job.next_run_time.isoformat() if job and job.next_run_time else None,
        "status": "scheduled",
        "persistent": True,
    }


def register_threat_sweep(cron: str = "0 3 * * *") -> None:
    """
    Register the daily threat intel sweep job.
    Called once from main.py startup after start_scheduler().
    cron default = 03:00 UTC every day.
    """
    sched = get_scheduler()
    parts = cron.strip().split()
    trigger = CronTrigger(
        minute=parts[0],
        hour=parts[1],
        day=parts[2],
        month=parts[3],
        day_of_week=parts[4],
        timezone="UTC",
    )
    sched.add_job(
        _dispatch_threat_sweep,
        trigger=trigger,
        id="__threat_intel_sweep__",
        replace_existing=True,
    )
    job = sched.get_job("__threat_intel_sweep__")
    logger.info(
        "scheduler.threat_sweep.registered",
        cron=cron,
        next_run=job.next_run_time.isoformat() if job and job.next_run_time else None,
    )


def remove_scan_job(job_id: str) -> bool:
    sched = get_scheduler()
    if sched.get_job(job_id):
        sched.remove_job(job_id)
        logger.info("scheduler.job_removed", job_id=job_id)
        return True
    return False


def list_scheduled_jobs() -> list[dict]:
    return [
        {
            "job_id": j.id,
            "next_run": j.next_run_time.isoformat() if j.next_run_time else None,
            "kwargs": j.kwargs,
            "status": "scheduled" if j.next_run_time else "paused",
            "persistent": True,
        }
        for j in get_scheduler().get_jobs()
        if not j.id.startswith("__")  # hide internal jobs from list
    ]
