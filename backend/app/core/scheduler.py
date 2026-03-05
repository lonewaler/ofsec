"""
OfSec V3 — APScheduler integration
=====================================
Persistent async cron/interval scheduler for automated scan dispatch.
Singleton — started once in app lifespan, stopped on shutdown.
"""
from __future__ import annotations

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

logger = structlog.get_logger()

_scheduler: AsyncIOScheduler | None = None


def get_scheduler() -> AsyncIOScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = AsyncIOScheduler(timezone="UTC")
    return _scheduler


def start_scheduler() -> None:
    sched = get_scheduler()
    if not sched.running:
        sched.start()
        logger.info("scheduler.started")


def stop_scheduler() -> None:
    sched = get_scheduler()
    if sched.running:
        sched.shutdown(wait=False)
        logger.info("scheduler.stopped")


async def _dispatch(target: str, scan_type: str, modules: list[str] | None, job_id: str) -> None:
    """Executed by APScheduler — fires a Taskiq task."""
    from app.workers.recon_tasks import run_full_recon
    from app.workers.scan_tasks import run_full_vulnerability_scan

    logger.info("scheduler.firing", job_id=job_id, target=target, scan_type=scan_type)
    try:
        if scan_type == "recon":
            await run_full_recon.kiq(target, modules)
        elif scan_type == "vuln":
            await run_full_vulnerability_scan.kiq(target, modules)
        else:                                    # "full"
            await run_full_recon.kiq(target, modules)
            await run_full_vulnerability_scan.kiq(target, modules)
    except Exception as e:
        logger.error("scheduler.dispatch_failed", job_id=job_id, error=str(e))


def add_scan_job(
    job_id: str,
    target: str,
    scan_type: str,
    schedule_type: str,       # "cron" | "interval"
    schedule_value: str,      # "0 2 * * *" or seconds as string e.g. "3600"
    modules: list[str] | None = None,
) -> dict:
    sched = get_scheduler()

    if schedule_type == "cron":
        parts = schedule_value.strip().split()
        if len(parts) != 5:
            raise ValueError(
                f"Expected 5-field cron expression, got: '{schedule_value}'"
            )
        trigger = CronTrigger(
            minute=parts[0], hour=parts[1],
            day=parts[2], month=parts[3], day_of_week=parts[4],
            timezone="UTC",
        )
    else:
        try:
            seconds = int(schedule_value)
        except ValueError:
            raise ValueError(f"Interval schedule_value must be integer seconds, got: '{schedule_value}'")
        trigger = IntervalTrigger(seconds=seconds)

    sched.add_job(
        _dispatch,
        trigger=trigger,
        id=job_id,
        kwargs={"target": target, "scan_type": scan_type, "modules": modules, "job_id": job_id},
        replace_existing=True,
        misfire_grace_time=60,
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
    }


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
        }
        for j in get_scheduler().get_jobs()
    ]
