"""
OfSec V3 — Scan Stream Bus
=============================
In-process async event bus for streaming per-module scan results
to SSE clients. Each scan_id maps to an asyncio.Queue.

Lifecycle:
  1. Route handler calls stream_bus.create(scan_id) before starting scan
  2. As each module finishes, route calls stream_bus.publish(scan_id, event)
  3. SSE endpoint calls stream_bus.subscribe(scan_id) to get the queue
  4. Route calls stream_bus.close(scan_id) when all modules are done
  5. SSE endpoint sees the sentinel None and closes the stream
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator

import structlog

logger = structlog.get_logger()

# scan_id -> asyncio.Queue
_queues: dict[str, asyncio.Queue] = {}

_SENTINEL = None          # Signals end of stream
_MAX_QUEUE_SIZE = 100     # Prevent unbounded growth


def create(scan_id: str) -> None:
    """Create a queue for a new scan. Call before starting the scan."""
    _queues[scan_id] = asyncio.Queue(maxsize=_MAX_QUEUE_SIZE)
    logger.debug("stream_bus.created", scan_id=scan_id)


async def publish(scan_id: str, event: dict) -> None:
    """Publish a module result event. Safe to call if no subscriber yet."""
    q = _queues.get(scan_id)
    if q:
        await q.put(event)


async def close(scan_id: str) -> None:
    """Signal end of stream. SSE consumer will close after this."""
    q = _queues.get(scan_id)
    if q:
        await q.put(_SENTINEL)
    logger.debug("stream_bus.closed", scan_id=scan_id)


async def subscribe(scan_id: str) -> AsyncGenerator[dict, None]:
    """
    Async generator -- yields events until the sentinel is received.
    Used by the SSE endpoint.
    """
    q = _queues.get(scan_id)
    if not q:
        # Scan not found or already cleaned up
        yield {"type": "error", "message": f"Stream not found for scan_id={scan_id}"}
        return

    try:
        while True:
            event = await asyncio.wait_for(q.get(), timeout=120.0)
            if event is _SENTINEL:
                break
            yield event
    except TimeoutError:
        yield {"type": "error", "message": "Stream timed out"}
    finally:
        # Clean up the queue after consumer is done
        _queues.pop(scan_id, None)
        logger.debug("stream_bus.consumed", scan_id=scan_id)


# ─── Scan control signals ─────────────────────────────────────────────
# scan_id → {"cancelled": bool, "paused": bool}
_control: dict[str, dict] = {}


def init_control(scan_id: str) -> None:
    """Create control state for a scan. Must be called before _run_recon_streaming starts."""
    _control[scan_id] = {"cancelled": False, "paused": False}


def cancel(scan_id: str) -> None:
    if scan_id in _control:
        _control[scan_id]["cancelled"] = True


def pause(scan_id: str) -> None:
    if scan_id in _control:
        _control[scan_id]["paused"] = True


def resume(scan_id: str) -> None:
    if scan_id in _control:
        _control[scan_id]["paused"] = False


def is_cancelled(scan_id: str) -> bool:
    return _control.get(scan_id, {}).get("cancelled", False)


def is_paused(scan_id: str) -> bool:
    return _control.get(scan_id, {}).get("paused", False)


def cleanup_control(scan_id: str) -> None:
    _control.pop(scan_id, None)
