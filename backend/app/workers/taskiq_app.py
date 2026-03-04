"""
OfSec V3 — Taskiq Worker Configuration
========================================
Async task broker using Taskiq with Redis backend.
Falls back to InMemoryBroker for local dev without Redis.
"""

from app.config import settings

try:
    from taskiq_redis import ListQueueBroker, RedisAsyncResultBackend
    # Redis-backed broker (async-native)
    broker = ListQueueBroker(
        url=settings.REDIS_URL,
    ).with_result_backend(
        RedisAsyncResultBackend(
            redis_url=settings.REDIS_URL,
        )
    )
except Exception:
    from taskiq import InMemoryBroker
    broker = InMemoryBroker()
