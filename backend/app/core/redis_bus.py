import json
import logging
from collections.abc import AsyncGenerator
from typing import Any

import redis.asyncio as redis

from app.config import settings

logger = logging.getLogger(__name__)


class RedisBus:
    """Async Redis Pub/Sub bus for real-time scan event streaming."""

    def __init__(self):
        self.redis: redis.Redis | None = None

    async def connect(self):
        if not self.redis:
            logger.info("Connecting to Redis Pub/Sub...")
            self.redis = redis.from_url(settings.REDIS_URL, decode_responses=True)

    async def disconnect(self):
        if self.redis:
            logger.info("Disconnecting from Redis Pub/Sub...")
            await self.redis.close()

    async def publish(self, channel: str, message: dict[str, Any]):
        if not self.redis:
            return
        await self.redis.publish(channel, json.dumps(message))

    async def subscribe(self, channel: str) -> AsyncGenerator[str, None]:
        if not self.redis:
            raise RuntimeError("Redis not connected")
        pubsub = self.redis.pubsub()
        await pubsub.subscribe(channel)
        try:
            async for message in pubsub.listen():
                if message["type"] == "message":
                    yield message["data"]
        finally:
            await pubsub.unsubscribe(channel)
            await pubsub.close()


redis_bus = RedisBus()


# Deprecated/Mocking the StreamBus's old functions to prevent instant crashes if they were imported directly
# BUT we will proactively replace them.
async def get_stream(scan_id: str) -> AsyncGenerator[str, None]:
    async for msg in redis_bus.subscribe(f"scan:{scan_id}"):
        yield msg


async def publish_event(scan_id: str, event: dict[str, Any]):
    await redis_bus.publish(f"scan:{scan_id}", event)


async def check_control_signal(scan_id: str) -> str | None:
    """Check Redis for a control signal (pause/resume/cancel)."""
    if not redis_bus.redis:
        return None
    val = await redis_bus.redis.get(f"scan_ctrl:{scan_id}")
    return val


async def set_control_signal(scan_id: str, action: str):
    """Set a control signal in Redis."""
    if not redis_bus.redis:
        return
    await redis_bus.redis.set(f"scan_ctrl:{scan_id}", action, ex=3600)
