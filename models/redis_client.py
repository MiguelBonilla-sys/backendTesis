"""Async Redis client — thin wrapper around redis.asyncio."""

from __future__ import annotations

import redis.asyncio as redis

from core.config import settings
from core.exceptions import DatabaseError
from core.logger import get_logger

logger = get_logger(__name__)

_client: redis.Redis | None = None


async def init_redis() -> None:
    """Create and verify the Redis connection."""
    global _client
    try:
        _client = redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
        # Validate connection eagerly
        await _client.ping()
        logger.info("Redis client initialised", url=settings.REDIS_URL)
    except Exception as exc:
        raise DatabaseError(
            message="Failed to initialise Redis client",
            detail=str(exc),
        ) from exc


async def close_redis() -> None:
    """Close the Redis connection pool."""
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None
        logger.info("Redis client closed")


def get_redis() -> redis.Redis:
    """Return the active Redis client.

    Raises:
        RuntimeError: If the client has not been initialised yet.
    """
    if _client is None:
        raise RuntimeError("Redis not initialised — call init_redis() first.")
    return _client


async def cache_get(key: str) -> str | None:
    """Return the cached string value for *key*, or None if absent / expired."""
    client = get_redis()
    try:
        return await client.get(key)
    except Exception as exc:
        logger.warning("cache_get failed", key=key, error=str(exc))
        return None


async def cache_set(key: str, value: str, ttl: int = 3600) -> None:
    """Store *value* under *key* with a TTL (seconds)."""
    client = get_redis()
    try:
        await client.set(key, value, ex=ttl)
    except Exception as exc:
        logger.warning("cache_set failed", key=key, error=str(exc))


async def cache_delete(key: str) -> None:
    """Remove *key* from the cache."""
    client = get_redis()
    try:
        await client.delete(key)
    except Exception as exc:
        logger.warning("cache_delete failed", key=key, error=str(exc))
