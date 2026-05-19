"""AsyncPG connection pool — initialised once during application lifespan."""

from __future__ import annotations

import asyncpg

from core.config import settings
from core.exceptions import DatabaseError
from core.logger import get_logger

logger = get_logger(__name__)

_pool: asyncpg.Pool | None = None


async def init_db() -> None:
    """Create the shared asyncpg connection pool."""
    global _pool
    try:
        _pool = await asyncpg.create_pool(
            dsn=settings.DATABASE_URL,
            min_size=2,
            max_size=10,
        )
        logger.info("Database pool initialised", min_size=2, max_size=10)
    except Exception as exc:
        raise DatabaseError(
            message="Failed to initialise database pool",
            detail=str(exc),
        ) from exc


async def close_db() -> None:
    """Gracefully close the connection pool."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info("Database pool closed")


def get_pool() -> asyncpg.Pool:
    """Return the active connection pool.

    Raises:
        RuntimeError: If the pool has not been initialised yet.
    """
    if _pool is None:
        raise RuntimeError("Database not initialised — call init_db() first.")
    return _pool


async def execute(query: str, *args: object) -> str:
    """Execute a parameterised DML statement and return the status string.

    All values are passed as positional *args* to prevent SQL injection.
    """
    pool = get_pool()
    try:
        return await pool.execute(query, *args)
    except Exception as exc:
        raise DatabaseError(
            message="Database execute failed",
            detail=str(exc),
        ) from exc


async def fetch(query: str, *args: object) -> list[asyncpg.Record]:
    """Execute a parameterised SELECT and return all matching rows."""
    pool = get_pool()
    try:
        return await pool.fetch(query, *args)
    except Exception as exc:
        raise DatabaseError(
            message="Database fetch failed",
            detail=str(exc),
        ) from exc


async def fetchrow(query: str, *args: object) -> asyncpg.Record | None:
    """Execute a parameterised SELECT and return the first row or None."""
    pool = get_pool()
    try:
        return await pool.fetchrow(query, *args)
    except Exception as exc:
        raise DatabaseError(
            message="Database fetchrow failed",
            detail=str(exc),
        ) from exc
