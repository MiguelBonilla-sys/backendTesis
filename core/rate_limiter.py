"""
Redis-based sliding window rate limiter.
Requirement: CA-2 (100 req/min/IP on /analyze), CA-4 (rate limit /incidents)
"""
from __future__ import annotations

import time

from fastapi import HTTPException, Request, status

from core.logger import get_logger
from models.redis_client import get_redis

logger = get_logger(__name__)


async def check_rate_limit(
    key: str,
    limit: int,
    window_seconds: int = 60,
) -> None:
    """
    Sliding window rate limiter using Redis sorted sets.
    Raises HTTP 429 if the caller has exceeded *limit* requests within
    the last *window_seconds*.

    Args:
        key: unique identifier (e.g. "rl:analyze:192.168.1.1")
        limit: max requests allowed per window
        window_seconds: rolling window size in seconds
    """
    try:
        redis = get_redis()
        now = time.time()
        window_start = now - window_seconds

        pipe = redis.pipeline()
        # Remove entries that fell outside the current window
        await pipe.zremrangebyscore(key, 0, window_start)
        # Count entries still inside the window
        await pipe.zcard(key)
        # Record the current request (score = timestamp, member = timestamp str)
        await pipe.zadd(key, {str(now): now})
        # Ensure the key expires automatically so Redis memory is not leaked
        await pipe.expire(key, window_seconds + 1)
        results = await pipe.execute()

        current_count: int = results[1]  # zcard result (before adding this request)

        if current_count >= limit:
            logger.warning(
                "rate_limit_exceeded",
                key=key,
                count=current_count,
                limit=limit,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded: {limit} requests per {window_seconds}s",
                headers={"Retry-After": str(window_seconds)},
            )
    except HTTPException:
        raise
    except Exception as exc:
        # Redis unavailability must never block legitimate requests — log and pass
        logger.warning("rate_limiter_redis_error", error=str(exc))


def get_client_ip(request: Request) -> str:
    """
    Extract the real client IP, honoring X-Forwarded-For set by NGINX Ingress
    or any other reverse proxy in front of the service.
    """
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
