"""
Redis-based sliding window rate limiter.
Requirement: CA-2 (100 req/min/IP on /analyze), CA-4 (rate limit /incidents)
"""

from __future__ import annotations

import time
from ipaddress import ip_address, ip_network
from uuid import uuid4

from fastapi import HTTPException, Request, status

from core.config import settings
from core.logger import get_logger
from models.redis_client import get_redis

logger = get_logger(__name__)


async def check_rate_limit(
    key: str,
    limit: int,
    window_seconds: int = 60,
    *,
    fail_closed: bool = False,
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
        # UUID members preserve simultaneous attempts with the same timestamp.
        await pipe.zadd(key, {str(uuid4()): now})
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
        # Authentication budgets fail closed; analysis keeps its existing availability policy.
        logger.warning("rate_limiter_redis_error", error=str(exc))
        if fail_closed:
            raise HTTPException(status_code=503, detail="Rate limit service unavailable") from exc


def get_client_ip(request: Request) -> str:
    """Use the socket peer unless it belongs to an explicitly trusted proxy.

    Walk X-Forwarded-For from right to left and stop at the first untrusted
    hop; an attacker-controlled prefix cannot override that address.
    """
    peer = request.client.host if request.client else "unknown"
    try:
        trusted = [ip_network(cidr) for cidr in settings.TRUSTED_PROXY_CIDRS]
        current = ip_address(peer)
        if not any(current in network for network in trusted):
            return peer
        forwarded = request.headers.get("X-Forwarded-For", "")
        chain = [ip_address(value.strip()) for value in forwarded.split(",") if value.strip()]
        for address in reversed(chain):
            if not any(current in network for network in trusted):
                break
            current = address
        return str(current)
    except ValueError:
        # Invalid peer/header/config never grants authority to a supplied header.
        return peer
