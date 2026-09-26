"""Per-process admission and deadlines, shared by URL and content analyses."""

from __future__ import annotations

import asyncio
from functools import wraps
from weakref import WeakKeyDictionary

from fastapi import HTTPException

from core.config import settings

_capacity: WeakKeyDictionary = WeakKeyDictionary()


def bounded_analysis(function):
    @wraps(function)
    async def bounded(*args, **kwargs):
        loop = asyncio.get_running_loop()
        limit = max(1, settings.ANALYSIS_CONCURRENCY)
        state = _capacity.get(loop)
        if state is None:
            state = asyncio.Semaphore(limit)
            _capacity[loop] = state
        try:
            await asyncio.wait_for(state.acquire(), timeout=settings.ANALYSIS_QUEUE_TIMEOUT_S)
        except TimeoutError as exc:
            raise HTTPException(
                503, "Analysis capacity temporarily unavailable", headers={"Retry-After": "5"}
            ) from exc
        try:
            async with asyncio.timeout(settings.ANALYSIS_TIMEOUT_S):
                return await function(*args, **kwargs)
        except TimeoutError as exc:
            raise HTTPException(504, "Analysis deadline exceeded") from exc
        finally:
            state.release()

    return bounded
