"""Track optional background work and finish/cancel it before closing stores."""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine

from core.logger import get_logger

logger = get_logger(__name__)
_pending: set[asyncio.Task] = set()


def schedule(coroutine: Coroutine, *, name: str) -> None:
    task = asyncio.create_task(coroutine, name=name)
    _pending.add(task)

    def completed(done: asyncio.Task) -> None:
        _pending.discard(done)
        if not done.cancelled() and done.exception() is not None:
            logger.warning(
                "background_task_failed",
                task=done.get_name(),
                error_type=type(done.exception()).__name__,
            )

    task.add_done_callback(completed)


async def drain(timeout: float = 5.0) -> None:
    tasks = [task for task in _pending if task.get_loop() is asyncio.get_running_loop()]
    if tasks:
        _, remaining = await asyncio.wait(tasks, timeout=timeout)
        for task in remaining:
            task.cancel()
        await asyncio.gather(*remaining, return_exceptions=True)
