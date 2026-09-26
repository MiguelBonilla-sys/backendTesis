"""Admission, cancellation and shutdown regressions."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from core import background
from core.config import settings
from services.analysis_limits import _capacity, bounded_analysis


async def test_capacity_queue_deadline_and_release_on_cancellation(monkeypatch):
    monkeypatch.setattr(settings, "ANALYSIS_CONCURRENCY", 1)
    monkeypatch.setattr(settings, "ANALYSIS_QUEUE_TIMEOUT_S", 0.02)
    _capacity.pop(asyncio.get_running_loop(), None)
    entered = asyncio.Event()
    release = asyncio.Event()

    @bounded_analysis
    async def analysis():
        entered.set()
        await release.wait()
        return "done"

    first = asyncio.create_task(analysis())
    await entered.wait()
    with pytest.raises(HTTPException) as error:
        await analysis()
    assert error.value.status_code == 503
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    release.set()
    assert await analysis() == "done"


async def test_analysis_deadline_releases_capacity(monkeypatch):
    monkeypatch.setattr(settings, "ANALYSIS_TIMEOUT_S", 0.01)
    _capacity.pop(asyncio.get_running_loop(), None)

    @bounded_analysis
    async def analysis(delay):
        await asyncio.sleep(delay)
        return "done"

    with pytest.raises(HTTPException) as error:
        await analysis(10)
    assert error.value.status_code == 504
    assert await analysis(0) == "done"


async def test_shutdown_drains_then_cancels_pending_optional_work():
    completed = []

    async def fast():
        completed.append("saved")

    async def slow():
        try:
            await asyncio.sleep(10)
        finally:
            completed.append("cancelled")

    background.schedule(fast(), name="fast")
    background.schedule(slow(), name="slow")
    await background.drain(timeout=0.01)
    await asyncio.sleep(0)
    assert set(completed) == {"saved", "cancelled"}
    assert not background._pending


@pytest.mark.parametrize(
    "postgres,redis,rag,expected",
    [
        (True, True, True, 200),
        (False, True, True, 503),
        (True, False, True, 503),
        (True, True, False, 200),
    ],
)
async def test_readiness_checks_dependencies(monkeypatch, postgres, redis, rag, expected):
    import json

    from routers.health_router import readiness

    monkeypatch.setattr(
        "models.database.fetchrow", AsyncMock(return_value={"ready": 1} if postgres else None)
    )
    monkeypatch.setattr(
        "models.redis_client.get_redis", lambda: MagicMock(ping=AsyncMock(return_value=redis))
    )
    monkeypatch.setattr(
        "models.chromadb_client.get_client",
        lambda: MagicMock(
            heartbeat=AsyncMock(side_effect=None if rag else RuntimeError("unavailable"))
        ),
    )
    response = await readiness()
    assert response.status_code == expected
    assert json.loads(response.body)["degraded"] is (expected == 200 and not rag)
