"""Tests for data_pipeline/cache_manager.py — Redis TI score cache."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from data_pipeline.cache_manager import CacheManager


@pytest.fixture
def manager() -> CacheManager:
    return CacheManager()


@pytest.fixture
def mock_redis() -> AsyncMock:
    redis = AsyncMock()
    return redis


def _patch_redis(mock_redis):
    return patch("data_pipeline.cache_manager.get_redis", return_value=mock_redis)


# ── _key ──────────────────────────────────────────────────────────────────────

def test_key_format(manager: CacheManager):
    assert manager._key("example.com") == "ti:example.com"


def test_key_with_subdomain(manager: CacheManager):
    assert manager._key("sub.example.com") == "ti:sub.example.com"


# ── get_ti_scores ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_ti_scores_cache_hit(manager: CacheManager, mock_redis: AsyncMock):
    scores = {"virustotal": 0.8, "urlscan": 0.5, "google_safe_browsing": 0.0}
    mock_redis.get.return_value = json.dumps(scores)

    with _patch_redis(mock_redis):
        result = await manager.get_ti_scores("evil.com")

    assert result == scores
    mock_redis.get.assert_called_once_with("ti:evil.com")


@pytest.mark.asyncio
async def test_get_ti_scores_cache_miss(manager: CacheManager, mock_redis: AsyncMock):
    mock_redis.get.return_value = None

    with _patch_redis(mock_redis):
        result = await manager.get_ti_scores("safe.com")

    assert result is None


@pytest.mark.asyncio
async def test_get_ti_scores_redis_error_returns_none(manager: CacheManager, mock_redis: AsyncMock):
    mock_redis.get.side_effect = ConnectionError("Redis down")

    with _patch_redis(mock_redis):
        result = await manager.get_ti_scores("example.com")

    assert result is None  # Graceful degradation


# ── set_ti_scores ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_set_ti_scores_writes_to_redis(manager: CacheManager, mock_redis: AsyncMock):
    scores = {"virustotal": 0.1, "urlscan": 0.0, "google_safe_browsing": 0.0}

    with _patch_redis(mock_redis):
        await manager.set_ti_scores("example.com", scores)

    mock_redis.setex.assert_called_once()
    call_args = mock_redis.setex.call_args
    assert call_args[0][0] == "ti:example.com"
    assert json.loads(call_args[0][2]) == scores


@pytest.mark.asyncio
async def test_set_ti_scores_redis_error_does_not_raise(manager: CacheManager, mock_redis: AsyncMock):
    mock_redis.setex.side_effect = ConnectionError("Redis write failed")

    with _patch_redis(mock_redis):
        # Should NOT raise — cache write errors are non-fatal
        await manager.set_ti_scores("example.com", {"virustotal": 0.0})


# ── get_or_fetch_ti ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_or_fetch_ti_returns_cache_hit(manager: CacheManager, mock_redis: AsyncMock):
    cached_scores = {"virustotal": 0.9, "urlscan": 0.0, "google_safe_browsing": 1.0}
    mock_redis.get.return_value = json.dumps(cached_scores)

    mock_ti_service = AsyncMock()

    with _patch_redis(mock_redis):
        result = await manager.get_or_fetch_ti("evil.com", mock_ti_service)

    assert result == cached_scores
    mock_ti_service.fetch_all.assert_not_called()  # Cache hit — no TI API call


@pytest.mark.asyncio
async def test_get_or_fetch_ti_fetches_on_miss(manager: CacheManager, mock_redis: AsyncMock):
    mock_redis.get.return_value = None  # Cache miss
    fetched_scores = {"virustotal": 0.5, "urlscan": 0.0, "google_safe_browsing": 0.0}

    mock_ti_service = AsyncMock()
    mock_ti_service.fetch_all.return_value = fetched_scores

    with _patch_redis(mock_redis):
        result = await manager.get_or_fetch_ti("example.com", mock_ti_service)

    assert result == fetched_scores
    mock_ti_service.fetch_all.assert_called_once_with("example.com")
    mock_redis.setex.assert_called_once()  # Cached the result
