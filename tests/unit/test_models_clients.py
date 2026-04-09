"""Tests for models/redis_client.py, chromadb_client.py, and database.py."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── redis_client ──────────────────────────────────────────────────────────────

def test_get_redis_raises_when_not_initialized():
    import models.redis_client as rc

    original = rc._redis
    rc._redis = None
    try:
        with pytest.raises(RuntimeError, match="Redis not initialized"):
            rc.get_redis()
    finally:
        rc._redis = original


@pytest.mark.asyncio
async def test_init_redis_sets_global():
    import models.redis_client as rc

    mock_redis_instance = AsyncMock()
    original = rc._redis
    try:
        with patch("models.redis_client.aioredis.from_url", return_value=mock_redis_instance):
            await rc.init_redis()
        assert rc._redis is mock_redis_instance
    finally:
        rc._redis = original


@pytest.mark.asyncio
async def test_close_redis_clears_global():
    import models.redis_client as rc

    mock_redis = AsyncMock()
    rc._redis = mock_redis
    try:
        await rc.close_redis()
        assert rc._redis is None
        mock_redis.aclose.assert_called_once()
    finally:
        rc._redis = None


@pytest.mark.asyncio
async def test_close_redis_noop_when_already_none():
    import models.redis_client as rc

    original = rc._redis
    rc._redis = None
    try:
        await rc.close_redis()  # Should not raise
    finally:
        rc._redis = original


@pytest.mark.asyncio
async def test_get_redis_returns_instance_after_init():
    import models.redis_client as rc

    mock_redis_instance = AsyncMock()
    original = rc._redis
    rc._redis = mock_redis_instance
    try:
        result = rc.get_redis()
        assert result is mock_redis_instance
    finally:
        rc._redis = original


# ── chromadb_client ───────────────────────────────────────────────────────────

def test_get_chromadb_client_creates_singleton():
    import models.chromadb_client as cc

    mock_client = MagicMock()
    original = cc._client
    cc._client = None
    try:
        with patch("models.chromadb_client.chromadb.HttpClient", return_value=mock_client):
            client = cc.get_chromadb_client()
        assert client is mock_client
        assert cc._client is mock_client
    finally:
        cc._client = original


def test_get_chromadb_client_returns_existing_singleton():
    import models.chromadb_client as cc

    mock_client = MagicMock()
    original = cc._client
    cc._client = mock_client
    try:
        with patch("models.chromadb_client.chromadb.HttpClient") as MockHttpClient:
            result = cc.get_chromadb_client()
        MockHttpClient.assert_not_called()  # Should reuse existing
        assert result is mock_client
    finally:
        cc._client = original


def test_ensure_collections_creates_all_three():
    import models.chromadb_client as cc
    from core.constants import (
        COLLECTION_EMAIL_EMBEDDINGS,
        COLLECTION_IDN_PATTERNS,
        COLLECTION_TI_SIGNALS,
    )

    mock_client = MagicMock()
    with patch.object(cc, "get_chromadb_client", return_value=mock_client):
        cc.ensure_collections()

    calls = [call[0][0] for call in mock_client.get_or_create_collection.call_args_list]
    assert COLLECTION_EMAIL_EMBEDDINGS in calls
    assert COLLECTION_IDN_PATTERNS in calls
    assert COLLECTION_TI_SIGNALS in calls
    assert mock_client.get_or_create_collection.call_count == 3


# ── database ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_close_db_disposes_engine():
    import models.database as db

    mock_engine = MagicMock()
    mock_engine.dispose = AsyncMock()
    with patch("models.database.engine", mock_engine):
        await db.close_db()
    mock_engine.dispose.assert_called_once()


@pytest.mark.asyncio
async def test_get_session_yields_session():
    import models.database as db

    mock_session = AsyncMock()
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
    mock_cm.__aexit__ = AsyncMock(return_value=False)

    with patch("models.database.AsyncSessionLocal", return_value=mock_cm):
        gen = db.get_session()
        session = await gen.__anext__()
        assert session is mock_session
