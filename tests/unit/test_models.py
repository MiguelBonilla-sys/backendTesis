"""Tests for models/database.py and models/redis_client.py."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from core.exceptions import DatabaseError


# ---------------------------------------------------------------------------
# models/database.py
# ---------------------------------------------------------------------------

class TestDatabase:
    @pytest.mark.asyncio
    async def test_get_pool_raises_when_not_initialized(self):
        import models.database as db
        original = db._pool
        db._pool = None
        try:
            with pytest.raises(RuntimeError, match="not initialised"):
                db.get_pool()
        finally:
            db._pool = original

    @pytest.mark.asyncio
    async def test_init_db_raises_database_error_on_failure(self):
        with patch("asyncpg.create_pool", side_effect=Exception("connection refused")):
            with pytest.raises(DatabaseError, match="Failed to initialise"):
                from models.database import init_db
                await init_db()

    @pytest.mark.asyncio
    async def test_close_db_is_noop_when_not_initialized(self):
        import models.database as db
        original = db._pool
        db._pool = None
        try:
            from models.database import close_db
            await close_db()  # Should not raise
        finally:
            db._pool = original

    @pytest.mark.asyncio
    async def test_execute_raises_database_error_on_query_failure(self):
        import models.database as db
        mock_pool = AsyncMock()
        mock_pool.execute = AsyncMock(side_effect=Exception("query error"))
        original = db._pool
        db._pool = mock_pool
        try:
            from models.database import execute
            with pytest.raises(DatabaseError):
                await execute("SELECT 1")
        finally:
            db._pool = original

    @pytest.mark.asyncio
    async def test_fetch_raises_database_error_on_failure(self):
        import models.database as db
        mock_pool = AsyncMock()
        mock_pool.fetch = AsyncMock(side_effect=Exception("query error"))
        original = db._pool
        db._pool = mock_pool
        try:
            from models.database import fetch
            with pytest.raises(DatabaseError):
                await fetch("SELECT 1")
        finally:
            db._pool = original

    @pytest.mark.asyncio
    async def test_fetchrow_raises_database_error_on_failure(self):
        import models.database as db
        mock_pool = AsyncMock()
        mock_pool.fetchrow = AsyncMock(side_effect=Exception("query error"))
        original = db._pool
        db._pool = mock_pool
        try:
            from models.database import fetchrow
            with pytest.raises(DatabaseError):
                await fetchrow("SELECT 1")
        finally:
            db._pool = original

    @pytest.mark.asyncio
    async def test_execute_succeeds_with_mock_pool(self):
        import models.database as db
        mock_pool = AsyncMock()
        mock_pool.execute = AsyncMock(return_value="INSERT 1")
        original = db._pool
        db._pool = mock_pool
        try:
            from models.database import execute
            result = await execute("INSERT INTO t VALUES ($1)", "value")
            assert result == "INSERT 1"
        finally:
            db._pool = original

    @pytest.mark.asyncio
    async def test_fetch_succeeds_with_mock_pool(self):
        import models.database as db
        mock_pool = AsyncMock()
        mock_pool.fetch = AsyncMock(return_value=[{"id": 1}])
        original = db._pool
        db._pool = mock_pool
        try:
            from models.database import fetch
            result = await fetch("SELECT * FROM t")
            assert result == [{"id": 1}]
        finally:
            db._pool = original

    @pytest.mark.asyncio
    async def test_fetchrow_returns_none_when_no_rows(self):
        import models.database as db
        mock_pool = AsyncMock()
        mock_pool.fetchrow = AsyncMock(return_value=None)
        original = db._pool
        db._pool = mock_pool
        try:
            from models.database import fetchrow
            result = await fetchrow("SELECT * FROM t WHERE id=$1", "missing")
            assert result is None
        finally:
            db._pool = original


# ---------------------------------------------------------------------------
# models/redis_client.py
# ---------------------------------------------------------------------------

class TestRedisClient:
    @pytest.mark.asyncio
    async def test_get_redis_raises_when_not_initialized(self):
        import models.redis_client as rc
        original = rc._client
        rc._client = None
        try:
            with pytest.raises(RuntimeError, match="not initialised"):
                rc.get_redis()
        finally:
            rc._client = original

    @pytest.mark.asyncio
    async def test_close_redis_is_noop_when_not_initialized(self):
        import models.redis_client as rc
        original = rc._client
        rc._client = None
        try:
            from models.redis_client import close_redis
            await close_redis()  # Should not raise
        finally:
            rc._client = original

    @pytest.mark.asyncio
    async def test_cache_get_returns_value(self):
        import models.redis_client as rc
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value="cached_value")
        original = rc._client
        rc._client = mock_client
        try:
            from models.redis_client import cache_get
            result = await cache_get("test_key")
            assert result == "cached_value"
        finally:
            rc._client = original

    @pytest.mark.asyncio
    async def test_cache_get_returns_none_on_error(self):
        import models.redis_client as rc
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("Redis error"))
        original = rc._client
        rc._client = mock_client
        try:
            from models.redis_client import cache_get
            result = await cache_get("test_key")
            assert result is None
        finally:
            rc._client = original

    @pytest.mark.asyncio
    async def test_cache_set_stores_value(self):
        import models.redis_client as rc
        mock_client = AsyncMock()
        mock_client.set = AsyncMock(return_value=True)
        original = rc._client
        rc._client = mock_client
        try:
            from models.redis_client import cache_set
            await cache_set("key", "value", ttl=3600)
            mock_client.set.assert_called_once_with("key", "value", ex=3600)
        finally:
            rc._client = original

    @pytest.mark.asyncio
    async def test_cache_set_silently_fails_on_error(self):
        import models.redis_client as rc
        mock_client = AsyncMock()
        mock_client.set = AsyncMock(side_effect=Exception("Redis error"))
        original = rc._client
        rc._client = mock_client
        try:
            from models.redis_client import cache_set
            await cache_set("key", "value")  # Should not raise
        finally:
            rc._client = original

    @pytest.mark.asyncio
    async def test_cache_delete_removes_key(self):
        import models.redis_client as rc
        mock_client = AsyncMock()
        mock_client.delete = AsyncMock(return_value=1)
        original = rc._client
        rc._client = mock_client
        try:
            from models.redis_client import cache_delete
            await cache_delete("test_key")
            mock_client.delete.assert_called_once_with("test_key")
        finally:
            rc._client = original

    @pytest.mark.asyncio
    async def test_cache_delete_silently_fails_on_error(self):
        import models.redis_client as rc
        mock_client = AsyncMock()
        mock_client.delete = AsyncMock(side_effect=Exception("Redis error"))
        original = rc._client
        rc._client = mock_client
        try:
            from models.redis_client import cache_delete
            await cache_delete("test_key")  # Should not raise
        finally:
            rc._client = original

    @pytest.mark.asyncio
    async def test_init_redis_raises_database_error_on_failure(self):
        with patch("redis.asyncio.from_url") as mock_from_url:
            mock_redis = AsyncMock()
            mock_redis.ping = AsyncMock(side_effect=Exception("connection refused"))
            mock_from_url.return_value = mock_redis
            from models.redis_client import init_redis
            with pytest.raises(DatabaseError, match="Failed to initialise"):
                await init_redis()
