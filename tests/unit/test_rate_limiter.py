"""Tests for core/rate_limiter.py"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request


class TestCheckRateLimit:
    @pytest.mark.asyncio
    async def test_allows_request_under_limit(self):
        """Requests bajo el límite deben pasar."""
        mock_redis = AsyncMock()
        mock_pipeline = AsyncMock()
        mock_pipeline.execute = AsyncMock(return_value=[None, 5, None, None])  # 5 < 100
        mock_pipeline.zremrangebyscore = AsyncMock()
        mock_pipeline.zcard = AsyncMock()
        mock_pipeline.zadd = AsyncMock()
        mock_pipeline.expire = AsyncMock()
        mock_redis.pipeline = MagicMock(return_value=mock_pipeline)

        with patch("core.rate_limiter.get_redis", return_value=mock_redis):
            from core.rate_limiter import check_rate_limit
            # No debe lanzar excepción
            await check_rate_limit("test_key", limit=100, window_seconds=60)

    @pytest.mark.asyncio
    async def test_blocks_request_over_limit(self):
        """Requests sobre el límite deben recibir 429."""
        mock_redis = AsyncMock()
        mock_pipeline = AsyncMock()
        mock_pipeline.execute = AsyncMock(return_value=[None, 101, None, None])  # 101 >= 100
        mock_pipeline.zremrangebyscore = AsyncMock()
        mock_pipeline.zcard = AsyncMock()
        mock_pipeline.zadd = AsyncMock()
        mock_pipeline.expire = AsyncMock()
        mock_redis.pipeline = MagicMock(return_value=mock_pipeline)

        with patch("core.rate_limiter.get_redis", return_value=mock_redis):
            from core.rate_limiter import check_rate_limit
            with pytest.raises(HTTPException) as exc_info:
                await check_rate_limit("test_key", limit=100, window_seconds=60)
            assert exc_info.value.status_code == 429

    @pytest.mark.asyncio
    async def test_allows_request_when_redis_fails(self):
        """Si Redis falla, el request debe pasar (fail-open)."""
        with patch("core.rate_limiter.get_redis", side_effect=Exception("Redis down")):
            from core.rate_limiter import check_rate_limit
            # No debe lanzar excepción — fail open
            await check_rate_limit("test_key", limit=100, window_seconds=60)

    def test_get_client_ip_from_x_forwarded_for(self):
        """Debe extraer la primera IP del header X-Forwarded-For."""
        from core.rate_limiter import get_client_ip
        mock_request = MagicMock()
        mock_request.headers = {"X-Forwarded-For": "10.0.0.1, 172.16.0.1"}
        mock_request.client = MagicMock(host="192.168.1.1")
        ip = get_client_ip(mock_request)
        assert ip == "10.0.0.1"

    def test_get_client_ip_fallback_to_client_host(self):
        """Sin X-Forwarded-For, usa client.host."""
        from core.rate_limiter import get_client_ip
        mock_request = MagicMock()
        mock_request.headers = {}
        mock_request.client = MagicMock(host="192.168.1.1")
        ip = get_client_ip(mock_request)
        assert ip == "192.168.1.1"


class TestRateLimitIntegration:
    @pytest.mark.asyncio
    async def test_exact_limit_is_blocked(self):
        """El request número limit debe ser bloqueado (count >= limit)."""
        mock_redis = AsyncMock()
        mock_pipeline = AsyncMock()
        mock_pipeline.execute = AsyncMock(return_value=[None, 100, None, None])  # exactamente 100
        mock_pipeline.zremrangebyscore = AsyncMock()
        mock_pipeline.zcard = AsyncMock()
        mock_pipeline.zadd = AsyncMock()
        mock_pipeline.expire = AsyncMock()
        mock_redis.pipeline = MagicMock(return_value=mock_pipeline)

        with patch("core.rate_limiter.get_redis", return_value=mock_redis):
            from core.rate_limiter import check_rate_limit
            with pytest.raises(HTTPException) as exc_info:
                await check_rate_limit("test_key", limit=100, window_seconds=60)
            assert exc_info.value.status_code == 429
            assert "Retry-After" in exc_info.value.headers
