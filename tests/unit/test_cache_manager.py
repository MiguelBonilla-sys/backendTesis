"""Tests for data_pipeline/cache_manager.py"""
from __future__ import annotations

import json

import pytest
from unittest.mock import AsyncMock, patch

from data_pipeline.cache_manager import (
    get_idn_cache,
    get_ti_cache,
    invalidate_domain,
    set_idn_cache,
    set_ti_cache,
)


# ---------------------------------------------------------------------------
# get_ti_cache
# ---------------------------------------------------------------------------

class TestGetTiCache:
    @pytest.mark.asyncio
    async def test_cache_miss_returns_none(self):
        with patch("data_pipeline.cache_manager.cache_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = None
            result = await get_ti_cache("paypal")
        assert result is None

    @pytest.mark.asyncio
    async def test_cache_hit_returns_dict(self):
        data = {"s_vt": 0.9, "s_urlscan": 0.8, "s_gsb": 1.0, "s_ti": 0.89}
        with patch("data_pipeline.cache_manager.cache_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = json.dumps(data)
            result = await get_ti_cache("paypal")
        assert result == data

    @pytest.mark.asyncio
    async def test_corrupt_cache_returns_none_and_deletes(self):
        with patch("data_pipeline.cache_manager.cache_get", new_callable=AsyncMock) as mock_get, \
             patch("data_pipeline.cache_manager.cache_delete", new_callable=AsyncMock) as mock_del:
            mock_get.return_value = "not-valid-json"
            result = await get_ti_cache("paypal")
        assert result is None
        mock_del.assert_called_once()

    @pytest.mark.asyncio
    async def test_uses_correct_key_prefix(self):
        with patch("data_pipeline.cache_manager.cache_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = None
            await get_ti_cache("paypal")
        mock_get.assert_called_once_with("ti:paypal")


# ---------------------------------------------------------------------------
# set_ti_cache
# ---------------------------------------------------------------------------

class TestSetTiCache:
    @pytest.mark.asyncio
    async def test_stores_json_serialized_data(self):
        data = {"s_vt": 0.9, "s_urlscan": 0.8, "s_gsb": 1.0, "s_ti": 0.89}
        with patch("data_pipeline.cache_manager.cache_set", new_callable=AsyncMock) as mock_set:
            await set_ti_cache("paypal", data, ttl=3600)
        mock_set.assert_called_once_with("ti:paypal", json.dumps(data), ttl=3600)

    @pytest.mark.asyncio
    async def test_uses_correct_key_prefix(self):
        with patch("data_pipeline.cache_manager.cache_set", new_callable=AsyncMock) as mock_set:
            await set_ti_cache("google", {"s_ti": 0.0}, ttl=1800)
        call_args = mock_set.call_args
        assert call_args[0][0] == "ti:google"


# ---------------------------------------------------------------------------
# get_idn_cache
# ---------------------------------------------------------------------------

class TestGetIdnCache:
    @pytest.mark.asyncio
    async def test_cache_miss_returns_none(self):
        with patch("data_pipeline.cache_manager.cache_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = None
            result = await get_idn_cache("paypal")
        assert result is None

    @pytest.mark.asyncio
    async def test_cache_hit_returns_dict(self):
        data = {"s_idn_local": 0.9, "homograph_ratio": 0.33}
        with patch("data_pipeline.cache_manager.cache_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = json.dumps(data)
            result = await get_idn_cache("paypal")
        assert result == data

    @pytest.mark.asyncio
    async def test_uses_idn_key_prefix(self):
        with patch("data_pipeline.cache_manager.cache_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = None
            await get_idn_cache("paypal")
        mock_get.assert_called_once_with("idn:paypal")

    @pytest.mark.asyncio
    async def test_corrupt_data_returns_none(self):
        with patch("data_pipeline.cache_manager.cache_get", new_callable=AsyncMock) as mock_get, \
             patch("data_pipeline.cache_manager.cache_delete", new_callable=AsyncMock):
            mock_get.return_value = "{bad json"
            result = await get_idn_cache("paypal")
        assert result is None


# ---------------------------------------------------------------------------
# set_idn_cache
# ---------------------------------------------------------------------------

class TestSetIdnCache:
    @pytest.mark.asyncio
    async def test_stores_data_with_idn_prefix(self):
        data = {"s_idn_local": 0.9}
        with patch("data_pipeline.cache_manager.cache_set", new_callable=AsyncMock) as mock_set:
            await set_idn_cache("paypal", data, ttl=3600)
        mock_set.assert_called_once_with("idn:paypal", json.dumps(data), ttl=3600)


# ---------------------------------------------------------------------------
# invalidate_domain
# ---------------------------------------------------------------------------

class TestInvalidateDomain:
    @pytest.mark.asyncio
    async def test_deletes_both_ti_and_idn_keys(self):
        with patch("data_pipeline.cache_manager.cache_delete", new_callable=AsyncMock) as mock_del:
            await invalidate_domain("paypal")
        assert mock_del.call_count == 2
        calls = [c[0][0] for c in mock_del.call_args_list]
        assert "ti:paypal" in calls
        assert "idn:paypal" in calls
