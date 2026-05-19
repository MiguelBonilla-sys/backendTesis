"""Shared fixtures for the full test suite."""
from __future__ import annotations

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from schemas.analyze import AnalyzeRequest, IDNResult, TIResult


@pytest.fixture
def sample_idn_result_phishing() -> IDNResult:
    """IDNResult for a clearly phishing domain (Cyrillic paypal)."""
    return IDNResult(
        domain_unicode="рaypal",
        confusable_chars=["р"],
        homograph_ratio=0.333,
        visual_similarity=0.857,
        s_idn_local=0.90,
        is_mixed_script=True,
        is_suspicious=True,
    )


@pytest.fixture
def sample_idn_result_legit() -> IDNResult:
    """IDNResult for a legitimate domain."""
    return IDNResult(
        domain_unicode="paypal",
        confusable_chars=[],
        homograph_ratio=0.0,
        visual_similarity=0.0,
        s_idn_local=0.0,
        is_mixed_script=False,
        is_suspicious=False,
    )


@pytest.fixture
def sample_ti_result_phishing() -> TIResult:
    return TIResult(s_vt=0.9, s_urlscan=0.8, s_gsb=1.0, s_ti=0.89)


@pytest.fixture
def sample_ti_result_legit() -> TIResult:
    return TIResult(s_vt=0.0, s_urlscan=0.0, s_gsb=0.0, s_ti=0.0)


@pytest.fixture
def sample_analyze_request() -> AnalyzeRequest:
    return AnalyzeRequest(
        url="https://рaypal.com/login",
        email_hash="abc123",
        email_body_snippet="Click here to verify your account",
    )


@pytest.fixture
def mock_redis():
    """Mock of the redis _client module-level var."""
    with patch("models.redis_client._client") as mock:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=None)
        mock_client.set = AsyncMock(return_value=True)
        mock_client.delete = AsyncMock(return_value=1)
        mock_client.ping = AsyncMock(return_value=True)
        mock.__bool__ = MagicMock(return_value=True)
        yield mock_client


@pytest.fixture
def mock_db():
    """Mock of the asyncpg connection pool."""
    with patch("models.database._pool") as mock:
        mock_pool = AsyncMock()
        mock_pool.fetch = AsyncMock(return_value=[])
        mock_pool.fetchrow = AsyncMock(return_value=None)
        mock_pool.execute = AsyncMock(return_value="INSERT 1")
        yield mock_pool
