"""Tests for routers/analyze_router.py — full pipeline with mocked agents."""

import pytest
from httpx import ASGITransport, AsyncClient
from unittest.mock import AsyncMock, MagicMock

from main import app
from routers.analyze_router import _cache, _fusion, _idn, _llm, _ti

# ── Shared mock return values ─────────────────────────────────────────────────

_IDN_RESULT = {
    "domain": "apple.com",
    "normalized": "apple.com",
    "is_punycode": False,
    "confusables": [],
    "ratio_h": 0.0,
    "sim_v": 0.0,
    "s_idn_local": 0.05,
    "ratio_h_alert": False,
}

_LLM_RESULT = {
    "domain": "apple.com",
    "s_llm": 0.1,
    "reasoning": "Looks like a legitimate Apple domain.",
    "rag_context": [],
    "tokens_used": 60,
}

_TI_SCORES = {
    "virustotal": 0.0,
    "urlscan": 0.0,
    "google_safe_browsing": 0.0,
}

_FUSION_RESULT = {
    "verdict": "SAFE",
    "s_risk": 0.08,
    "s_idn": 0.05,
    "s_ti": 0.0,
    "shap_explanation": {
        "idn_contribution": 0.02,
        "llm_contribution": 0.03,
        "ti_contribution": 0.01,
        "idn_local_score": 0.05,
        "baseline": 0.5,
    },
}

_FUSION_PHISHING = {
    "verdict": "PHISHING",
    "s_risk": 0.95,
    "s_idn": 0.9,
    "s_ti": 0.8,
    "shap_explanation": {
        "idn_contribution": 0.45,
        "llm_contribution": 0.30,
        "ti_contribution": 0.20,
        "idn_local_score": 0.9,
        "baseline": 0.5,
    },
}


# ── Fixture: override all agent dependencies ──────────────────────────────────

@pytest.fixture
def mock_pipeline():
    mock_idn = AsyncMock()
    mock_idn.analyze.return_value = _IDN_RESULT

    mock_llm = AsyncMock()
    mock_llm.analyze.return_value = _LLM_RESULT

    mock_fusion = AsyncMock()
    mock_fusion.analyze.return_value = _FUSION_RESULT

    mock_cache = AsyncMock()
    mock_cache.get_or_fetch_ti.return_value = _TI_SCORES

    mock_ti = MagicMock()

    app.dependency_overrides[_idn] = lambda: mock_idn
    app.dependency_overrides[_llm] = lambda: mock_llm
    app.dependency_overrides[_fusion] = lambda: mock_fusion
    app.dependency_overrides[_cache] = lambda: mock_cache
    app.dependency_overrides[_ti] = lambda: mock_ti

    yield {
        "idn": mock_idn,
        "llm": mock_llm,
        "fusion": mock_fusion,
        "cache": mock_cache,
        "ti": mock_ti,
    }

    app.dependency_overrides.clear()


# ── Dependency factory functions ──────────────────────────────────────────────

def test_idn_factory_returns_idn_agent():
    from agents.idn_agent import IDNAgent
    agent = _idn()
    assert isinstance(agent, IDNAgent)


def test_llm_factory_returns_llm_agent():
    from agents.llm_agent import LLMAgent
    agent = _llm()
    assert isinstance(agent, LLMAgent)


def test_fusion_factory_returns_fusion_agent():
    from agents.fusion_agent import FusionAgent
    agent = _fusion()
    assert isinstance(agent, FusionAgent)


def test_cache_factory_returns_cache_manager():
    from data_pipeline.cache_manager import CacheManager
    cache = _cache()
    assert isinstance(cache, CacheManager)


def test_ti_factory_returns_ti_service():
    from data_pipeline.threat_intel import ThreatIntelService
    service = _ti()
    assert isinstance(service, ThreatIntelService)


# ── POST /api/v1/analyze ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_analyze_valid_url_returns_200(mock_pipeline):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.post(
            "/api/v1/analyze",
            json={"url": "https://apple.com/login", "source": "extension"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "SAFE"
    assert data["domain"] == "apple.com"
    assert "s_risk" in data
    assert "idn_analysis" in data
    assert "llm_analysis" in data
    assert "shap_explanation" in data


@pytest.mark.asyncio
async def test_analyze_phishing_verdict(mock_pipeline):
    mock_pipeline["fusion"].analyze.return_value = _FUSION_PHISHING

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.post(
            "/api/v1/analyze",
            json={"url": "https://xn--pple-43d.com/account"},
        )
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "PHISHING"


@pytest.mark.asyncio
async def test_analyze_url_no_host_returns_422(mock_pipeline):
    # "https://" passes Pydantic validator but sanitize_url raises InvalidURLError
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.post("/api/v1/analyze", json={"url": "https://"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_analyze_non_http_scheme_returns_422(mock_pipeline):
    # Pydantic validator catches ftp:// before it reaches the route
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.post("/api/v1/analyze", json={"url": "ftp://example.com"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_analyze_pipeline_error_returns_500(mock_pipeline):
    from core.exceptions import IDNAnalysisError

    mock_pipeline["idn"].analyze.side_effect = IDNAnalysisError("IDN stage failed")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.post(
            "/api/v1/analyze",
            json={"url": "https://example.com"},
        )
    assert resp.status_code == 500
    assert "pipeline" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_analyze_all_agents_called(mock_pipeline):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        await client.post("/api/v1/analyze", json={"url": "https://test.example.com"})

    mock_pipeline["idn"].analyze.assert_called_once()
    mock_pipeline["llm"].analyze.assert_called_once()
    mock_pipeline["fusion"].analyze.assert_called_once()
    mock_pipeline["cache"].get_or_fetch_ti.assert_called_once()
