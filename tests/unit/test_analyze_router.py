"""Tests for routers/analyze_router.py — full pipeline with mocked agents."""

import pytest
from httpx import ASGITransport, AsyncClient
from unittest.mock import AsyncMock, MagicMock, patch

from main import app
from auth.auth import require_auth as _require_auth
from data_pipeline.analysis_repo import save_full_analysis as _save_full_analysis
from models.database import get_session
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
    "s_llm": 0.1,
    "s_ti": 0.0,
    "top_features": ["idn_contribution", "llm_contribution", "ti_contribution"],
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
    "s_llm": 0.8,
    "s_ti": 0.8,
    "top_features": ["idn_contribution", "ti_contribution", "llm_contribution"],
    "shap_explanation": {
        "idn_contribution": 0.45,
        "llm_contribution": 0.30,
        "ti_contribution": 0.20,
        "idn_local_score": 0.9,
        "baseline": 0.5,
    },
}

_MOCK_USER = {"sub": "test_user", "role": "admin"}


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _mock_session_gen():
    """Async generator that yields a bare mock session for get_session override."""
    yield AsyncMock()


# ── Fixture: override all agent + infra dependencies ─────────────────────────

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
    # Auth: inject a pre-validated user dict so tests don't need real JWTs
    app.dependency_overrides[_require_auth] = lambda: _MOCK_USER
    # DB session override — session itself is not exercised in router tests
    app.dependency_overrides[get_session] = _mock_session_gen

    # Prevent background task from hitting analysis_repo (no real DB)
    with patch("routers.analyze_router.save_full_analysis") as mock_save:
        yield {
            "idn": mock_idn,
            "llm": mock_llm,
            "fusion": mock_fusion,
            "cache": mock_cache,
            "ti": mock_ti,
            "save": mock_save,
        }

    app.dependency_overrides.clear()


# ── Dependency factory functions ──────────────────────────────────────────────

def test_idn_factory_returns_idn_agent():
    from agents.idn_agent import IDNAgent
    assert isinstance(_idn(), IDNAgent)


def test_llm_factory_returns_llm_agent():
    from agents.llm_agent import LLMAgent
    assert isinstance(_llm(), LLMAgent)


def test_fusion_factory_returns_fusion_agent():
    from agents.fusion_agent import FusionAgent
    assert isinstance(_fusion(), FusionAgent)


def test_cache_factory_returns_cache_manager():
    from data_pipeline.cache_manager import CacheManager
    assert isinstance(_cache(), CacheManager)


def test_ti_factory_returns_ti_service():
    from data_pipeline.threat_intel import ThreatIntelService
    assert isinstance(_ti(), ThreatIntelService)


# ── POST /api/v1/analyze ──────────────────────────────────────────────────────

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
    assert "s_llm" in data
    assert "top_features" in data
    assert "idn_analysis" in data
    assert "llm_analysis" in data
    assert "shap_explanation" in data


async def test_analyze_phishing_verdict(mock_pipeline):
    mock_pipeline["fusion"].analyze.return_value = _FUSION_PHISHING

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.post(
            "/api/v1/analyze",
            json={"url": "https://xn--pple-43d.com/account"},
        )
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "PHISHING"


async def test_analyze_url_no_host_returns_422(mock_pipeline):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.post("/api/v1/analyze", json={"url": "https://"})
    assert resp.status_code == 422


async def test_analyze_non_http_scheme_returns_422(mock_pipeline):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.post("/api/v1/analyze", json={"url": "ftp://example.com"})
    assert resp.status_code == 422


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


async def test_analyze_all_agents_called(mock_pipeline):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        await client.post("/api/v1/analyze", json={"url": "https://test.example.com"})

    mock_pipeline["idn"].analyze.assert_called_once()
    mock_pipeline["llm"].analyze.assert_called_once()
    mock_pipeline["fusion"].analyze.assert_called_once()
    mock_pipeline["cache"].get_or_fetch_ti.assert_called_once()


# ── Auth ──────────────────────────────────────────────────────────────────────

async def test_analyze_without_token_returns_401(mock_pipeline):
    """Requests without Authorization header must be rejected with 401."""
    # Remove the auth override to test the real guard
    del app.dependency_overrides[_require_auth]
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
            resp = await client.post("/api/v1/analyze", json={"url": "https://apple.com"})
        assert resp.status_code == 401
    finally:
        # Restore override so teardown clear() works cleanly
        app.dependency_overrides[_require_auth] = lambda: _MOCK_USER


# ── Background persistence ────────────────────────────────────────────────────

async def test_analyze_background_task_enqueued(mock_pipeline):
    """save_full_analysis must be called (via BackgroundTasks) on a successful analysis."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.post(
            "/api/v1/analyze",
            json={"url": "https://apple.com"},
        )
    assert resp.status_code == 200
    mock_pipeline["save"].assert_called_once()
    call_kwargs = mock_pipeline["save"].call_args.kwargs
    assert "trace_id" in call_kwargs
    assert "url" in call_kwargs
    assert "domain" in call_kwargs


async def test_analyze_email_sha256_computed_when_body_present(mock_pipeline):
    """email_sha256 is SHA-256(email_body) and passed to save_full_analysis."""
    import hashlib

    body = "Click here to verify your account"
    expected_sha = hashlib.sha256(body.encode()).hexdigest()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        await client.post(
            "/api/v1/analyze",
            json={"url": "https://apple.com", "email_body": body},
        )
    call_kwargs = mock_pipeline["save"].call_args.kwargs
    assert call_kwargs["email_sha256"] == expected_sha


async def test_analyze_email_sha256_none_when_no_body(mock_pipeline):
    """email_sha256 is None when no email_body is provided."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        await client.post(
            "/api/v1/analyze",
            json={"url": "https://apple.com"},
        )
    call_kwargs = mock_pipeline["save"].call_args.kwargs
    assert call_kwargs["email_sha256"] is None


# ── Response fields ───────────────────────────────────────────────────────────

async def test_analyze_response_contains_s_llm_and_top_features(mock_pipeline):
    """AnalyzeResponse must include s_llm and top_features fields."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.post("/api/v1/analyze", json={"url": "https://apple.com"})
    data = resp.json()
    assert "s_llm" in data
    assert isinstance(data["s_llm"], float)
    assert "top_features" in data
    assert isinstance(data["top_features"], list)
