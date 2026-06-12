"""Integration tests for POST /api/v1/analyze and related endpoints."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from auth.jwt import create_access_token
from main import app
from schemas.analyze import (
    AgentScores,
    AnalyzeResponse,
    IDNResult,
    ShapExplanation,
    TIResult,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_analyze_response(
    verdict: str = "PHISHING", s_risk: float = 0.85
) -> AnalyzeResponse:
    return AnalyzeResponse(
        request_id=str(uuid.uuid4()),
        url="https://рaypal.com/login",
        domain="рaypal.com",
        verdict=verdict,
        s_risk=s_risk,
        agent_scores=AgentScores(
            s_idn_local=0.90,
            s_ti=0.89,
            s_idn=0.90,
            s_llm=0.80,
            s_risk=s_risk,
        ),
        idn_result=IDNResult(
            domain_unicode="рaypal",
            confusable_chars=["р"],
            homograph_ratio=0.333,
            visual_similarity=0.857,
            s_idn_local=0.90,
            is_mixed_script=True,
            is_suspicious=True,
        ),
        ti_result=TIResult(s_vt=0.9, s_urlscan=0.8, s_gsb=1.0, s_ti=0.89),
        llm_reason="Domain uses Cyrillic characters to impersonate paypal.com",
        shap_explanation=ShapExplanation(
            feature_contributions={
                "s_idn_local": 0.27,
                "s_ti": 0.18,
                "s_llm": 0.40,
                "s_vt": 0.09,
                "s_urlscan": 0.05,
                "s_gsb": 0.04,
                "homograph_ratio": 0.04,
                "visual_similarity": 0.06,
                "is_mixed_script": 0.03,
            }
        ),
        processing_ms=250.0,
        timestamp=datetime.now(timezone.utc),
    )


def _valid_token() -> str:
    """Generate a real JWT signed with the test secret."""
    return create_access_token({"sub": "test-user", "role": "admin"})


def _auth_headers() -> dict:
    return {"Authorization": f"Bearer {_valid_token()}"}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    """TestClient with patched lifespan so no real DB/Redis is needed."""
    # Patch the functions as called inside main.py's lifespan
    with patch("main.init_db", new_callable=AsyncMock), \
         patch("main.close_db", new_callable=AsyncMock), \
         patch("main.init_redis", new_callable=AsyncMock), \
         patch("main.close_redis", new_callable=AsyncMock):
        with TestClient(app) as c:
            yield c


@pytest.fixture
def mock_pipeline(client):
    """Mock the entire 3-agent pipeline for integration tests."""
    phishing_response = _make_mock_analyze_response()
    with patch("routers.analyze_router.idn_agent") as mock_idn, \
         patch("routers.analyze_router.threat_intel_service") as mock_ti, \
         patch("routers.analyze_router.llm_agent") as mock_llm, \
         patch("routers.analyze_router.fusion_agent") as mock_fusion, \
         patch("routers.analyze_router._persist_incident", new_callable=AsyncMock):
        mock_idn.analyze = AsyncMock(
            return_value=IDNResult(
                domain_unicode="рaypal",
                confusable_chars=["р"],
                homograph_ratio=0.333,
                visual_similarity=0.857,
                s_idn_local=0.90,
                is_mixed_script=True,
                is_suspicious=True,
            )
        )
        mock_ti.analyze = AsyncMock(
            return_value=TIResult(s_vt=0.9, s_urlscan=0.8, s_gsb=1.0, s_ti=0.89)
        )
        mock_llm.analyze = AsyncMock(return_value=(0.80, "Suspicious IDN domain"))
        mock_fusion.fuse = AsyncMock(return_value=phishing_response)
        yield {
            "idn": mock_idn,
            "ti": mock_ti,
            "llm": mock_llm,
            "fusion": mock_fusion,
            "response": phishing_response,
        }


@pytest.fixture
def mock_pipeline_legit(client):
    """Mock pipeline returning a LEGITIMATE verdict."""
    legit_response = _make_mock_analyze_response(verdict="LEGITIMATE", s_risk=0.05)
    with patch("routers.analyze_router.idn_agent") as mock_idn, \
         patch("routers.analyze_router.threat_intel_service") as mock_ti, \
         patch("routers.analyze_router.llm_agent") as mock_llm, \
         patch("routers.analyze_router.fusion_agent") as mock_fusion, \
         patch("routers.analyze_router._persist_incident", new_callable=AsyncMock):
        mock_idn.analyze = AsyncMock(
            return_value=IDNResult(
                domain_unicode="paypal",
                confusable_chars=[],
                homograph_ratio=0.0,
                visual_similarity=0.0,
                s_idn_local=0.0,
                is_mixed_script=False,
                is_suspicious=False,
            )
        )
        mock_ti.analyze = AsyncMock(
            return_value=TIResult(s_vt=0.0, s_urlscan=0.0, s_gsb=0.0, s_ti=0.0)
        )
        mock_llm.analyze = AsyncMock(return_value=(0.05, "Clean domain"))
        mock_fusion.fuse = AsyncMock(return_value=legit_response)
        yield legit_response


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_returns_ok_status(self, client):
        resp = client.get("/health")
        data = resp.json()
        assert data["status"] == "ok"

    def test_health_returns_version(self, client):
        resp = client.get("/health")
        data = resp.json()
        assert "version" in data

    def test_health_no_auth_required(self, client):
        # No authorization header
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_contains_timestamp(self, client):
        resp = client.get("/health")
        data = resp.json()
        assert "timestamp" in data


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

class TestAuthentication:
    def test_analyze_without_auth_header_returns_4xx(self, client):
        resp = client.post("/api/v1/analyze", json={"url": "https://paypal.com"})
        assert resp.status_code in {401, 403}

    def test_analyze_with_invalid_token_returns_401(self, client):
        resp = client.post(
            "/api/v1/analyze",
            json={"url": "https://paypal.com"},
            headers={"Authorization": "Bearer invalid.token.here"},
        )
        assert resp.status_code == 401

    def test_analyze_with_valid_token_passes_auth(self, client, mock_pipeline):
        resp = client.post(
            "/api/v1/analyze",
            json={"url": "https://рaypal.com/login"},
            headers=_auth_headers(),
        )
        # Auth passed — should not be 401 or 403
        assert resp.status_code not in {401, 403}


# ---------------------------------------------------------------------------
# Request validation
# ---------------------------------------------------------------------------

class TestRequestValidation:
    def test_missing_url_returns_422(self, client):
        resp = client.post(
            "/api/v1/analyze",
            json={},
            headers=_auth_headers(),
        )
        assert resp.status_code == 422

    def test_url_without_scheme_returns_422(self, client):
        resp = client.post(
            "/api/v1/analyze",
            json={"url": "not-a-url"},
            headers=_auth_headers(),
        )
        assert resp.status_code == 422

    def test_url_with_only_domain_returns_422(self, client):
        resp = client.post(
            "/api/v1/analyze",
            json={"url": "paypal.com"},
            headers=_auth_headers(),
        )
        assert resp.status_code == 422

    def test_url_http_scheme_accepted(self, client, mock_pipeline):
        resp = client.post(
            "/api/v1/analyze",
            json={"url": "http://paypal.com"},
            headers=_auth_headers(),
        )
        assert resp.status_code == 200

    def test_url_https_scheme_accepted(self, client, mock_pipeline):
        resp = client.post(
            "/api/v1/analyze",
            json={"url": "https://paypal.com"},
            headers=_auth_headers(),
        )
        assert resp.status_code == 200

    def test_optional_email_hash_accepted(self, client, mock_pipeline):
        resp = client.post(
            "/api/v1/analyze",
            json={
                "url": "https://рaypal.com/login",
                "email_hash": "abc123hash",
            },
            headers=_auth_headers(),
        )
        assert resp.status_code == 200

    def test_optional_email_body_snippet_accepted(self, client, mock_pipeline):
        resp = client.post(
            "/api/v1/analyze",
            json={
                "url": "https://рaypal.com/login",
                "email_body_snippet": "Click here to verify",
            },
            headers=_auth_headers(),
        )
        assert resp.status_code == 200

    def test_empty_url_string_returns_422(self, client):
        resp = client.post(
            "/api/v1/analyze",
            json={"url": ""},
            headers=_auth_headers(),
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Response schema
# ---------------------------------------------------------------------------

class TestAnalyzeResponse:
    def test_phishing_verdict_in_response(self, client, mock_pipeline):
        resp = client.post(
            "/api/v1/analyze",
            json={"url": "https://рaypal.com/login"},
            headers=_auth_headers(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "PHISHING"

    def test_s_risk_present_and_in_range(self, client, mock_pipeline):
        resp = client.post(
            "/api/v1/analyze",
            json={"url": "https://рaypal.com/login"},
            headers=_auth_headers(),
        )
        data = resp.json()
        assert "s_risk" in data
        assert 0.0 <= data["s_risk"] <= 1.0

    def test_response_contains_shap_explanation(self, client, mock_pipeline):
        resp = client.post(
            "/api/v1/analyze",
            json={"url": "https://рaypal.com/login"},
            headers=_auth_headers(),
        )
        data = resp.json()
        assert "shap_explanation" in data
        assert "feature_contributions" in data["shap_explanation"]

    def test_response_contains_idn_result(self, client, mock_pipeline):
        resp = client.post(
            "/api/v1/analyze",
            json={"url": "https://рaypal.com/login"},
            headers=_auth_headers(),
        )
        data = resp.json()
        assert "idn_result" in data
        idn = data["idn_result"]
        assert "domain_unicode" in idn
        assert "s_idn_local" in idn
        assert "homograph_ratio" in idn

    def test_response_contains_ti_result(self, client, mock_pipeline):
        resp = client.post(
            "/api/v1/analyze",
            json={"url": "https://рaypal.com/login"},
            headers=_auth_headers(),
        )
        data = resp.json()
        assert "ti_result" in data
        ti = data["ti_result"]
        assert "s_vt" in ti
        assert "s_urlscan" in ti
        assert "s_gsb" in ti

    def test_response_contains_request_id(self, client, mock_pipeline):
        resp = client.post(
            "/api/v1/analyze",
            json={"url": "https://рaypal.com/login"},
            headers=_auth_headers(),
        )
        data = resp.json()
        assert "request_id" in data
        assert len(data["request_id"]) > 0

    def test_response_contains_processing_ms(self, client, mock_pipeline):
        resp = client.post(
            "/api/v1/analyze",
            json={"url": "https://рaypal.com/login"},
            headers=_auth_headers(),
        )
        data = resp.json()
        assert "processing_ms" in data

    def test_legitimate_url_returns_legitimate_verdict(self, client, mock_pipeline_legit):
        resp = client.post(
            "/api/v1/analyze",
            json={"url": "https://paypal.com"},
            headers=_auth_headers(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "LEGITIMATE"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestAnalyzeErrorHandling:
    def test_idn_analysis_error_returns_500(self, client):
        from core.exceptions import IDNAnalysisError
        with patch("routers.analyze_router.idn_agent") as mock_idn, \
             patch("routers.analyze_router.threat_intel_service") as mock_ti:
            mock_idn.analyze = AsyncMock(
                side_effect=IDNAnalysisError("IDN failed", "detail")
            )
            mock_ti.analyze = AsyncMock(
                return_value=TIResult(s_vt=0.0, s_urlscan=0.0, s_gsb=0.0, s_ti=0.0)
            )
            resp = client.post(
                "/api/v1/analyze",
                json={"url": "https://paypal.com"},
                headers=_auth_headers(),
            )
        assert resp.status_code == 500

    def test_threat_intel_error_returns_500(self, client):
        from core.exceptions import ThreatIntelError
        with patch("routers.analyze_router.idn_agent") as mock_idn, \
             patch("routers.analyze_router.threat_intel_service") as mock_ti:
            mock_idn.analyze = AsyncMock(
                return_value=IDNResult(
                    domain_unicode="paypal",
                    confusable_chars=[],
                    homograph_ratio=0.0,
                    visual_similarity=0.0,
                    s_idn_local=0.0,
                    is_mixed_script=False,
                    is_suspicious=False,
                )
            )
            mock_ti.analyze = AsyncMock(
                side_effect=ThreatIntelError("TI failed", "detail")
            )
            resp = client.post(
                "/api/v1/analyze",
                json={"url": "https://paypal.com"},
                headers=_auth_headers(),
            )
        assert resp.status_code == 500

    def test_llm_timeout_uses_fallback_score(self, client):
        """LLM timeout should not fail the pipeline — fallback 0.5 applied."""
        from core.exceptions import LLMTimeoutError
        phishing_response = _make_mock_analyze_response(verdict="LEGITIMATE", s_risk=0.25)
        with patch("routers.analyze_router.idn_agent") as mock_idn, \
             patch("routers.analyze_router.threat_intel_service") as mock_ti, \
             patch("routers.analyze_router.llm_agent") as mock_llm, \
             patch("routers.analyze_router.fusion_agent") as mock_fusion, \
             patch("routers.analyze_router._persist_incident", new_callable=AsyncMock):
            mock_idn.analyze = AsyncMock(
                return_value=IDNResult(
                    domain_unicode="paypal",
                    confusable_chars=[],
                    homograph_ratio=0.0,
                    visual_similarity=0.0,
                    s_idn_local=0.0,
                    is_mixed_script=False,
                    is_suspicious=False,
                )
            )
            mock_ti.analyze = AsyncMock(
                return_value=TIResult(s_vt=0.0, s_urlscan=0.0, s_gsb=0.0, s_ti=0.0)
            )
            mock_llm.analyze = AsyncMock(
                side_effect=LLMTimeoutError("Timeout", "url=test")
            )
            mock_fusion.fuse = AsyncMock(return_value=phishing_response)
            resp = client.post(
                "/api/v1/analyze",
                json={"url": "https://paypal.com"},
                headers=_auth_headers(),
            )
        # Pipeline must not return 500 on LLM timeout
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# New endpoints — /analyze_email alias and /report
# ---------------------------------------------------------------------------

class TestNewEndpoints:
    def test_analyze_email_alias_returns_200(self, client, mock_pipeline):
        """POST /analyze_email con el schema completo de la extensión → 200."""
        with patch(
            "routers.analyze_router._analyze_single_url_for_email",
            new_callable=AsyncMock,
            return_value=mock_pipeline["response"],
        ), patch(
            "routers.analyze_router._persist_email_incident",
            new_callable=AsyncMock,
        ), patch(
            "routers.analyze_router.check_rate_limit", new_callable=AsyncMock
        ):
            resp = client.post(
                "/api/v1/analyze_email",
                json={
                    "email_subject": "Verifique su cuenta",
                    "email_from": "soporte@рaypal.com",
                    "email_to": "victima@usbbog.edu.co",
                    "email_body_html": "<a href='https://рaypal.com/login'>entrar</a>",
                    "email_text_snippet": "Su cuenta será suspendida",
                    "all_urls": ["https://рaypal.com/login"],
                },
                headers=_auth_headers(),
            )
        assert resp.status_code == 200
        assert resp.json()["email_verdict"] == "PHISHING"

    def test_report_endpoint_returns_201(self, client):
        """POST /report debe retornar 201."""
        with patch("routers.analyze_router._persist_manual_report", new_callable=AsyncMock), \
             patch("routers.analyze_router.asyncio") as mock_asyncio:
            mock_asyncio.create_task = MagicMock()
            resp = client.post(
                "/api/v1/report",
                json={"url": "https://evil.com", "reported_verdict": "PHISHING"},
                headers=_auth_headers(),
            )
        assert resp.status_code == 201
        data = resp.json()
        assert "report_id" in data
        assert data["reported_verdict"] == "PHISHING"

    def test_report_endpoint_invalid_verdict_returns_422(self, client):
        """Verdict inválido debe retornar 422."""
        resp = client.post(
            "/api/v1/report",
            json={"url": "https://evil.com", "reported_verdict": "INVALID"},
            headers=_auth_headers(),
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Generic exception paths (uncovered branches)
# ---------------------------------------------------------------------------

class TestAnalyzeGenericExceptionPaths:
    """Cover lines 80-81, 113-115, 145-147, 166-168 in analyze_router.py."""

    @pytest.fixture
    def client(self):
        with patch("main.init_db", new_callable=AsyncMock), \
             patch("main.close_db", new_callable=AsyncMock), \
             patch("main.init_redis", new_callable=AsyncMock), \
             patch("main.close_redis", new_callable=AsyncMock):
            with TestClient(app) as c:
                yield c

    def test_domain_extraction_failure_returns_422(self, client):
        """Lines 80-81: extract_domain raises → 422."""
        with patch("routers.analyze_router.extract_effective_domain",
                   side_effect=ValueError("malformed host")), \
             patch("routers.analyze_router.check_rate_limit", new_callable=AsyncMock):
            resp = client.post(
                "/api/v1/analyze",
                json={"url": "https://paypal.com"},
                headers=_auth_headers(),
            )
        assert resp.status_code == 422
        assert "dominio" in resp.json()["detail"].lower() or "domain" in resp.json()["detail"].lower()

    def test_stage1_generic_exception_returns_500(self, client):
        """Lines 113-115: RuntimeError in asyncio.gather (not IDNAnalysisError/ThreatIntelError)."""
        with patch("routers.analyze_router.idn_agent") as mock_idn, \
             patch("routers.analyze_router.threat_intel_service") as mock_ti, \
             patch("routers.analyze_router.check_rate_limit", new_callable=AsyncMock):
            mock_idn.analyze = AsyncMock(side_effect=RuntimeError("unexpected stage 1 error"))
            mock_ti.analyze = AsyncMock(
                return_value=TIResult(s_vt=0.0, s_urlscan=0.0, s_gsb=0.0, s_ti=0.0)
            )
            resp = client.post(
                "/api/v1/analyze",
                json={"url": "https://paypal.com"},
                headers=_auth_headers(),
            )
        assert resp.status_code == 500
        assert "stage 1" in resp.json()["detail"]

    def test_stage2_generic_exception_returns_500(self, client):
        """Lines 145-147: RuntimeError in llm_agent.analyze (not LLMTimeoutError)."""
        with patch("routers.analyze_router.idn_agent") as mock_idn, \
             patch("routers.analyze_router.threat_intel_service") as mock_ti, \
             patch("routers.analyze_router.llm_agent") as mock_llm, \
             patch("routers.analyze_router.check_rate_limit", new_callable=AsyncMock):
            mock_idn.analyze = AsyncMock(
                return_value=IDNResult(
                    domain_unicode="paypal", confusable_chars=[],
                    homograph_ratio=0.0, visual_similarity=0.0,
                    s_idn_local=0.0, is_mixed_script=False, is_suspicious=False,
                )
            )
            mock_ti.analyze = AsyncMock(
                return_value=TIResult(s_vt=0.0, s_urlscan=0.0, s_gsb=0.0, s_ti=0.0)
            )
            mock_llm.analyze = AsyncMock(side_effect=RuntimeError("unexpected LLM crash"))
            resp = client.post(
                "/api/v1/analyze",
                json={"url": "https://paypal.com"},
                headers=_auth_headers(),
            )
        assert resp.status_code == 500
        assert "stage 2" in resp.json()["detail"]

    def test_stage3_generic_exception_returns_500(self, client):
        """Lines 166-168: RuntimeError in fusion_agent.fuse."""
        with patch("routers.analyze_router.idn_agent") as mock_idn, \
             patch("routers.analyze_router.threat_intel_service") as mock_ti, \
             patch("routers.analyze_router.llm_agent") as mock_llm, \
             patch("routers.analyze_router.fusion_agent") as mock_fusion, \
             patch("routers.analyze_router.check_rate_limit", new_callable=AsyncMock):
            mock_idn.analyze = AsyncMock(
                return_value=IDNResult(
                    domain_unicode="paypal", confusable_chars=[],
                    homograph_ratio=0.0, visual_similarity=0.0,
                    s_idn_local=0.0, is_mixed_script=False, is_suspicious=False,
                )
            )
            mock_ti.analyze = AsyncMock(
                return_value=TIResult(s_vt=0.0, s_urlscan=0.0, s_gsb=0.0, s_ti=0.0)
            )
            mock_llm.analyze = AsyncMock(return_value=(0.5, "neutral"))
            mock_fusion.fuse = AsyncMock(side_effect=RuntimeError("unexpected fusion crash"))
            resp = client.post(
                "/api/v1/analyze",
                json={"url": "https://paypal.com"},
                headers=_auth_headers(),
            )
        assert resp.status_code == 500
        assert "stage 3" in resp.json()["detail"]
