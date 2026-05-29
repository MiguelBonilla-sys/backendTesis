"""Tests for data_pipeline/threat_intel.py — ThreatIntelService."""
from __future__ import annotations

import json

import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock, patch

from core.constants import W_GSB, W_URLSCAN, W_VT, W_WHOIS
from data_pipeline.threat_intel import ThreatIntelService
from schemas.analyze import TIResult


@pytest.fixture
def service() -> ThreatIntelService:
    return ThreatIntelService()


# ---------------------------------------------------------------------------
# Dev/test mode (no API keys) — fast path
# ---------------------------------------------------------------------------

class TestThreatIntelDevMode:
    @pytest.mark.asyncio
    async def test_returns_zero_scores_when_no_keys(self, service: ThreatIntelService):
        """With all TI keys empty, should return S_TI=0.0 immediately."""
        with patch("data_pipeline.threat_intel.get_ti_cache", new_callable=AsyncMock, return_value=None), \
             patch("data_pipeline.threat_intel.set_ti_cache", new_callable=AsyncMock), \
             patch("data_pipeline.threat_intel.settings") as mock_settings:
            mock_settings.VIRUSTOTAL_API_KEY = ""
            mock_settings.URLSCAN_API_KEY = ""
            mock_settings.GOOGLE_SAFE_BROWSING_API_KEY = ""
            mock_settings.WHOISXML_API_KEY = ""
            mock_settings.TI_CACHE_TTL = 3600
            result = await service.analyze("https://paypal.com", "paypal.com")
        assert result.s_vt == 0.0
        assert result.s_urlscan == 0.0
        assert result.s_gsb == 0.0
        assert result.s_ti == 0.0

    @pytest.mark.asyncio
    async def test_returns_cached_result_on_cache_hit(self, service: ThreatIntelService):
        cached_data = {"s_vt": 0.9, "s_urlscan": 0.8, "s_gsb": 1.0, "s_ti": 0.89}
        with patch("data_pipeline.threat_intel.get_ti_cache",
                   new_callable=AsyncMock, return_value=cached_data):
            result = await service.analyze("https://paypal.com", "paypal.com")
        assert result.s_ti == 0.89
        assert result.s_vt == 0.9

    @pytest.mark.asyncio
    async def test_cached_result_is_ti_result_instance(self, service: ThreatIntelService):
        cached_data = {"s_vt": 0.0, "s_urlscan": 0.0, "s_gsb": 0.0, "s_ti": 0.0}
        with patch("data_pipeline.threat_intel.get_ti_cache",
                   new_callable=AsyncMock, return_value=cached_data):
            result = await service.analyze("https://paypal.com", "paypal.com")
        assert isinstance(result, TIResult)


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

def _make_async_client_mock(method: str, response=None, side_effect=None):
    """Helper to build a mock httpx.AsyncClient context manager."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    if side_effect:
        getattr(mock_client, method).side_effect = side_effect
    else:
        getattr(mock_client, method).return_value = response
    return mock_client


class TestQueryVirusTotal:
    @pytest.mark.asyncio
    async def test_returns_zero_when_no_key(self, service: ThreatIntelService):
        with patch("data_pipeline.threat_intel.settings") as s:
            s.VIRUSTOTAL_API_KEY = ""
            result = await service._query_virustotal("https://paypal.com", "paypal.com")
        assert result == 0.0

    @pytest.mark.asyncio
    async def test_returns_malicious_ratio_on_200(self, service: ThreatIntelService):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 10, "harmless": 40, "undetected": 50
                    }
                }
            }
        }
        mock_client = _make_async_client_mock("get", response=mock_response)
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.VIRUSTOTAL_API_KEY = "test-key"
            result = await service._query_virustotal("https://paypal.com", "paypal.com")
        assert abs(result - 0.10) < 0.01

    @pytest.mark.asyncio
    async def test_returns_zero_on_404(self, service: ThreatIntelService):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_client = _make_async_client_mock("get", response=mock_response)
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.VIRUSTOTAL_API_KEY = "test-key"
            result = await service._query_virustotal("https://paypal.com", "paypal.com")
        assert result == 0.0

    @pytest.mark.asyncio
    async def test_returns_zero_on_timeout(self, service: ThreatIntelService):
        mock_client = _make_async_client_mock("get", side_effect=httpx.TimeoutException("timeout"))
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.VIRUSTOTAL_API_KEY = "test-key"
            result = await service._query_virustotal("https://paypal.com", "paypal.com")
        assert result == 0.0

    @pytest.mark.asyncio
    async def test_returns_zero_on_request_error(self, service: ThreatIntelService):
        mock_client = _make_async_client_mock("get", side_effect=httpx.RequestError("error"))
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.VIRUSTOTAL_API_KEY = "test-key"
            result = await service._query_virustotal("https://paypal.com", "paypal.com")
        assert result == 0.0

    @pytest.mark.asyncio
    async def test_returns_zero_when_empty_stats(self, service: ThreatIntelService):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"attributes": {"last_analysis_stats": {}}}}
        mock_client = _make_async_client_mock("get", response=mock_response)
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.VIRUSTOTAL_API_KEY = "test-key"
            result = await service._query_virustotal("https://paypal.com", "paypal.com")
        assert result == 0.0

    @pytest.mark.asyncio
    async def test_returns_zero_on_unexpected_status(self, service: ThreatIntelService):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_client = _make_async_client_mock("get", response=mock_response)
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.VIRUSTOTAL_API_KEY = "test-key"
            result = await service._query_virustotal("https://paypal.com", "paypal.com")
        assert result == 0.0


# ---------------------------------------------------------------------------
# URLScan
# ---------------------------------------------------------------------------

class TestQueryUrlScan:
    @pytest.mark.asyncio
    async def test_returns_zero_when_no_key(self, service: ThreatIntelService):
        with patch("data_pipeline.threat_intel.settings") as s:
            s.URLSCAN_API_KEY = ""
            result = await service._query_urlscan("https://paypal.com", "paypal.com")
        assert result == 0.0

    @pytest.mark.asyncio
    async def test_returns_one_when_malicious_verdict(self, service: ThreatIntelService):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [{"verdicts": {"overall": {"malicious": True, "score": 100}}}]
        }
        mock_client = _make_async_client_mock("get", response=mock_response)
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.URLSCAN_API_KEY = "test-key"
            result = await service._query_urlscan("https://paypal.com", "paypal.com")
        assert result == 1.0

    @pytest.mark.asyncio
    async def test_returns_half_when_suspicious_score(self, service: ThreatIntelService):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [{"verdicts": {"overall": {"malicious": False, "score": 75}}}]
        }
        mock_client = _make_async_client_mock("get", response=mock_response)
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.URLSCAN_API_KEY = "test-key"
            result = await service._query_urlscan("https://paypal.com", "paypal.com")
        assert result == 0.5

    @pytest.mark.asyncio
    async def test_returns_zero_when_no_results(self, service: ThreatIntelService):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"results": []}
        mock_client = _make_async_client_mock("get", response=mock_response)
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.URLSCAN_API_KEY = "test-key"
            result = await service._query_urlscan("https://paypal.com", "paypal.com")
        assert result == 0.0

    @pytest.mark.asyncio
    async def test_returns_zero_on_rate_limit(self, service: ThreatIntelService):
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_client = _make_async_client_mock("get", response=mock_response)
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.URLSCAN_API_KEY = "test-key"
            result = await service._query_urlscan("https://paypal.com", "paypal.com")
        assert result == 0.0

    @pytest.mark.asyncio
    async def test_returns_zero_on_timeout(self, service: ThreatIntelService):
        mock_client = _make_async_client_mock("get", side_effect=httpx.TimeoutException("timeout"))
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.URLSCAN_API_KEY = "test-key"
            result = await service._query_urlscan("https://paypal.com", "paypal.com")
        assert result == 0.0

    @pytest.mark.asyncio
    async def test_returns_zero_on_unexpected_status(self, service: ThreatIntelService):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_client = _make_async_client_mock("get", response=mock_response)
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.URLSCAN_API_KEY = "test-key"
            result = await service._query_urlscan("https://paypal.com", "paypal.com")
        assert result == 0.0


# ---------------------------------------------------------------------------
# Google Safe Browsing
# ---------------------------------------------------------------------------

class TestQueryGSB:
    @pytest.mark.asyncio
    async def test_returns_zero_when_no_key(self, service: ThreatIntelService):
        with patch("data_pipeline.threat_intel.settings") as s:
            s.GOOGLE_SAFE_BROWSING_API_KEY = ""
            result = await service._query_gsb("https://paypal.com")
        assert result == 0.0

    @pytest.mark.asyncio
    async def test_returns_one_when_threat_found(self, service: ThreatIntelService):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}
        mock_client = _make_async_client_mock("post", response=mock_response)
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.GOOGLE_SAFE_BROWSING_API_KEY = "test-key"
            result = await service._query_gsb("https://paypal.com")
        assert result == 1.0

    @pytest.mark.asyncio
    async def test_returns_zero_when_clean(self, service: ThreatIntelService):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_client = _make_async_client_mock("post", response=mock_response)
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.GOOGLE_SAFE_BROWSING_API_KEY = "test-key"
            result = await service._query_gsb("https://paypal.com")
        assert result == 0.0

    @pytest.mark.asyncio
    async def test_returns_zero_on_timeout(self, service: ThreatIntelService):
        mock_client = _make_async_client_mock("post", side_effect=httpx.TimeoutException("timeout"))
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.GOOGLE_SAFE_BROWSING_API_KEY = "test-key"
            result = await service._query_gsb("https://paypal.com")
        assert result == 0.0

    @pytest.mark.asyncio
    async def test_returns_zero_on_request_error(self, service: ThreatIntelService):
        mock_client = _make_async_client_mock("post", side_effect=httpx.RequestError("error"))
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.GOOGLE_SAFE_BROWSING_API_KEY = "test-key"
            result = await service._query_gsb("https://paypal.com")
        assert result == 0.0

    @pytest.mark.asyncio
    async def test_returns_zero_on_unexpected_status(self, service: ThreatIntelService):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_client = _make_async_client_mock("post", response=mock_response)
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.GOOGLE_SAFE_BROWSING_API_KEY = "test-key"
            result = await service._query_gsb("https://paypal.com")
        assert result == 0.0


# ---------------------------------------------------------------------------
# WhoisXML — domain age scoring
# ---------------------------------------------------------------------------

class TestQueryWhoisXML:
    @pytest.mark.asyncio
    async def test_returns_zero_tuple_when_no_key(self, service: ThreatIntelService):
        with patch("data_pipeline.threat_intel.settings") as s:
            s.WHOISXML_API_KEY = ""
            score, age = await service._query_whoisxml("paypal.com")
        assert score == 0.0
        assert age is None

    @pytest.mark.asyncio
    async def test_new_domain_returns_high_score(self, service: ThreatIntelService):
        """Domain registered < DOMAIN_AGE_SUSPICIOUS_DAYS → score 0.8."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "WhoisRecord": {"createdDateNormalized": "2026-05-01T00:00:00Z"}
        }
        mock_client = _make_async_client_mock("get", response=mock_response)
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.WHOISXML_API_KEY = "test-key"
            s.DOMAIN_AGE_SUSPICIOUS_DAYS = 30
            score, age = await service._query_whoisxml("paypal.com")
        assert score == 0.8
        assert age is not None and age >= 0

    @pytest.mark.asyncio
    async def test_moderate_domain_returns_medium_score(self, service: ThreatIntelService):
        """Domain 30–90 days old → score 0.4."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "WhoisRecord": {"createdDateNormalized": "2026-03-01T00:00:00Z"}
        }
        mock_client = _make_async_client_mock("get", response=mock_response)
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.WHOISXML_API_KEY = "test-key"
            s.DOMAIN_AGE_SUSPICIOUS_DAYS = 30
            score, age = await service._query_whoisxml("paypal.com")
        assert score == 0.4
        assert age is not None and age >= 30

    @pytest.mark.asyncio
    async def test_mature_domain_returns_zero_score(self, service: ThreatIntelService):
        """Domain > 90 days old → score 0.0 (no risk added by age)."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "WhoisRecord": {"createdDateNormalized": "2020-01-01T00:00:00Z"}
        }
        mock_client = _make_async_client_mock("get", response=mock_response)
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.WHOISXML_API_KEY = "test-key"
            s.DOMAIN_AGE_SUSPICIOUS_DAYS = 30
            score, age = await service._query_whoisxml("paypal.com")
        assert score == 0.0
        assert age is not None and age > 90

    @pytest.mark.asyncio
    async def test_missing_created_date_returns_zero(self, service: ThreatIntelService):
        """WhoisRecord without createdDateNormalized → (0.0, None)."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"WhoisRecord": {}}
        mock_client = _make_async_client_mock("get", response=mock_response)
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.WHOISXML_API_KEY = "test-key"
            s.DOMAIN_AGE_SUSPICIOUS_DAYS = 30
            score, age = await service._query_whoisxml("paypal.com")
        assert score == 0.0
        assert age is None

    @pytest.mark.asyncio
    async def test_timeout_returns_zero(self, service: ThreatIntelService):
        mock_client = _make_async_client_mock("get", side_effect=httpx.TimeoutException("timeout"))
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.WHOISXML_API_KEY = "test-key"
            score, age = await service._query_whoisxml("paypal.com")
        assert score == 0.0
        assert age is None

    @pytest.mark.asyncio
    async def test_request_error_returns_zero(self, service: ThreatIntelService):
        mock_client = _make_async_client_mock("get", side_effect=httpx.RequestError("err"))
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.WHOISXML_API_KEY = "test-key"
            score, age = await service._query_whoisxml("paypal.com")
        assert score == 0.0
        assert age is None

    @pytest.mark.asyncio
    async def test_unexpected_status_returns_zero(self, service: ThreatIntelService):
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_client = _make_async_client_mock("get", response=mock_response)
        with patch("data_pipeline.threat_intel.settings") as s, \
             patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_client):
            s.WHOISXML_API_KEY = "test-key"
            score, age = await service._query_whoisxml("paypal.com")
        assert score == 0.0
        assert age is None


# ---------------------------------------------------------------------------
# analyze() — aggregation formula verification
# ---------------------------------------------------------------------------

class TestAnalyzeAggregation:
    """Verifies the S_TI = W_VT*vt + W_URLSCAN*urlscan + W_GSB*gsb + W_WHOIS*whois formula."""

    def _mock_ti_gather(self, vt: float, urlscan: float, gsb: float,
                        whois: tuple) -> tuple:
        return (vt, urlscan, gsb, whois)

    @pytest.mark.asyncio
    async def test_aggregation_formula_correct(self, service: ThreatIntelService):
        """S_TI = W_VT*vt + W_URLSCAN*urlscan + W_GSB*gsb + W_WHOIS*whois."""
        vt, urlscan, gsb, whois_score = 0.8, 0.6, 1.0, 0.0
        expected_s_ti = round(
            W_VT * vt + W_URLSCAN * urlscan + W_GSB * gsb + W_WHOIS * whois_score, 4
        )
        with patch("data_pipeline.threat_intel.get_ti_cache", new_callable=AsyncMock, return_value=None), \
             patch("data_pipeline.threat_intel.set_ti_cache", new_callable=AsyncMock), \
             patch("data_pipeline.threat_intel.settings") as s, \
             patch.object(service, "_query_virustotal", new_callable=AsyncMock, return_value=vt), \
             patch.object(service, "_query_urlscan", new_callable=AsyncMock, return_value=urlscan), \
             patch.object(service, "_query_gsb", new_callable=AsyncMock, return_value=gsb), \
             patch.object(service, "_query_whoisxml", new_callable=AsyncMock, return_value=(whois_score, 400)):
            s.VIRUSTOTAL_API_KEY = "k"
            s.URLSCAN_API_KEY = "k"
            s.GOOGLE_SAFE_BROWSING_API_KEY = "k"
            s.WHOISXML_API_KEY = "k"
            s.TI_CACHE_TTL = 3600
            s.DOMAIN_AGE_SUSPICIOUS_DAYS = 30
            result = await service.analyze("https://paypal.com", "paypal.com")

        assert abs(result.s_ti - expected_s_ti) < 0.001

    @pytest.mark.asyncio
    async def test_whois_boost_increases_s_ti(self, service: ThreatIntelService):
        """A new domain (whois_score=0.8) pushes s_ti above the base."""
        vt, urlscan, gsb, whois_score = 0.0, 0.0, 0.0, 0.8
        with patch("data_pipeline.threat_intel.get_ti_cache", new_callable=AsyncMock, return_value=None), \
             patch("data_pipeline.threat_intel.set_ti_cache", new_callable=AsyncMock), \
             patch("data_pipeline.threat_intel.settings") as s, \
             patch.object(service, "_query_virustotal", new_callable=AsyncMock, return_value=vt), \
             patch.object(service, "_query_urlscan", new_callable=AsyncMock, return_value=urlscan), \
             patch.object(service, "_query_gsb", new_callable=AsyncMock, return_value=gsb), \
             patch.object(service, "_query_whoisxml", new_callable=AsyncMock, return_value=(whois_score, 5)):
            s.VIRUSTOTAL_API_KEY = "k"
            s.URLSCAN_API_KEY = "k"
            s.GOOGLE_SAFE_BROWSING_API_KEY = "k"
            s.WHOISXML_API_KEY = "k"
            s.TI_CACHE_TTL = 3600
            s.DOMAIN_AGE_SUSPICIOUS_DAYS = 30
            result = await service.analyze("https://new-domain.com", "new-domain.com")

        assert result.s_ti == round(W_WHOIS * whois_score, 4)
        assert result.is_newly_registered is True

    @pytest.mark.asyncio
    async def test_s_ti_capped_at_one(self, service: ThreatIntelService):
        """Even with all signals at maximum, s_ti ≤ 1.0."""
        with patch("data_pipeline.threat_intel.get_ti_cache", new_callable=AsyncMock, return_value=None), \
             patch("data_pipeline.threat_intel.set_ti_cache", new_callable=AsyncMock), \
             patch("data_pipeline.threat_intel.settings") as s, \
             patch.object(service, "_query_virustotal", new_callable=AsyncMock, return_value=1.0), \
             patch.object(service, "_query_urlscan", new_callable=AsyncMock, return_value=1.0), \
             patch.object(service, "_query_gsb", new_callable=AsyncMock, return_value=1.0), \
             patch.object(service, "_query_whoisxml", new_callable=AsyncMock, return_value=(0.8, 5)):
            s.VIRUSTOTAL_API_KEY = "k"
            s.URLSCAN_API_KEY = "k"
            s.GOOGLE_SAFE_BROWSING_API_KEY = "k"
            s.WHOISXML_API_KEY = "k"
            s.TI_CACHE_TTL = 3600
            s.DOMAIN_AGE_SUSPICIOUS_DAYS = 30
            result = await service.analyze("https://evil.com", "evil.com")

        assert result.s_ti <= 1.0
