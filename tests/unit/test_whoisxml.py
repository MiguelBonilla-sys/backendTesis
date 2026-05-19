"""Tests for WhoisXML integration in ThreatIntelService"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx
from datetime import datetime, timezone, timedelta


class TestQueryWhoisXML:
    @pytest.mark.asyncio
    async def test_returns_zero_when_no_api_key(self):
        from data_pipeline.threat_intel import ThreatIntelService
        service = ThreatIntelService()
        with patch("data_pipeline.threat_intel.settings") as mock_settings:
            mock_settings.WHOISXML_API_KEY = ""
            score, age = await service._query_whoisxml("paypal")
        assert score == 0.0
        assert age is None

    @pytest.mark.asyncio
    async def test_high_score_for_new_domain(self):
        """Dominio registrado hace 10 días → score 0.8."""
        from data_pipeline.threat_intel import ThreatIntelService
        service = ThreatIntelService()

        ten_days_ago = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "WhoisRecord": {
                "createdDateNormalized": ten_days_ago,
            }
        }

        with patch("data_pipeline.threat_intel.settings") as mock_settings, \
             patch("httpx.AsyncClient") as mock_client:
            mock_settings.WHOISXML_API_KEY = "test_key"
            mock_settings.DOMAIN_AGE_SUSPICIOUS_DAYS = 30
            mock_client.return_value.__aenter__ = AsyncMock(return_value=MagicMock(
                get=AsyncMock(return_value=mock_response)
            ))
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
            score, age = await service._query_whoisxml("newdomain")

        assert score == 0.8
        assert age == 10

    @pytest.mark.asyncio
    async def test_zero_score_for_old_domain(self):
        """Dominio registrado hace 5 años → score 0.0."""
        from data_pipeline.threat_intel import ThreatIntelService
        service = ThreatIntelService()

        old_date = (datetime.now(timezone.utc) - timedelta(days=1825)).isoformat()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "WhoisRecord": {"createdDateNormalized": old_date}
        }

        with patch("data_pipeline.threat_intel.settings") as mock_settings, \
             patch("httpx.AsyncClient") as mock_client:
            mock_settings.WHOISXML_API_KEY = "test_key"
            mock_settings.DOMAIN_AGE_SUSPICIOUS_DAYS = 30
            mock_client.return_value.__aenter__ = AsyncMock(return_value=MagicMock(
                get=AsyncMock(return_value=mock_response)
            ))
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
            score, age = await service._query_whoisxml("olddomain")

        assert score == 0.0
        assert age == 1825

    @pytest.mark.asyncio
    async def test_returns_zero_on_timeout(self):
        from data_pipeline.threat_intel import ThreatIntelService
        service = ThreatIntelService()

        with patch("data_pipeline.threat_intel.settings") as mock_settings, \
             patch("httpx.AsyncClient") as mock_client:
            mock_settings.WHOISXML_API_KEY = "test_key"
            mock_settings.DOMAIN_AGE_SUSPICIOUS_DAYS = 30
            mock_client.return_value.__aenter__ = AsyncMock(return_value=MagicMock(
                get=AsyncMock(side_effect=httpx.TimeoutException("timeout"))
            ))
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
            score, age = await service._query_whoisxml("domain")

        assert score == 0.0
        assert age is None


class TestTIResultWithAge:
    def test_ti_result_includes_domain_age_fields(self):
        from schemas.analyze import TIResult
        result = TIResult(
            s_vt=0.5, s_urlscan=0.3, s_gsb=0.2, s_ti=0.4,
            domain_age_days=15,
            is_newly_registered=True,
        )
        assert result.domain_age_days == 15
        assert result.is_newly_registered is True

    def test_ti_result_age_defaults_to_none(self):
        from schemas.analyze import TIResult
        result = TIResult(s_vt=0.5, s_urlscan=0.3, s_gsb=0.2, s_ti=0.4)
        assert result.domain_age_days is None
        assert result.is_newly_registered is False
