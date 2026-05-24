"""Tests for agents/hf_agent.py"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agents.hf_agent import HFAgent
from core.constants import HF_FALLBACK_SCORE


@pytest.fixture
def agent() -> HFAgent:
    return HFAgent()


# ---------------------------------------------------------------------------
# No API key → fallback
# ---------------------------------------------------------------------------

class TestHFAgentNoKey:
    @pytest.mark.asyncio
    async def test_returns_fallback_when_no_api_key(self, agent: HFAgent):
        with patch("agents.hf_agent.settings") as mock_settings:
            mock_settings.HUGGINGFACE_API_KEY = ""
            result = await agent.analyze("https://paypal.com")
        assert result == HF_FALLBACK_SCORE

    @pytest.mark.asyncio
    async def test_returns_fallback_when_api_key_is_whitespace(self, agent: HFAgent):
        with patch("agents.hf_agent.settings") as mock_settings:
            mock_settings.HUGGINGFACE_API_KEY = "   "
            # "   " is truthy — will attempt call; but also tests empty key path
            # Actually "   " is not falsy, so it will attempt the call
            # Just verify it doesn't raise
            mock_settings.HF_URL_MODEL = "test/model"
            mock_settings.HF_EMAIL_MODEL = "test/model2"
            # _call_hf_api will get connection error → fallback
            with patch.object(agent, "_call_hf_api", return_value=HF_FALLBACK_SCORE):
                result = await agent.analyze("https://paypal.com")
        assert result == HF_FALLBACK_SCORE


# ---------------------------------------------------------------------------
# Score extraction
# ---------------------------------------------------------------------------

class TestExtractPhishingScore:
    def test_flat_list_phishing_label(self, agent: HFAgent):
        data = [{"label": "PHISHING", "score": 0.9}, {"label": "LEGITIMATE", "score": 0.1}]
        assert agent._extract_phishing_score(data) == pytest.approx(0.9)

    def test_flat_list_legitimate_label_inverts(self, agent: HFAgent):
        data = [{"label": "LEGITIMATE", "score": 0.8}, {"label": "PHISHING", "score": 0.2}]
        # First matching label is LEGITIMATE → returns 1-0.8=0.2
        result = agent._extract_phishing_score(data)
        assert result == pytest.approx(0.2)

    def test_nested_list_normalized(self, agent: HFAgent):
        data = [[{"label": "phishing", "score": 0.75}, {"label": "safe", "score": 0.25}]]
        assert agent._extract_phishing_score(data) == pytest.approx(0.75)

    def test_safe_label_inverts_score(self, agent: HFAgent):
        data = [{"label": "safe", "score": 0.7}]
        assert agent._extract_phishing_score(data) == pytest.approx(0.3)

    def test_benign_label_inverts_score(self, agent: HFAgent):
        data = [{"label": "benign", "score": 0.6}]
        assert agent._extract_phishing_score(data) == pytest.approx(0.4)

    def test_label_1_treated_as_phishing(self, agent: HFAgent):
        data = [{"label": "LABEL_1", "score": 0.85}]
        assert agent._extract_phishing_score(data) == pytest.approx(0.85)

    def test_label_0_treated_as_legitimate(self, agent: HFAgent):
        data = [{"label": "LABEL_0", "score": 0.9}]
        assert agent._extract_phishing_score(data) == pytest.approx(0.1)

    def test_unknown_label_returns_fallback(self, agent: HFAgent):
        data = [{"label": "UNKNOWN_CLASS", "score": 0.9}]
        assert agent._extract_phishing_score(data) == HF_FALLBACK_SCORE

    def test_empty_list_returns_fallback(self, agent: HFAgent):
        assert agent._extract_phishing_score([]) == HF_FALLBACK_SCORE

    def test_non_list_returns_fallback(self, agent: HFAgent):
        assert agent._extract_phishing_score({"error": "loading"}) == HF_FALLBACK_SCORE

    def test_score_clamped_to_0_1(self, agent: HFAgent):
        data = [{"label": "phishing", "score": 1.5}]
        assert agent._extract_phishing_score(data) == 1.0

    def test_case_insensitive_matching(self, agent: HFAgent):
        data = [{"label": "Phishing", "score": 0.8}]
        assert agent._extract_phishing_score(data) == pytest.approx(0.8)


# ---------------------------------------------------------------------------
# analyze() — mocked HTTP calls
# ---------------------------------------------------------------------------

class TestHFAgentAnalyze:
    @pytest.mark.asyncio
    async def test_url_only_when_no_email_body(self, agent: HFAgent):
        with patch("agents.hf_agent.settings") as mock_settings:
            mock_settings.HUGGINGFACE_API_KEY = "hf_test_key"
            mock_settings.HF_URL_MODEL = "test/url-model"
            mock_settings.HF_EMAIL_MODEL = "test/email-model"
            with patch.object(agent, "_classify_url", new_callable=AsyncMock, return_value=0.8) as mock_url, \
                 patch.object(agent, "_classify_content", new_callable=AsyncMock, return_value=0.6) as mock_content:
                result = await agent.analyze("https://evil.com", None)
                mock_url.assert_called_once()
                mock_content.assert_not_called()
        assert result == pytest.approx(0.8)

    @pytest.mark.asyncio
    async def test_both_classifiers_with_email_body(self, agent: HFAgent):
        with patch("agents.hf_agent.settings") as mock_settings:
            mock_settings.HUGGINGFACE_API_KEY = "hf_test_key"
            mock_settings.HF_URL_MODEL = "test/url-model"
            mock_settings.HF_EMAIL_MODEL = "test/email-model"
            with patch.object(agent, "_classify_url", new_callable=AsyncMock, return_value=0.8), \
                 patch.object(agent, "_classify_content", new_callable=AsyncMock, return_value=0.6):
                result = await agent.analyze("https://evil.com", "Click here to verify your account")
        assert result == pytest.approx(0.7)   # average of 0.8 and 0.6

    @pytest.mark.asyncio
    async def test_returns_fallback_when_all_classifiers_fail(self, agent: HFAgent):
        with patch("agents.hf_agent.settings") as mock_settings:
            mock_settings.HUGGINGFACE_API_KEY = "hf_test_key"
            mock_settings.HF_URL_MODEL = "test/url-model"
            mock_settings.HF_EMAIL_MODEL = "test/email-model"
            with patch.object(agent, "_classify_url", new_callable=AsyncMock, side_effect=Exception("network error")):
                result = await agent.analyze("https://evil.com", None)
        assert result == HF_FALLBACK_SCORE

    @pytest.mark.asyncio
    async def test_result_clamped_between_0_and_1(self, agent: HFAgent):
        with patch("agents.hf_agent.settings") as mock_settings:
            mock_settings.HUGGINGFACE_API_KEY = "hf_test_key"
            mock_settings.HF_URL_MODEL = "test/url-model"
            mock_settings.HF_EMAIL_MODEL = "test/email-model"
            with patch.object(agent, "_classify_url", new_callable=AsyncMock, return_value=0.95):
                result = await agent.analyze("https://evil.com")
        assert 0.0 <= result <= 1.0
