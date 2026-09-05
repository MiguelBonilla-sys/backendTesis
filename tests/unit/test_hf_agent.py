"""Tests for agents/hf_agent.py"""
from __future__ import annotations

import asyncio
import json
import threading
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from agents.hf_agent import HFAgent
from core.constants import HF_FALLBACK_SCORE


@pytest.fixture
def agent() -> HFAgent:
    return HFAgent()


@pytest.fixture(autouse=True)
def _no_url_onnx():
    """Por defecto el modelo ONNX de URL no está disponible en los tests → el
    clasificador de URL cae a _call_hf_api (que los tests ya mockean). Además
    resetea el cache global entre tests."""
    import agents.hf_agent as hf_mod

    hf_mod._url_onnx_session = None
    hf_mod._url_onnx_tried = True  # ya "intentado", None → skip
    with patch("agents.hf_agent._get_url_onnx", return_value=None):
        yield
    hf_mod._url_onnx_tried = False
    hf_mod._url_onnx_session = None


# ---------------------------------------------------------------------------
# No API key → fallback
# ---------------------------------------------------------------------------

class TestHFAgentNoKey:
    @pytest.mark.asyncio
    async def test_returns_fallback_when_no_api_key(self, agent: HFAgent):
        # Sin key y sin ONNX: URL → _call_hf_api (mock), content no se llama.
        with patch("agents.hf_agent.settings") as mock_settings, \
             patch.object(agent, "_call_hf_api", new_callable=AsyncMock,
                          return_value=HF_FALLBACK_SCORE):
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


class TestHFAgentUrlOnnx:
    async def test_model_loading_does_not_block_the_event_loop(self, agent):
        loop_thread = threading.get_ident()
        loaded_in = []

        def load():
            loaded_in.append(threading.get_ident())
            return None

        with patch("agents.hf_agent._get_url_onnx", side_effect=load):
            assert await agent._url_onnx_score("https://example.com") is None
        assert loaded_in and loaded_in[0] != loop_thread

    async def test_local_model_deadline_returns_neutral(self, agent):
        async def stalled(_url):
            await asyncio.sleep(10)

        with patch.object(agent, "_url_onnx_score", side_effect=stalled), \
             patch("agents.hf_agent.HF_TIMEOUT_S", 0.01):
            assert await agent._classify_url("https://example.com") == HF_FALLBACK_SCORE

    @pytest.mark.asyncio
    async def test_uses_onnx_when_available_no_api_call(self, agent: HFAgent):
        fake = MagicMock()
        # run(...) → list; [1] = [[p_legit, p_phish]]
        fake.run.return_value = [None, [[0.08, 0.92]]]
        with patch("agents.hf_agent._get_url_onnx", return_value=fake), \
             patch.object(agent, "_call_hf_api", new_callable=AsyncMock) as api:
            score = await agent._classify_url("http://phish.example/login")
        assert score == pytest.approx(0.92)
        api.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_falls_back_to_api_when_onnx_infer_fails(self, agent: HFAgent):
        fake = MagicMock()
        fake.run.side_effect = RuntimeError("bad input")
        with patch("agents.hf_agent._get_url_onnx", return_value=fake), \
             patch.object(agent, "_call_hf_api", new_callable=AsyncMock,
                          return_value=HF_FALLBACK_SCORE) as api:
            score = await agent._classify_url("http://x/y")
        assert score == HF_FALLBACK_SCORE
        api.assert_awaited_once()


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


@pytest.mark.parametrize("model", ["test/url", "test/email"])
async def test_external_hf_payload_is_redacted_before_truncation(agent, model, monkeypatch):
    sent = []

    def handle(request):
        sent.append(json.loads(request.content)["inputs"])
        return httpx.Response(200, json=[{"label": "PHISHING", "score": 0.6}])

    original_client = httpx.AsyncClient
    monkeypatch.setattr("agents.hf_agent.settings.LLM_REDACT_PROMPT", True)
    monkeypatch.setattr("agents.hf_agent.settings.HF_EMAIL_MODEL", "test/email")
    with patch("agents.hf_agent.httpx.AsyncClient",
               side_effect=lambda **kwargs: original_client(
                   transport=httpx.MockTransport(handle), **kwargs)):
        result = await agent._call_hf_api(model, "private@example.com " + "a" * 600)
    assert result == 0.6
    assert "private@example.com" not in sent[0] and "[EMAIL_1]" in sent[0]
    if model == "test/email":
        assert len(sent[0]) == 512


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
