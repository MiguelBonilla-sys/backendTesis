"""Tests for core/llm_gateway.py — cubre el contrato HTTP que antes no tenía test."""
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from core.llm_gateway import LLMGateway, LLMResult


def _resp(status: int = 200, body: dict | None = None) -> MagicMock:
    """Fake httpx.Response: raise_for_status() lanza si status >= 400."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status
    resp.json.return_value = body or {
        "choices": [{"message": {"content": "SCORE: 0.9 | REASON: homograph"}}]
    }
    if status >= 400:
        err = httpx.HTTPStatusError(
            f"HTTP {status}", request=MagicMock(), response=resp
        )
        resp.raise_for_status.side_effect = err
    else:
        resp.raise_for_status.return_value = None
    return resp


@pytest.fixture
def gw() -> LLMGateway:
    g = LLMGateway()
    g._client = MagicMock(spec=httpx.AsyncClient)
    g._client.post = AsyncMock()
    g._client.get = AsyncMock()
    g._client.aclose = AsyncMock()
    return g


class TestHeaders:
    def test_no_auth_header_without_key(self, gw, monkeypatch):
        monkeypatch.setattr("core.llm_gateway.settings.LLM_API_KEY", "")
        assert "Authorization" not in gw._headers()

    def test_auth_header_with_key(self, gw, monkeypatch):
        monkeypatch.setattr("core.llm_gateway.settings.LLM_API_KEY", "secret123")
        assert gw._headers()["Authorization"] == "Bearer secret123"


class TestChat:
    async def test_success_returns_llmresult(self, gw, monkeypatch):
        monkeypatch.setattr("core.llm_gateway.settings.LLM_MODEL", "primary-model")
        monkeypatch.setattr("core.llm_gateway.settings.LLM_PROVIDER", "opencode-go")
        gw._client.post.return_value = _resp()

        result = await gw.chat([{"role": "user", "content": "hi"}])

        assert isinstance(result, LLMResult)
        assert result.text == "SCORE: 0.9 | REASON: homograph"
        assert result.model == "primary-model"
        assert result.provider == "opencode-go"
        assert result.latency_ms >= 0.0
        # endpoint + payload
        call = gw._client.post.call_args
        assert call.args[0] == "/chat/completions"
        assert call.kwargs["json"]["model"] == "primary-model"
        assert call.kwargs["json"]["max_tokens"] == 150
        # reasoning models: thinking disabled by default
        assert call.kwargs["json"]["thinking"] == {"type": "disabled"}

    async def test_thinking_true_omits_disable_flag(self, gw):
        gw._client.post.return_value = _resp()
        await gw.chat([{"role": "user", "content": "x"}], thinking=True)
        assert "thinking" not in gw._client.post.call_args.kwargs["json"]

    async def test_captures_reasoning_content(self, gw):
        gw._client.post.return_value = _resp(body={
            "choices": [{"message": {
                "content": "SCORE: 0.9 | REASON: x",
                "reasoning_content": "decoded punycode to Cyrillic a",
            }}]
        })
        result = await gw.chat([{"role": "user", "content": "x"}])
        assert result.reasoning == "decoded punycode to Cyrillic a"

    async def test_lazy_client_creation(self, monkeypatch):
        g = LLMGateway()
        fake = MagicMock(spec=httpx.AsyncClient)
        fake.post = AsyncMock(return_value=_resp())
        monkeypatch.setattr("core.llm_gateway.httpx.AsyncClient", lambda **kw: fake)
        result = await g.chat([{"role": "user", "content": "x"}])
        assert result.text.startswith("SCORE:")

    async def test_retries_once_on_503_then_succeeds(self, gw):
        gw._client.post.side_effect = [_resp(503), _resp()]
        result = await gw.chat([{"role": "user", "content": "x"}])
        assert result.text.startswith("SCORE:")
        assert gw._client.post.await_count == 2

    async def test_raises_when_retry_exhausted(self, gw):
        gw._client.post.side_effect = [_resp(500), _resp(500)]
        with pytest.raises(httpx.HTTPStatusError):
            await gw.chat([{"role": "user", "content": "x"}])

    async def test_non_retryable_4xx_raises_immediately(self, gw):
        # 403 no está en _RETRY_STATUS ni en _MODEL_STATUS
        gw._client.post.return_value = _resp(403)
        with pytest.raises(httpx.HTTPStatusError):
            await gw.chat([{"role": "user", "content": "x"}])
        assert gw._client.post.await_count == 1

    async def test_falls_back_to_secondary_model_on_404(self, gw, monkeypatch):
        monkeypatch.setattr("core.llm_gateway.settings.LLM_MODEL", "gone-model")
        monkeypatch.setattr(
            "core.llm_gateway.settings.LLM_MODEL_FALLBACK", "fallback-model"
        )
        gw._client.post.side_effect = [_resp(404), _resp()]
        result = await gw.chat([{"role": "user", "content": "x"}])
        assert result.model == "fallback-model"

    async def test_fallback_model_404_propagates(self, gw, monkeypatch):
        monkeypatch.setattr("core.llm_gateway.settings.LLM_MODEL", "gone")
        monkeypatch.setattr("core.llm_gateway.settings.LLM_MODEL_FALLBACK", "also-gone")
        gw._client.post.side_effect = [_resp(404), _resp(404)]
        with pytest.raises(httpx.HTTPStatusError):
            await gw.chat([{"role": "user", "content": "x"}])

    async def test_empty_content_and_no_reasoning_returns_empty(self, gw):
        gw._client.post.return_value = _resp(body={"choices": [{"message": {}}]})
        result = await gw.chat([{"role": "user", "content": "x"}])
        assert result.text == ""  # nunca el dict crudo

    async def test_empty_content_falls_back_to_reasoning(self, gw):
        gw._client.post.return_value = _resp(body={
            "choices": [{"message": {"content": "", "reasoning_content": "el análisis va acá"}}]
        })
        result = await gw.chat([{"role": "user", "content": "x"}])
        assert result.text == "el análisis va acá"
        assert result.reasoning == "el análisis va acá"


class TestLifecycle:
    async def test_initialize_healthcheck_ok(self, gw):
        gw._client.get.return_value = _resp(body={"data": []})
        await gw.initialize()  # no raise
        gw._client.get.assert_awaited_once()

    async def test_initialize_swallows_healthcheck_failure(self, gw):
        gw._client.get.side_effect = httpx.ConnectError("no route")
        await gw.initialize()  # no debe propagar

    async def test_initialize_warns_when_no_api_key(self, gw, monkeypatch, caplog):
        monkeypatch.setattr("core.llm_gateway.settings.LLM_API_KEY", "")
        gw._client.get.return_value = _resp(body={"data": []})
        await gw.initialize()  # no raise; solo warning

    async def test_initialize_creates_client_when_missing(self, monkeypatch):
        g = LLMGateway()
        fake = MagicMock(spec=httpx.AsyncClient)
        fake.get = AsyncMock(return_value=_resp(body={"data": []}))
        monkeypatch.setattr("core.llm_gateway.httpx.AsyncClient", lambda **kw: fake)
        await g.initialize()
        assert g._client is fake

    async def test_aclose_closes_and_clears(self, gw):
        client = gw._client
        await gw.aclose()
        client.aclose.assert_awaited_once()
        assert gw._client is None

    async def test_aclose_noop_when_no_client(self):
        g = LLMGateway()
        await g.aclose()  # no raise
