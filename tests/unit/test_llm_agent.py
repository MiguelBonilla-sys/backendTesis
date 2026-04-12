"""Tests for agents/llm_agent.py — LlamaStack + ChromaDB RAG (all mocked)."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agents.llm_agent import LLMAgent
from core.exceptions import LLMInferenceError


import numpy as np


@pytest.fixture
def agent_no_chroma() -> LLMAgent:
    return LLMAgent(chromadb_client=None)


@pytest.fixture
def mock_chroma():
    chroma = MagicMock()
    # Mock para RAGRetriever: get_collection().query() -> dict with "documents"
    mock_collection = MagicMock()
    mock_collection.query.return_value = {
        "documents": [["past phishing email snippet 1", "snippet 2", "snippet 3"]]
    }
    chroma.get_collection.return_value = mock_collection
    return chroma


@pytest.fixture
def agent_with_chroma(mock_chroma) -> LLMAgent:
    # LLMAgent inyectará mock_chroma en RAGRetriever
    return LLMAgent(chromadb_client=mock_chroma)


# ── _retrieve_rag ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_retrieve_rag_no_chroma_returns_empty(agent_no_chroma: LLMAgent):
    result = await agent_no_chroma._retrieve_rag("evil.com", "Click here to win!")
    assert result == []


@pytest.mark.asyncio
async def test_retrieve_rag_with_chroma(agent_with_chroma: LLMAgent):
    # Patch encoder to avoid heavy loading
    with patch("agents.rag_retriever._get_encoder") as mock_get_encoder:
        mock_encoder = MagicMock()
        mock_encoder.encode.return_value = np.array([0.1] * 384)
        mock_get_encoder.return_value = mock_encoder

        result = await agent_with_chroma._retrieve_rag("evil.com", "some body")
        # email_embeddings (3) + idn_patterns (3) — mock_chroma returns same 3 docs
        # for both collections since get_collection() returns the same mock_collection.
        assert len(result) == 6
        assert "snippet 1" in result[0]


@pytest.mark.asyncio
async def test_retrieve_rag_chroma_error_returns_empty(mock_chroma):
    # Error en get_collection para disparar el fallback de RAGRetriever
    mock_chroma.get_collection.side_effect = RuntimeError("ChromaDB connection failed")
    agent = LLMAgent(chromadb_client=mock_chroma)
    result = await agent._retrieve_rag("evil.com", "body")
    assert result == []


# ── _build_prompt ─────────────────────────────────────────────────────────────

def test_build_prompt_with_rag_context(agent_no_chroma: LLMAgent):
    prompt = agent_no_chroma._build_prompt(
        "evil.com", "Click here!", 0.85, ["Context snippet 1"]
    )
    assert "evil.com" in prompt
    assert "Context snippet 1" in prompt
    assert "0.85" in prompt
    assert "SCORE:" in prompt


def test_build_prompt_no_rag_context(agent_no_chroma: LLMAgent):
    prompt = agent_no_chroma._build_prompt("safe.com", None, 0.0, [])
    assert "None." in prompt
    assert "safe.com" in prompt


def test_build_prompt_long_body_truncated(agent_no_chroma: LLMAgent):
    long_body = "x" * 1000
    prompt = agent_no_chroma._build_prompt("evil.com", long_body, 0.5, [])
    # Body is truncated to 500 chars
    assert "x" * 500 in prompt
    assert "x" * 501 not in prompt


# ── _parse_score ──────────────────────────────────────────────────────────────

def test_parse_score_valid(agent_no_chroma: LLMAgent):
    result = agent_no_chroma._parse_score({"completion": "SCORE: 0.87 | REASON: looks bad"})
    assert result == pytest.approx(0.87)


def test_parse_score_no_match_returns_half(agent_no_chroma: LLMAgent):
    result = agent_no_chroma._parse_score({"completion": "I cannot determine the score"})
    assert result == 0.5


def test_parse_score_clamped_above_one(agent_no_chroma: LLMAgent):
    result = agent_no_chroma._parse_score({"completion": "SCORE: 1.5 | REASON: very phishy"})
    assert result == 1.0


def test_parse_score_negative_not_matched_returns_half(agent_no_chroma: LLMAgent):
    # Regex [\d.]+ does not match negative numbers, so falls back to 0.5
    result = agent_no_chroma._parse_score({"completion": "SCORE: -0.3 | REASON: negative"})
    assert result == 0.5


def test_parse_score_empty_completion(agent_no_chroma: LLMAgent):
    result = agent_no_chroma._parse_score({})
    assert result == 0.5


# ── _call_llamastack ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_call_llamastack_success(agent_no_chroma: LLMAgent):
    api_response = {
        "choices": [{"message": {"content": "SCORE: 0.9 | REASON: clear phishing"}}],
        "usage": {"total_tokens": 150},
    }
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = api_response

    mock_http = AsyncMock()
    mock_http.post.return_value = mock_resp
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_http)
    mock_cm.__aexit__ = AsyncMock(return_value=False)

    with patch("agents.llm_agent.httpx.AsyncClient", return_value=mock_cm):
        result = await agent_no_chroma._call_llamastack("test prompt")

    assert result["completion"] == "SCORE: 0.9 | REASON: clear phishing"
    assert result["usage"]["total_tokens"] == 150


# ── analyze ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_analyze_success(agent_no_chroma: LLMAgent):
    api_response = {
        "choices": [{"message": {"content": "SCORE: 0.75 | REASON: suspicious domain"}}],
        "usage": {"total_tokens": 80},
    }
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = api_response

    mock_http = AsyncMock()
    mock_http.post.return_value = mock_resp
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_http)
    mock_cm.__aexit__ = AsyncMock(return_value=False)

    with patch("agents.llm_agent.httpx.AsyncClient", return_value=mock_cm):
        result = await agent_no_chroma.analyze("suspicious.com", "Check this!", 0.4)

    assert result["s_llm"] == pytest.approx(0.75)
    assert result["domain"] == "suspicious.com"
    assert "reasoning" in result
    assert "rag_context" in result
    assert "tokens_used" in result


@pytest.mark.asyncio
async def test_analyze_timeout_fallback(agent_no_chroma: LLMAgent):
    async def slow_call(prompt):
        await asyncio.sleep(100)

    with patch.object(agent_no_chroma, "_call_llamastack", slow_call), \
         patch("agents.llm_agent.LLAMASTACK_TIMEOUT_SECONDS", 0.001):
        result = await agent_no_chroma.analyze("evil.com")

    assert result["s_llm"] == 0.5
    assert result["reasoning"] == "timeout"
    assert result["rag_context"] == []
    assert result["tokens_used"] == 0


@pytest.mark.asyncio
async def test_analyze_llm_error_raises_inference_error(agent_no_chroma: LLMAgent):
    async def failing_call(prompt):
        raise ValueError("API error")

    with patch.object(agent_no_chroma, "_call_llamastack", failing_call):
        with pytest.raises(LLMInferenceError):
            await agent_no_chroma.analyze("evil.com")
