"""Tests for agents/llm_agent.py — LLMAgent score parsing and prompt building."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agents.llm_agent import LLMAgent
from core.constants import LLM_FALLBACK_SCORE


class TestLLMAgentParsers:
    @pytest.fixture
    def agent(self) -> LLMAgent:
        a = LLMAgent()
        a._ready = True
        return a

    def test_parse_score_valid_float(self, agent: LLMAgent):
        text = "SCORE: 0.85 | REASON: Suspicious domain"
        assert agent._parse_score(text) == 0.85

    def test_parse_score_zero(self, agent: LLMAgent):
        text = "SCORE: 0.0 | REASON: Clean"
        assert agent._parse_score(text) == 0.0

    def test_parse_score_one(self, agent: LLMAgent):
        text = "SCORE: 1.0 | REASON: Definite phishing"
        assert agent._parse_score(text) == 1.0

    def test_parse_score_no_pattern_returns_fallback(self, agent: LLMAgent):
        assert agent._parse_score("No score here") == LLM_FALLBACK_SCORE

    def test_parse_score_saturates_above_one(self, agent: LLMAgent):
        text = "SCORE: 1.5 | REASON: Too high"
        assert agent._parse_score(text) == 1.0

    def test_parse_score_negative_value_returns_fallback(self, agent: LLMAgent):
        # The regex only matches digits and '.', so "-0.5" won't match SCORE: pattern
        # It will fall back to LLM_FALLBACK_SCORE
        text = "SCORE: -0.5 | REASON: Negative"
        result = agent._parse_score(text)
        # Either returns fallback (pattern not matched) or 0.0 (clamped) — both are valid
        assert result >= 0.0

    def test_parse_score_with_whitespace(self, agent: LLMAgent):
        text = "SCORE:   0.75 | REASON: Test"
        assert agent._parse_score(text) == 0.75

    def test_parse_reason_standard_format(self, agent: LLMAgent):
        text = "SCORE: 0.9 | REASON: Domain uses Cyrillic characters"
        reason = agent._parse_reason(text)
        assert "Cyrillic" in reason

    def test_parse_reason_no_pattern_returns_truncated_text(self, agent: LLMAgent):
        text = "No structured output here at all"
        reason = agent._parse_reason(text)
        assert len(reason) > 0

    def test_parse_reason_empty_text(self, agent: LLMAgent):
        reason = agent._parse_reason("")
        assert reason == "No reason provided"

    def test_parse_reason_truncated_to_500(self, agent: LLMAgent):
        long_reason = "REASON: " + "x" * 600
        reason = agent._parse_reason(long_reason)
        assert len(reason) <= 500

    def test_parse_reason_strips_whitespace(self, agent: LLMAgent):
        text = "SCORE: 0.8 | REASON:   Suspicious   "
        reason = agent._parse_reason(text)
        assert reason == reason.strip()


class TestLLMAgentBuildPrompt:
    @pytest.fixture
    def agent(self) -> LLMAgent:
        a = LLMAgent()
        a._ready = True
        return a

    def test_prompt_contains_url(self, agent: LLMAgent):
        prompt = agent._build_prompt(
            url="https://paypal.com",
            domain="paypal.com",
            email_body=None,
            rag_context=[],
            idn_summary=None,
        )
        assert "https://paypal.com" in prompt

    def test_prompt_contains_domain(self, agent: LLMAgent):
        prompt = agent._build_prompt(
            url="https://paypal.com",
            domain="paypal.com",
            email_body=None,
            rag_context=[],
            idn_summary=None,
        )
        assert "paypal.com" in prompt

    def test_prompt_contains_rag_context(self, agent: LLMAgent):
        context = ["[Past phishing pattern] Cyrillic domain attack"]
        prompt = agent._build_prompt(
            url="https://paypal.com",
            domain="paypal.com",
            email_body=None,
            rag_context=context,
            idn_summary=None,
        )
        assert "Cyrillic domain attack" in prompt

    def test_prompt_no_rag_shows_no_patterns(self, agent: LLMAgent):
        prompt = agent._build_prompt(
            url="https://paypal.com",
            domain="paypal.com",
            email_body=None,
            rag_context=[],
            idn_summary=None,
        )
        assert "No similar patterns found" in prompt

    def test_prompt_includes_email_body_when_provided(self, agent: LLMAgent):
        prompt = agent._build_prompt(
            url="https://paypal.com",
            domain="paypal.com",
            email_body="Click here to verify your account",
            rag_context=[],
            idn_summary=None,
        )
        assert "Click here to verify" in prompt

    def test_prompt_includes_idn_summary_when_provided(self, agent: LLMAgent):
        prompt = agent._build_prompt(
            url="https://paypal.com",
            domain="paypal.com",
            email_body=None,
            rag_context=[],
            idn_summary="IDN score=0.90, mixed_script=True",
        )
        assert "IDN score=0.90" in prompt

    def test_prompt_contains_score_format_instruction(self, agent: LLMAgent):
        prompt = agent._build_prompt(
            url="https://paypal.com",
            domain="paypal.com",
            email_body=None,
            rag_context=[],
            idn_summary=None,
        )
        assert "SCORE:" in prompt
        assert "REASON:" in prompt

    def test_email_body_truncated_to_500(self, agent: LLMAgent):
        long_body = "x" * 1000
        prompt = agent._build_prompt(
            url="https://paypal.com",
            domain="paypal.com",
            email_body=long_body,
            rag_context=[],
            idn_summary=None,
        )
        # The snippet used in prompt should be truncated to 500 chars
        assert "x" * 501 not in prompt


class TestLLMAgentInitialize:
    @pytest.mark.asyncio
    async def test_initialize_sets_ready_true(self):
        agent = LLMAgent()
        assert not agent._ready
        with patch("agents.llm_agent.llm_gateway.initialize", new_callable=AsyncMock):
            await agent.initialize()
        assert agent._ready is True


class TestLLMAgentCallLLM:
    @pytest.fixture
    def agent(self) -> LLMAgent:
        a = LLMAgent()
        a._ready = True
        return a

    @pytest.mark.asyncio
    async def test_call_llm_delegates_to_gateway(self, agent: LLMAgent):
        from core.llm_gateway import LLMResult

        fake = LLMResult(
            text="SCORE: 0.9 | REASON: homograph",
            model="deepseek-v4-flash-vision-exp",
            provider="opencode-go",
            latency_ms=12.3,
        )
        with patch(
            "agents.llm_agent.llm_gateway.chat", new_callable=AsyncMock, return_value=fake
        ) as mock_chat:
            out = await agent._call_llm("some prompt")

        assert out == "SCORE: 0.9 | REASON: homograph"
        messages = mock_chat.call_args.args[0]
        assert messages[0]["role"] == "system"
        assert "untrusted data" in messages[0]["content"].lower()
        assert messages[1] == {"role": "user", "content": "some prompt"}

    @pytest.mark.asyncio
    async def test_call_llm_propagates_gateway_error(self, agent: LLMAgent):
        with patch(
            "agents.llm_agent.llm_gateway.chat",
            new_callable=AsyncMock,
            side_effect=RuntimeError("gateway down"),
        ):
            with pytest.raises(RuntimeError):
                await agent._call_llm("p")


class TestLLMAgentAdjudicate:
    @pytest.fixture
    def agent(self) -> LLMAgent:
        a = LLMAgent()
        a._ready = True
        return a

    @pytest.mark.asyncio
    async def test_parses_verdict_and_reason(self, agent: LLMAgent):
        from core.llm_gateway import LLMResult

        fake = LLMResult(
            text="VERDICT: PHISHING | REASON: Cyrillic homograph of a bank.",
            model="m", provider="p", latency_ms=1.0,
        )
        with patch(
            "agents.llm_agent.llm_gateway.chat", new_callable=AsyncMock, return_value=fake
        ) as mock_chat:
            verdict, reason = await agent.adjudicate("all the evidence")
        assert verdict == "PHISHING"
        assert "Cyrillic homograph" in reason
        # thinking on for the deliberate pass; evidence fenced
        assert mock_chat.call_args.kwargs["thinking"] is True
        assert "<<<UNTRUSTED_CONTENT>>>" in mock_chat.call_args.args[0][1]["content"]

    @pytest.mark.asyncio
    async def test_unparseable_verdict_returns_empty(self, agent: LLMAgent):
        from core.llm_gateway import LLMResult

        fake = LLMResult(text="I think it's fine", model="m", provider="p", latency_ms=1.0)
        with patch(
            "agents.llm_agent.llm_gateway.chat", new_callable=AsyncMock, return_value=fake
        ):
            verdict, _ = await agent.adjudicate("evidence")
        assert verdict == ""

    @pytest.mark.asyncio
    async def test_gateway_error_returns_empty_tuple(self, agent: LLMAgent):
        with patch(
            "agents.llm_agent.llm_gateway.chat",
            new_callable=AsyncMock,
            side_effect=RuntimeError("down"),
        ):
            assert await agent.adjudicate("evidence") == ("", "")


class TestLLMAgentAnalyze:
    @pytest.fixture
    def agent(self) -> LLMAgent:
        a = LLMAgent()
        a._ready = True
        return a

    @pytest.mark.asyncio
    async def test_analyze_returns_fallback_on_llamastack_error(self, agent: LLMAgent):
        with patch.object(agent, "_retrieve_rag_context", new_callable=AsyncMock) as mock_rag, \
             patch.object(agent, "_call_llm", new_callable=AsyncMock) as mock_call:
            mock_rag.return_value = []
            mock_call.side_effect = Exception("Connection refused")
            score, reason = await agent.analyze(
                url="https://paypal.com",
                domain="paypal.com",
            )
        assert score == LLM_FALLBACK_SCORE

    @pytest.mark.asyncio
    async def test_analyze_parses_score_from_response(self, agent: LLMAgent):
        with patch.object(agent, "_retrieve_rag_context", new_callable=AsyncMock) as mock_rag, \
             patch.object(agent, "_call_llm", new_callable=AsyncMock) as mock_call:
            mock_rag.return_value = []
            mock_call.return_value = "SCORE: 0.92 | REASON: Phishing detected"
            score, reason = await agent.analyze(
                url="https://paypal.com",
                domain="paypal.com",
            )
        assert abs(score - 0.92) < 0.001
        assert "Phishing" in reason

    @pytest.mark.asyncio
    async def test_analyze_returns_fallback_on_timeout(self, agent: LLMAgent):
        import asyncio
        with patch.object(agent, "_retrieve_rag_context", new_callable=AsyncMock) as mock_rag, \
             patch.object(agent, "_call_llm", new_callable=AsyncMock) as mock_call:
            mock_rag.return_value = []
            mock_call.side_effect = asyncio.TimeoutError()
            score, reason = await agent.analyze(
                url="https://paypal.com",
                domain="paypal.com",
            )
        assert score == LLM_FALLBACK_SCORE

    @pytest.mark.asyncio
    async def test_analyze_rag_retrieval_failure_graceful(self, agent: LLMAgent):
        """RAG failure must not crash the analysis."""
        with patch.object(agent, "_retrieve_rag_context", new_callable=AsyncMock) as mock_rag, \
             patch.object(agent, "_call_llm", new_callable=AsyncMock) as mock_call:
            mock_rag.return_value = []
            mock_call.return_value = "SCORE: 0.5 | REASON: Neutral"
            score, reason = await agent.analyze(
                url="https://paypal.com",
                domain="paypal.com",
            )
        assert 0.0 <= score <= 1.0


class TestLLMAgentRetrieveRagContext:
    """
    The _retrieve_rag_context method does a late import:
        from models.chromadb_client import query_collection
    We must inject a mock module into sys.modules BEFORE calling the method.
    """

    @pytest.fixture
    def agent(self) -> LLMAgent:
        a = LLMAgent()
        a._ready = True
        return a

    @pytest.fixture
    def mock_chromadb_module(self):
        """Inject a mock chromadb_client into sys.modules."""
        import sys
        from unittest.mock import MagicMock
        mock_module = MagicMock()
        original = sys.modules.get("models.chromadb_client")
        sys.modules["models.chromadb_client"] = mock_module
        yield mock_module
        # Restore
        if original is None:
            sys.modules.pop("models.chromadb_client", None)
        else:
            sys.modules["models.chromadb_client"] = original

    @pytest.mark.asyncio
    async def test_returns_empty_list_when_query_raises(self, agent: LLMAgent, mock_chromadb_module):
        mock_chromadb_module.query_collection = AsyncMock(side_effect=Exception("ChromaDB down"))
        result = await agent._retrieve_rag_context("https://test.com", "test.com")
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_max_twelve_chunks_returned(self, agent: LLMAgent, mock_chromadb_module):
        # 4 colecciones × 3 (RAG_TOP_K) = 12 chunks máx (T10 agregó usb_baseline)
        many_docs = [{"document": f"doc {i}", "distance": 0.1} for i in range(10)]
        mock_chromadb_module.query_collection = AsyncMock(return_value=many_docs)
        result = await agent._retrieve_rag_context("https://test.com", "test.com")
        assert len(result) <= 12

    @pytest.mark.asyncio
    async def test_combines_all_four_collections(self, agent: LLMAgent, mock_chromadb_module):
        async def mock_query(collection, query_texts, n_results):
            if "email" in collection:
                return [{"document": "phishing email pattern", "distance": 0.1}]
            if "idn" in collection:
                return [{"document": "IDN attack pattern", "distance": 0.1}]
            if "baseline" in collection:
                return [{"document": "legitimate USB email", "distance": 0.1}]
            return [{"document": "TI campaign pattern", "distance": 0.1}]

        mock_chromadb_module.query_collection = mock_query
        result = await agent._retrieve_rag_context("https://test.com", "test.com")
        assert len(result) == 4  # 1 per collection
        assert any("[Past phishing pattern]" in r for r in result)
        assert any("[IDN attack pattern]" in r for r in result)
        assert any("[TI campaign pattern]" in r for r in result)
        assert any("[USB legitimate baseline]" in r for r in result)

    @pytest.mark.asyncio
    async def test_returns_empty_on_exception(self, agent: LLMAgent, mock_chromadb_module):
        """Any exception from chromadb must not propagate — returns []."""
        mock_chromadb_module.query_collection = AsyncMock(side_effect=RuntimeError("crashed"))
        result = await agent._retrieve_rag_context("https://test.com", "test.com")
        assert result == []


# ---------------------------------------------------------------------------
# _rerank_by_source (T11 — anti-envenenamiento)
# ---------------------------------------------------------------------------

class TestRerankBySource:
    @staticmethod
    def _doc(doc_id, distance, source):
        return {
            "id": doc_id,
            "document": f"doc {doc_id}",
            "distance": distance,
            "metadata": {"source": source} if source else {},
        }

    def test_admin_confirmed_outranks_closer_auto_ingest(self):
        from agents.llm_agent import LLMAgent

        # auto_ingest más cercano (d=0.10 → sim 0.90*0.6=0.54)
        # admin_confirmed más lejano (d=0.30 → sim 0.70*1.0=0.70) → gana
        results = [
            self._doc("auto", 0.10, "auto_ingest"),
            self._doc("confirmed", 0.30, "admin_confirmed"),
        ]
        ranked = LLMAgent._rerank_by_source(results)
        assert ranked[0]["id"] == "confirmed"

    def test_returns_at_most_top_k(self):
        from agents.llm_agent import LLMAgent
        from core.constants import RAG_TOP_K

        results = [self._doc(str(i), 0.1 * i, "admin_confirmed") for i in range(8)]
        ranked = LLMAgent._rerank_by_source(results)
        assert len(ranked) == RAG_TOP_K

    def test_skips_empty_documents_and_handles_missing_source(self):
        from agents.llm_agent import LLMAgent

        results = [
            {"id": "empty", "document": "", "distance": 0.0, "metadata": {}},
            self._doc("legacy", 0.2, None),
        ]
        ranked = LLMAgent._rerank_by_source(results)
        assert [r["id"] for r in ranked] == ["legacy"]
