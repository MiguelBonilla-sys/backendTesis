"""Tests for data_pipeline/reranker.py — LLM-rerank of retrieved chunks."""
from unittest.mock import AsyncMock, patch

from data_pipeline.reranker import _parse_order, llm_rerank


def _res(text: str):
    from core.llm_gateway import LLMResult

    return LLMResult(text=text, model="m", provider="p", latency_ms=1.0)


class TestParseOrder:
    def test_extracts_and_dedupes_in_range(self):
        # 99 y 7 fuera de rango (n=6); 0 repetido
        assert _parse_order("3, 0, 5, 0, 99, 7", 6) == [3, 0, 5]

    def test_prose_wrapped_indices(self):
        assert _parse_order("Order: [2] then [1] then [0]", 3) == [2, 1, 0]

    def test_empty_or_garbage(self):
        assert _parse_order("no numbers here", 5) == []
        assert _parse_order("", 5) == []


class TestLLMRerank:
    async def test_noop_with_zero_or_one_chunk(self):
        with patch("data_pipeline.reranker.llm_gateway.chat", new_callable=AsyncMock) as c:
            assert await llm_rerank("q", [], 12) == []
            assert await llm_rerank("q", ["only"], 12) == ["only"]
        c.assert_not_awaited()

    async def test_reorders_by_returned_indices(self):
        chunks = ["A", "B", "C", "D"]
        with patch("data_pipeline.reranker.llm_gateway.chat",
                   new_callable=AsyncMock, return_value=_res("2,0,3,1")):
            out = await llm_rerank("q", chunks, 12)
        assert out == ["C", "A", "D", "B"]

    async def test_partial_order_keeps_rest_stable_then_truncates(self):
        chunks = ["A", "B", "C", "D", "E"]
        with patch("data_pipeline.reranker.llm_gateway.chat",
                   new_callable=AsyncMock, return_value=_res("3,1")):
            out = await llm_rerank("q", chunks, 4)
        # 3,1 first; luego A,C,E en orden original; truncado a 4
        assert out == ["D", "B", "A", "C"]

    async def test_gateway_error_returns_original_truncated(self):
        chunks = ["A", "B", "C"]
        with patch("data_pipeline.reranker.llm_gateway.chat",
                   new_callable=AsyncMock, side_effect=RuntimeError("down")):
            out = await llm_rerank("q", chunks, 2)
        assert out == ["A", "B"]

    async def test_unparseable_response_returns_original(self):
        chunks = ["A", "B", "C"]
        with patch("data_pipeline.reranker.llm_gateway.chat",
                   new_callable=AsyncMock, return_value=_res("I cannot rank these")):
            out = await llm_rerank("q", chunks, 3)
        assert out == ["A", "B", "C"]

    async def test_prompt_has_numbered_passages(self):
        with patch("data_pipeline.reranker.llm_gateway.chat",
                   new_callable=AsyncMock, return_value=_res("0,1")) as c:
            await llm_rerank("phishing query", ["first", "second"], 12)
        user_msg = c.call_args.args[0][1]["content"]
        assert "[0] first" in user_msg and "[1] second" in user_msg
