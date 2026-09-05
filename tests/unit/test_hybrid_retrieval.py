"""Tests for data_pipeline/hybrid_retrieval.py — dense + BM25 + RRF."""
from unittest.mock import AsyncMock, patch

import pytest

from data_pipeline.hybrid_retrieval import (
    HybridRetriever,
    _rrf_fuse,
    _tokenize,
)


def _d(id_, doc="", src="seed_corpus"):
    return {"id": id_, "document": doc or f"document {id_}",
            "distance": 0.1, "metadata": {"source": src}}


class TestTokenize:
    def test_lowercases_and_splits(self):
        assert _tokenize("PayPal Login-Now") == ["paypal", "login", "now"]

    def test_keeps_cyrillic_tokens(self):
        toks = _tokenize("usbbog.edу.co")  # у = Cyrillic
        assert "usbbog" in toks and "co" in toks

    def test_none_safe(self):
        assert _tokenize(None) == []


class TestRRFFuse:
    def test_dense_only_input(self):
        out = _rrf_fuse([_d("a"), _d("b"), _d("c")], [], n=2, k=60)
        assert [x["id"] for x in out] == ["a", "b"]
        assert out[0]["distance"] == 0.0 and out[1]["distance"] == 0.5

    def test_overlap_gets_boosted(self):
        dense = [_d("a"), _d("b"), _d("c")]
        sparse = [_d("c"), _d("d")]           # c aparece en ambos → sube
        out = _rrf_fuse(dense, sparse, n=3, k=1)
        assert out[0]["id"] == "c"

    def test_sparse_only_doc_can_enter(self):
        dense = [_d("a")]
        sparse = [_d("z", "lexical-only match")]
        out = _rrf_fuse(dense, sparse, n=2, k=60)
        assert set(x["id"] for x in out) == {"a", "z"}

    def test_synthetic_distance_increases_with_rank(self):
        out = _rrf_fuse([_d("a"), _d("b"), _d("c"), _d("d")], [], n=4, k=60)
        ds = [x["distance"] for x in out]
        assert ds == sorted(ds)


@pytest.fixture
def retriever() -> HybridRetriever:
    return HybridRetriever()


class TestSearch:
    async def test_hybrid_disabled_returns_dense(self, retriever):
        dense = [_d("a"), _d("b"), _d("c"), _d("d")]
        with patch("data_pipeline.hybrid_retrieval.settings.RAG_HYBRID_ENABLED", False), \
             patch("models.chromadb_client.query_collection",
                   new_callable=AsyncMock, return_value=dense):
            out = await retriever.search("idn_patterns", "q", 2)
        assert [x["id"] for x in out] == ["a", "b"]

    async def test_bm25_unavailable_falls_back_to_dense(self, retriever):
        dense = [_d("a"), _d("b"), _d("c")]
        with patch("data_pipeline.hybrid_retrieval.settings.RAG_HYBRID_ENABLED", True), \
             patch("models.chromadb_client.query_collection",
                   new_callable=AsyncMock, return_value=dense), \
             patch("models.chromadb_client.get_all_documents",
                   new_callable=AsyncMock, side_effect=RuntimeError("no chroma")):
            out = await retriever.search("idn_patterns", "q", 2)
        assert [x["id"] for x in out] == ["a", "b"]

    async def test_empty_corpus_falls_back_to_dense(self, retriever):
        dense = [_d("a"), _d("b")]
        with patch("data_pipeline.hybrid_retrieval.settings.RAG_HYBRID_ENABLED", True), \
             patch("models.chromadb_client.query_collection",
                   new_callable=AsyncMock, return_value=dense), \
             patch("models.chromadb_client.get_all_documents",
                   new_callable=AsyncMock, return_value=[]):
            out = await retriever.search("idn_patterns", "q", 2)
        assert [x["id"] for x in out] == ["a", "b"]

    async def test_lexical_hit_missed_by_dense_is_recovered(self, retriever):
        # denso NO devuelve el doc del homógrafo; BM25 sí (match léxico exacto).
        dense = [_d("far1", "unrelated"), _d("far2", "unrelated too")]
        corpus = [
            {"id": "hit", "document": "IDN homograph xn--pypal-4ve paypal cyrillic",
             "metadata": {"source": "seed_corpus"}},
            {"id": "n1", "document": "casino welcome bonus spanish", "metadata": {}},
            {"id": "n2", "document": "legitimate university portal", "metadata": {}},
        ]
        with patch("data_pipeline.hybrid_retrieval.settings.RAG_HYBRID_ENABLED", True), \
             patch("models.chromadb_client.query_collection",
                   new_callable=AsyncMock, return_value=dense), \
             patch("models.chromadb_client.get_all_documents",
                   new_callable=AsyncMock, return_value=corpus):
            out = await retriever.search("idn_patterns", "xn--pypal-4ve paypal homograph", 3)
        assert "hit" in [x["id"] for x in out]

    async def test_index_is_cached_then_invalidated(self, retriever):
        corpus = [{"id": "c1", "document": "paypal phishing", "metadata": {}}]
        with patch("data_pipeline.hybrid_retrieval.settings.RAG_HYBRID_ENABLED", True), \
             patch("models.chromadb_client.query_collection",
                   new_callable=AsyncMock, return_value=[_d("a")]), \
             patch("models.chromadb_client.get_all_documents",
                   new_callable=AsyncMock, return_value=corpus) as gad:
            await retriever.search("idn_patterns", "paypal", 2)
            await retriever.search("idn_patterns", "paypal", 2)
            gad.assert_awaited_once()          # cacheado
            retriever.invalidate("idn_patterns")
            await retriever.search("idn_patterns", "paypal", 2)
            assert gad.await_count == 2        # rebuild tras invalidate
