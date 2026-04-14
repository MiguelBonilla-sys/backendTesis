"""Integration tests for the LLM + RAG pipeline (Phase 3 — Sprint S2).

Scope: End-to-end tests using:
  - chromadb.EphemeralClient() — in-memory ChromaDB, no Docker required.
  - Mocked SentenceTransformer encoder — avoids loading the ~90MB model in CI.
  - Mocked LlamaStack HTTP responses — avoids LlamaStack service dependency.

These tests verify PIPELINE WIRING: that RAGRetriever, build_prompt, and LLMAgent
compose correctly end-to-end, not just in unit isolation.  They complement the unit
tests in tests/unit/test_rag_retriever.py and tests/unit/test_prompt_builder.py.

Test map:
  RAGRetriever + real in-memory ChromaDB:
    - test_rag_retriever_returns_docs_from_real_chromadb
    - test_rag_retriever_empty_collection_returns_empty_list
    - test_rag_retriever_uses_query_embeddings_not_query_texts

  LLMAgent full pipeline:
    - test_llm_agent_full_pipeline_returns_valid_result
    - test_llm_agent_rag_context_present_in_result
    - test_llm_agent_no_chroma_succeeds_with_empty_rag
    - test_llm_agent_timeout_fallback_during_pipeline

  Full 3-agent pipeline (IDNAgent → LLMAgent → FusionAgent):
    - test_full_pipeline_phishing_domain
    - test_full_pipeline_safe_domain
    - test_full_pipeline_result_has_all_required_keys
    - test_pipeline_llm_timeout_fallback_propagates_to_fusion
"""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import chromadb
import numpy as np
import pytest

from agents.fusion_agent import FusionAgent
from agents.idn_agent import IDNAgent
from agents.llm_agent import LLMAgent
from agents.rag_retriever import RAGRetriever
from core.constants import (
    COLLECTION_EMAIL_EMBEDDINGS,
    GAMMA_LLM_FALLBACK,
    RAG_TOP_K,
)

# ── Constants ──────────────────────────────────────────────────────────────────

_EMBED_DIM = 384
# Fixed embedding for both stored documents and mock encoder queries.
# All docs share the same vector → cosine similarity = 1.0 for all → ChromaDB
# returns them in insertion order, which is deterministic for tests.
_FIXED_EMBEDDING: list[float] = [0.1] * _EMBED_DIM

_FIXTURE_CATALOG_PATH = Path("tests/fixtures/confusables_minimal.txt")

PHISHING_DOCS = [
    "paypal account suspended urgently verify your identity at http://fake-paypal.com",
    "apple id locked click here to restore access immediately",
    "amazon prize claim your reward urgent action required",
]


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _make_mock_encoder() -> MagicMock:
    """Encoder returning a fixed 384-d vector — avoids loading the real model."""
    enc = MagicMock()
    enc.encode.return_value = np.array(_FIXED_EMBEDDING, dtype=float)
    return enc


def _make_chroma_with_docs(
    documents: list[str] = PHISHING_DOCS,
    collection_name: str = COLLECTION_EMAIL_EMBEDDINGS,
) -> chromadb.EphemeralClient:
    """In-memory ChromaDB pre-populated with documents and fixed embeddings."""
    client = chromadb.EphemeralClient()
    collection = client.get_or_create_collection(
        name=collection_name,
        metadata={"hnsw:space": "cosine"},
    )
    if documents:
        collection.add(
            documents=documents,
            embeddings=[_FIXED_EMBEDDING] * len(documents),
            ids=[f"doc_{i}" for i in range(len(documents))],
        )
    return client


def _make_llamastack_mock(
    score: float = 0.85,
    reason: str = "phishing pattern detected",
) -> MagicMock:
    """Mock async context manager simulating a successful LlamaStack HTTP response."""
    api_response = {
        "choices": [
            {"message": {"content": f"SCORE: {score} | REASON: {reason}"}}
        ],
        "usage": {"total_tokens": 120},
    }
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = api_response

    mock_http = AsyncMock()
    mock_http.post.return_value = mock_resp

    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_http)
    mock_cm.__aexit__ = AsyncMock(return_value=False)
    return mock_cm


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def chroma_with_docs() -> chromadb.EphemeralClient:
    return _make_chroma_with_docs()


@pytest.fixture
def mock_encoder() -> MagicMock:
    return _make_mock_encoder()


# ── RAGRetriever + real in-memory ChromaDB ─────────────────────────────────────

def test_rag_retriever_returns_docs_from_real_chromadb(
    chroma_with_docs: chromadb.EphemeralClient,
    mock_encoder: MagicMock,
) -> None:
    """RAGRetriever retrieves documents from a real in-memory ChromaDB collection.

    Verifies the ChromaDB API contract used in rag_retriever.py:
      client.get_collection(name) → collection.query(query_embeddings=[...], n_results=k)
    """
    with patch("agents.rag_retriever._get_encoder", return_value=mock_encoder):
        retriever = RAGRetriever(chromadb_client=chroma_with_docs)
        results = retriever.retrieve("paypal account verify", top_k=RAG_TOP_K)

    assert len(results) == RAG_TOP_K
    assert all(isinstance(doc, str) for doc in results)
    for doc in results:
        assert doc in PHISHING_DOCS, f"Unexpected doc returned: {doc!r}"


def test_rag_retriever_empty_collection_returns_empty_list(
    mock_encoder: MagicMock,
) -> None:
    """RAGRetriever handles an empty collection without raising (graceful degradation).

    ChromaDB raises when querying with n_results > collection size.
    RAGRetriever.retrieve() must catch this and return [].
    """
    _EMPTY_COLLECTION = "empty_test_collection_v2"
    client = chromadb.EphemeralClient()
    client.get_or_create_collection(
        name=_EMPTY_COLLECTION,
        metadata={"hnsw:space": "cosine"},
    )
    # No documents added — empty collection

    with patch("agents.rag_retriever._get_encoder", return_value=mock_encoder):
        retriever = RAGRetriever(
            chromadb_client=client,
            collection_name=_EMPTY_COLLECTION,
        )
        result = retriever.retrieve("test query", top_k=RAG_TOP_K)

    assert result == []


def test_rag_retriever_uses_query_embeddings_not_query_texts(
    chroma_with_docs: chromadb.EphemeralClient,
    mock_encoder: MagicMock,
) -> None:
    """ChromaDB query must use query_embeddings (SentenceTransformer) not query_texts.

    This ensures the encoder is never bypassed — a design invariant from rag_retriever.py
    docstring design decisions §6.
    """
    collection = chroma_with_docs.get_collection(COLLECTION_EMAIL_EMBEDDINGS)
    original_query = collection.query
    call_kwargs: dict = {}

    def spy_query(**kwargs):
        call_kwargs.update(kwargs)
        return original_query(**kwargs)

    with (
        patch("agents.rag_retriever._get_encoder", return_value=mock_encoder),
        patch.object(collection, "query", side_effect=spy_query),
    ):
        retriever = RAGRetriever(chromadb_client=chroma_with_docs)
        retriever.retrieve("apple login", top_k=1)

    assert "query_embeddings" in call_kwargs
    assert "query_texts" not in call_kwargs


# ── LLMAgent full pipeline ─────────────────────────────────────────────────────

async def test_llm_agent_full_pipeline_returns_valid_result(
    chroma_with_docs: chromadb.EphemeralClient,
    mock_encoder: MagicMock,
) -> None:
    """LLMAgent: RAG retrieval from real ChromaDB → prompt build → score parse.

    Key pipeline wiring verified:
      _retrieve_rag()  → RAGRetriever.retrieve() [real ChromaDB]
      _build_prompt()  → prompt_builder.build_prompt() [tiktoken budget]
      _parse_score()   → regex extraction from LlamaStack mock response
    """
    mock_cm = _make_llamastack_mock(score=0.9, reason="Cyrillic homograph of paypal.com")

    with (
        patch("agents.rag_retriever._get_encoder", return_value=mock_encoder),
        patch("agents.llm_agent.httpx.AsyncClient", return_value=mock_cm),
    ):
        agent = LLMAgent(chromadb_client=chroma_with_docs)
        result = await agent.analyze(
            domain="pаypal.com",  # Cyrillic а (U+0430)
            email_body="Urgent: verify your account now",
            s_idn_local=0.85,
        )

    assert result["domain"] == "pаypal.com"
    assert result["s_llm"] == pytest.approx(0.9)
    assert result["reasoning"] != ""
    assert "rag_context" in result
    assert "tokens_used" in result


async def test_llm_agent_rag_context_present_in_result(
    chroma_with_docs: chromadb.EphemeralClient,
    mock_encoder: MagicMock,
) -> None:
    """RAG documents retrieved from real ChromaDB appear in result's rag_context."""
    mock_cm = _make_llamastack_mock(score=0.7)

    with (
        patch("agents.rag_retriever._get_encoder", return_value=mock_encoder),
        patch("agents.llm_agent.httpx.AsyncClient", return_value=mock_cm),
    ):
        agent = LLMAgent(chromadb_client=chroma_with_docs)
        result = await agent.analyze("evil.com", "click here", 0.5)

    rag = result["rag_context"]
    assert isinstance(rag, list)
    assert len(rag) == RAG_TOP_K
    for snippet in rag:
        assert snippet in PHISHING_DOCS


async def test_llm_agent_no_chroma_succeeds_with_empty_rag() -> None:
    """LLMAgent without ChromaDB produces a valid score; rag_context is []."""
    mock_cm = _make_llamastack_mock(score=0.6)

    with patch("agents.llm_agent.httpx.AsyncClient", return_value=mock_cm):
        agent = LLMAgent(chromadb_client=None)
        result = await agent.analyze("suspicious.com", "verify account", 0.3)

    assert result["s_llm"] == pytest.approx(0.6)
    assert result["rag_context"] == []


async def test_llm_agent_timeout_fallback_during_pipeline(
    chroma_with_docs: chromadb.EphemeralClient,
    mock_encoder: MagicMock,
) -> None:
    """LlamaStack timeout triggers fallback (s_llm=0.5) even when RAG succeeds."""

    async def slow_llamastack(*_args, **_kwargs) -> None:
        await asyncio.sleep(100)

    with (
        patch("agents.rag_retriever._get_encoder", return_value=mock_encoder),
        patch.object(LLMAgent, "_call_llamastack", slow_llamastack),
        patch("agents.llm_agent.LLAMASTACK_TIMEOUT_SECONDS", 0.001),
    ):
        agent = LLMAgent(chromadb_client=chroma_with_docs)
        result = await agent.analyze("evil.com", None, 0.7)

    assert result["s_llm"] == 0.5
    assert result["reasoning"] == "timeout"
    assert result["rag_context"] == []


# ── Full 3-agent pipeline (IDNAgent → LLMAgent → FusionAgent) ─────────────────

async def test_full_pipeline_phishing_domain(
    chroma_with_docs: chromadb.EphemeralClient,
    mock_encoder: MagicMock,
) -> None:
    """IDNAgent → LLMAgent → FusionAgent classifies a Cyrillic homograph domain.

    Verifies the three stateless agents execute in sequence and produce a coherent
    FusionAgent result.  This is the core research pipeline.
    """
    catalog = {}
    if _FIXTURE_CATALOG_PATH.exists():
        from agents.confusables_loader import load_confusables

        catalog = load_confusables(str(_FIXTURE_CATALOG_PATH))

    # Stage 1 — IDN Agent
    idn_agent = IDNAgent(
        top1m_index=["paypal", "apple", "amazon", "google"],
        catalog=catalog,
    )
    idn_result = await idn_agent.analyze("pаypal.com")  # Cyrillic а (U+0430)
    s_idn_local: float = idn_result["s_idn_local"]

    # Stage 2 — LLM Agent with real ChromaDB
    mock_cm = _make_llamastack_mock(score=0.88, reason="homograph of paypal.com")

    with (
        patch("agents.rag_retriever._get_encoder", return_value=mock_encoder),
        patch("agents.llm_agent.httpx.AsyncClient", return_value=mock_cm),
    ):
        llm_agent = LLMAgent(chromadb_client=chroma_with_docs)
        llm_result = await llm_agent.analyze("pаypal.com", None, s_idn_local)

    s_llm: float = llm_result["s_llm"]

    # Stage 3 — Fusion Agent
    fusion_agent = FusionAgent()
    ti_scores = {"virustotal": 0.0, "urlscan": 0.0, "google_safe_browsing": 0.0}
    fusion_result = await fusion_agent.analyze(s_idn_local, s_llm, ti_scores)

    # IDN Agent must detect the Cyrillic character as mixed-script
    assert idn_result["is_mixed_script"] is True
    assert s_idn_local > 0.0

    # LLM result must include RAG context retrieved from real ChromaDB
    assert len(llm_result["rag_context"]) == RAG_TOP_K

    # Fusion result must contain all required API-facing keys
    assert {"s_risk", "verdict", "shap_explanation", "s_idn", "s_llm", "s_ti"} <= fusion_result.keys()
    assert 0.0 <= fusion_result["s_risk"] <= 1.0
    assert fusion_result["s_risk"] > 0.3, (
        f"Expected s_risk > 0.3 for known homograph, got {fusion_result['s_risk']}"
    )


async def test_full_pipeline_safe_domain() -> None:
    """Full pipeline on a safe ASCII domain produces low S_risk."""
    idn_agent = IDNAgent(top1m_index=["google"], catalog={})
    idn_result = await idn_agent.analyze("google.com")
    s_idn_local: float = idn_result["s_idn_local"]

    mock_cm = _make_llamastack_mock(score=0.1, reason="legitimate domain")

    with patch("agents.llm_agent.httpx.AsyncClient", return_value=mock_cm):
        llm_agent = LLMAgent(chromadb_client=None)
        llm_result = await llm_agent.analyze("google.com", None, s_idn_local)

    fusion_agent = FusionAgent()
    fusion_result = await fusion_agent.analyze(
        s_idn_local,
        llm_result["s_llm"],
        {"virustotal": 0.0, "urlscan": 0.0, "google_safe_browsing": 0.0},
    )

    assert fusion_result["s_risk"] < 0.5, (
        f"Expected s_risk < 0.5 for google.com, got {fusion_result['s_risk']}"
    )
    assert fusion_result["verdict"] in ("SAFE", "SUSPICIOUS")


async def test_full_pipeline_result_has_all_required_keys() -> None:
    """Fusion result contains every key required for AnalyzeResponse serialization."""
    idn_agent = IDNAgent(top1m_index=[], catalog={})
    idn_result = await idn_agent.analyze("paypal.com")

    mock_cm = _make_llamastack_mock(score=0.6)
    with patch("agents.llm_agent.httpx.AsyncClient", return_value=mock_cm):
        llm_agent = LLMAgent(chromadb_client=None)
        llm_result = await llm_agent.analyze("paypal.com", "Login now.", idn_result["s_idn_local"])

    fusion_agent = FusionAgent()
    fusion_result = await fusion_agent.analyze(
        s_idn_local=idn_result["s_idn_local"],
        s_llm=llm_result["s_llm"],
        ti_scores={"virustotal": 0.5, "urlscan": 0.4, "google_safe_browsing": 0.0},
    )

    required_keys = {
        "verdict", "s_risk", "s_idn", "s_llm", "s_ti",
        "shap_explanation", "top_features", "effective_gamma",
    }
    assert required_keys.issubset(fusion_result.keys())

    shap_keys = {"idn_contribution", "llm_contribution", "ti_contribution", "baseline", "idn_local_score"}
    assert shap_keys.issubset(fusion_result["shap_explanation"].keys())


async def test_pipeline_llm_timeout_fallback_propagates_to_fusion() -> None:
    """When LLM times out (s_llm=0.5), FusionAgent uses GAMMA_LLM_FALLBACK weight."""
    fusion_agent = FusionAgent()
    result = await fusion_agent.analyze(
        s_idn_local=0.9,
        s_llm=0.5,  # neutral fallback value — LLM timed out
        ti_scores={"virustotal": 0.8, "urlscan": 0.7, "google_safe_browsing": 0.9},
        is_definitive_homograph=False,
        llm_is_fallback=True,
    )

    assert result["effective_gamma"] == GAMMA_LLM_FALLBACK
    assert result["verdict"] in ("PHISHING", "SUSPICIOUS", "SAFE")
    assert 0.0 <= result["s_risk"] <= 1.0
