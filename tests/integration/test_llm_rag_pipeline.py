"""Integration tests — LLM Agent + RAG pipeline (Phase 3, Sprint S2).

Scope: End-to-end tests using:
  - chromadb.EphemeralClient() — in-memory ChromaDB, no Docker required.
  - Mocked SentenceTransformer encoder — avoids loading the ~90MB model in CI.
  - Mocked LlamaStack HTTP responses — avoids LlamaStack service dependency.

These tests verify PIPELINE WIRING: that RAGRetriever, build_prompt, and LLMAgent
compose correctly end-to-end, not just in unit isolation.  They complement the unit
tests in tests/unit/test_rag_retriever.py and tests/unit/test_prompt_builder.py.

Test map:
  RAGRetriever + real ChromaDB:
    - test_rag_retriever_returns_docs_from_real_chromadb
    - test_rag_retriever_empty_collection_returns_empty_list

  LLMAgent full pipeline:
    - test_llm_agent_full_pipeline_returns_valid_result
    - test_llm_agent_rag_context_present_in_result
    - test_llm_agent_no_chroma_succeeds_with_empty_rag
    - test_llm_agent_timeout_fallback_during_pipeline

  Full 3-agent pipeline (IDNAgent → LLMAgent → FusionAgent):
    - test_full_pipeline_phishing_domain
    - test_full_pipeline_safe_domain
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
from core.constants import COLLECTION_EMAIL_EMBEDDINGS, RAG_TOP_K

# ── Constants ─────────────────────────────────────────────────────────────────

_EMBED_DIM = 384
# Fixed embedding used for both stored documents and mock encoder queries.
# All docs share the same vector so cosine similarity = 1.0 for all → chromadb
# returns them in insertion order, which is deterministic for tests.
_FIXED_EMBEDDING: list[float] = [0.1] * _EMBED_DIM

_FIXTURE_CATALOG_PATH = Path("tests/fixtures/confusables_minimal.txt")

PHISHING_DOCS = [
    "paypal account suspended urgently verify your identity at http://fake-paypal.com",
    "apple id locked click here to restore access immediately",
    "amazon prize claim your reward urgent action required",
]


# ── Shared helpers ────────────────────────────────────────────────────────────

def _make_mock_encoder() -> MagicMock:
    """Encoder returning a fixed 384-d zero vector — avoids loading the real model."""
    enc = MagicMock()
    enc.encode.return_value = np.array(_FIXED_EMBEDDING, dtype=float)
    return enc


def _make_chroma_with_docs(
    documents: list[str] = PHISHING_DOCS,
    collection_name: str = COLLECTION_EMAIL_EMBEDDINGS,
) -> chromadb.EphemeralClient:
    """In-memory ChromaDB pre-populated with documents + fixed embeddings."""
    client = chromadb.EphemeralClient()
    collection = client.get_or_create_collection(
        name=collection_name,
        metadata={"hnsw:space": "cosine"},
    )
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
    """Mock async context manager that simulates a LlamaStack HTTP success."""
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


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def chroma_with_docs() -> chromadb.EphemeralClient:
    return _make_chroma_with_docs()


@pytest.fixture
def mock_encoder() -> MagicMock:
    return _make_mock_encoder()


# ── RAGRetriever + real in-memory ChromaDB ────────────────────────────────────

def test_rag_retriever_returns_docs_from_real_chromadb(
    chroma_with_docs: chromadb.EphemeralClient,
    mock_encoder: MagicMock,
) -> None:
    """RAGRetriever retrieves documents from a real in-memory ChromaDB collection.

    This test exercises the real ChromaDB API:
      client.get_collection(name) → collection.query(query_embeddings=[...], n_results=k)
    It verifies that the ChromaDB contract used in rag_retriever.py is correct.
    """
    with patch("agents.rag_retriever._get_encoder", return_value=mock_encoder):
        retriever = RAGRetriever(chromadb_client=chroma_with_docs)
        results = retriever.retrieve("paypal account verify", top_k=RAG_TOP_K)

    assert len(results) == RAG_TOP_K
    assert all(isinstance(doc, str) for doc in results)
    # Every returned doc must be one of the stored phishing documents
    for doc in results:
        assert doc in PHISHING_DOCS, f"Unexpected doc returned: {doc!r}"


def test_rag_retriever_empty_collection_returns_empty_list(
    mock_encoder: MagicMock,
) -> None:
    """RAGRetriever handles an empty collection without raising.

    ChromaDB raises when querying with n_results > collection size.
    RAGRetriever.retrieve() must swallow this and return [].

    Uses a dedicated collection name ("empty_test_collection") to avoid
    state collision with the shared EphemeralClient singleton used by other
    fixtures in the same test session.
    """
    _EMPTY_COLLECTION = "empty_test_collection"

    client = chromadb.EphemeralClient()
    client.get_or_create_collection(
        name=_EMPTY_COLLECTION,
        metadata={"hnsw:space": "cosine"},
    )
    # Collection is empty — no documents added

    with patch("agents.rag_retriever._get_encoder", return_value=mock_encoder):
        retriever = RAGRetriever(
            chromadb_client=client,
            collection_name=_EMPTY_COLLECTION,
        )
        result = retriever.retrieve("test query", top_k=RAG_TOP_K)

    assert result == []  # graceful degradation — ChromaDB error caught


# ── LLMAgent full pipeline ─────────────────────────────────────────────────────

async def test_llm_agent_full_pipeline_returns_valid_result(
    chroma_with_docs: chromadb.EphemeralClient,
    mock_encoder: MagicMock,
) -> None:
    """LLMAgent retrieves RAG from real ChromaDB, builds prompt, parses score.

    Key pipeline wiring verified here:
      _retrieve_rag() → RAGRetriever.retrieve() [real ChromaDB]
      _build_prompt() → prompt_builder.build_prompt() [tiktoken budget]
      _parse_score()  → regex extraction from LlamaStack mock response
    """
    mock_cm = _make_llamastack_mock(score=0.9, reason="Cyrillic homograph of paypal.com")

    with patch("agents.rag_retriever._get_encoder", return_value=mock_encoder), \
         patch("agents.llm_agent.httpx.AsyncClient", return_value=mock_cm):

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
    """RAG documents retrieved from real ChromaDB appear in the result's rag_context."""
    mock_cm = _make_llamastack_mock(score=0.7)

    with patch("agents.rag_retriever._get_encoder", return_value=mock_encoder), \
         patch("agents.llm_agent.httpx.AsyncClient", return_value=mock_cm):

        agent = LLMAgent(chromadb_client=chroma_with_docs)
        result = await agent.analyze("evil.com", "click here", 0.5)

    rag = result["rag_context"]
    assert isinstance(rag, list)
    assert len(rag) == RAG_TOP_K
    # Every returned snippet must be from the stored phishing docs
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
    """LlamaStack timeout triggers fallback even when RAG retrieval succeeds."""

    async def slow_llamastack(*_args, **_kwargs) -> None:
        await asyncio.sleep(100)

    with patch("agents.rag_retriever._get_encoder", return_value=mock_encoder), \
         patch.object(LLMAgent, "_call_llamastack", slow_llamastack), \
         patch("agents.llm_agent.LLAMASTACK_TIMEOUT_SECONDS", 0.001):

        agent = LLMAgent(chromadb_client=chroma_with_docs)
        result = await agent.analyze("evil.com", None, 0.7)

    assert result["s_llm"] == 0.5
    assert result["reasoning"] == "timeout"
    # Timeout clears rag_context in the fallback path
    assert result["rag_context"] == []


# ── Full 3-agent pipeline (IDNAgent → LLMAgent → FusionAgent) ─────────────────

async def test_full_pipeline_phishing_domain(
    chroma_with_docs: chromadb.EphemeralClient,
    mock_encoder: MagicMock,
) -> None:
    """IDNAgent → LLMAgent → FusionAgent with Cyrillic homograph domain.

    Verifies that the three stateless agents execute in sequence and produce
    a coherent FusionAgent result.  This is the core research pipeline.
    """
    catalog = {}
    if _FIXTURE_CATALOG_PATH.exists():
        from agents.confusables_loader import load_confusables
        catalog = load_confusables(_FIXTURE_CATALOG_PATH)

    # Stage 1 — IDN Agent
    idn_agent = IDNAgent(
        top1m_index=["paypal", "apple", "amazon", "google"],
        catalog=catalog,
    )
    idn_result = await idn_agent.analyze("pаypal.com")  # Cyrillic а (U+0430)
    s_idn_local: float = idn_result["s_idn_local"]

    # Stage 2 — LLM Agent
    mock_cm = _make_llamastack_mock(score=0.88, reason="homograph of paypal.com")

    with patch("agents.rag_retriever._get_encoder", return_value=mock_encoder), \
         patch("agents.llm_agent.httpx.AsyncClient", return_value=mock_cm):

        llm_agent = LLMAgent(chromadb_client=chroma_with_docs)
        llm_result = await llm_agent.analyze("pаypal.com", None, s_idn_local)

    s_llm: float = llm_result["s_llm"]

    # Stage 3 — Fusion Agent
    fusion_agent = FusionAgent()
    ti_scores = {"virustotal": 0.0, "urlscan": 0.0, "google_safe_browsing": 0.0}
    fusion_result = await fusion_agent.analyze(s_idn_local, s_llm, ti_scores)

    # ── Assertions ────────────────────────────────────────────────────────────
    # IDN Agent must detect the Cyrillic homograph
    assert idn_result["is_mixed_script"] is True, "Cyrillic+Latin must be mixed_script=True"
    assert s_idn_local > 0.0

    # LLM result must include RAG context retrieved from real ChromaDB
    assert len(llm_result["rag_context"]) == RAG_TOP_K

    # Fusion result must have all required keys
    assert {"s_risk", "verdict", "shap_explanation", "s_idn", "s_llm", "s_ti"} \
        <= fusion_result.keys()
    assert 0.0 <= fusion_result["s_risk"] <= 1.0

    # With high IDN + high LLM scores, S_risk should be significant
    assert fusion_result["s_risk"] > 0.3, (
        f"Expected s_risk > 0.3 for known homograph, got {fusion_result['s_risk']}"
    )


async def test_full_pipeline_safe_domain() -> None:
    """Full pipeline on a safe domain produces low S_risk."""
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
