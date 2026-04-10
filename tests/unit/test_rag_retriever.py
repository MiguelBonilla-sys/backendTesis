"""Tests for agents/rag_retriever.py — Phase 3 (Sprint S2).

Unit tests for RAGRetriever with all ChromaDB and SentenceTransformer calls mocked.
No real ChromaDB instance or network calls are made.

Coverage targets:
  - None client → []
  - Successful retrieval flow (encoder → embeddings → ChromaDB → documents)
  - Correct ChromaDB API usage (get_collection + query with query_embeddings)
  - Correct collection name and n_results forwarding
  - Encoder called with the right query string
  - ChromaDB error → []
  - Encoder error → []
  - Empty ChromaDB result → []
"""

from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from agents.rag_retriever import RAGRetriever, _get_encoder
from core.constants import COLLECTION_EMAIL_EMBEDDINGS, RAG_TOP_K


# ── Helpers / shared fixtures ─────────────────────────────────────────────────

def _make_mock_encoder(embedding_dim: int = 384) -> MagicMock:
    """Return a mock SentenceTransformer encoder returning a zero vector."""
    encoder = MagicMock()
    # encode() returns numpy array; .tolist() must produce a plain list[float]
    encoder.encode.return_value = np.zeros(embedding_dim, dtype=float)
    return encoder


def _make_mock_chroma(documents: list[str]) -> MagicMock:
    """Return a mock ChromaDB client that returns the given documents from query()."""
    collection = MagicMock()
    collection.query.return_value = {"documents": [documents]}

    client = MagicMock()
    client.get_collection.return_value = collection
    return client


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_encoder() -> MagicMock:
    return _make_mock_encoder()


@pytest.fixture
def chroma_with_three_docs() -> MagicMock:
    return _make_mock_chroma([
        "phishing snippet 1 — account suspended",
        "phishing snippet 2 — urgent verify",
        "phishing snippet 3 — click here",
    ])


@pytest.fixture
def chroma_empty() -> MagicMock:
    return _make_mock_chroma([])


# ── None client ───────────────────────────────────────────────────────────────

def test_retrieve_no_client_returns_empty_list() -> None:
    """If chromadb_client is None, retrieve() must return [] immediately."""
    retriever = RAGRetriever(chromadb_client=None)
    result = retriever.retrieve("paypal.com phishing verify account", top_k=3)
    assert result == []


def test_retrieve_no_client_never_calls_encoder() -> None:
    """If chromadb_client is None, the SentenceTransformer encoder is never called."""
    retriever = RAGRetriever(chromadb_client=None)
    mock_enc = _make_mock_encoder()
    with patch("agents.rag_retriever._get_encoder", return_value=mock_enc):
        retriever.retrieve("query")
    mock_enc.encode.assert_not_called()


# ── Successful retrieval flow ─────────────────────────────────────────────────

def test_retrieve_returns_correct_documents(
    chroma_with_three_docs: MagicMock,
    mock_encoder: MagicMock,
) -> None:
    """retrieve() returns the document strings from ChromaDB."""
    with patch("agents.rag_retriever._get_encoder", return_value=mock_encoder):
        retriever = RAGRetriever(chromadb_client=chroma_with_three_docs)
        result = retriever.retrieve("paypal.com", top_k=3)
    assert result == [
        "phishing snippet 1 — account suspended",
        "phishing snippet 2 — urgent verify",
        "phishing snippet 3 — click here",
    ]


def test_retrieve_returns_list_of_strings(
    chroma_with_three_docs: MagicMock,
    mock_encoder: MagicMock,
) -> None:
    """Return type must be list[str]."""
    with patch("agents.rag_retriever._get_encoder", return_value=mock_encoder):
        retriever = RAGRetriever(chromadb_client=chroma_with_three_docs)
        result = retriever.retrieve("query")
    assert isinstance(result, list)
    assert all(isinstance(doc, str) for doc in result)


# ── ChromaDB API contract ─────────────────────────────────────────────────────

def test_retrieve_calls_get_collection_with_collection_name(
    chroma_with_three_docs: MagicMock,
    mock_encoder: MagicMock,
) -> None:
    """retrieve() must call client.get_collection() with the configured collection name."""
    with patch("agents.rag_retriever._get_encoder", return_value=mock_encoder):
        retriever = RAGRetriever(
            chromadb_client=chroma_with_three_docs,
            collection_name=COLLECTION_EMAIL_EMBEDDINGS,
        )
        retriever.retrieve("query")
    chroma_with_three_docs.get_collection.assert_called_once_with(COLLECTION_EMAIL_EMBEDDINGS)


def test_retrieve_calls_collection_query_with_query_embeddings(
    chroma_with_three_docs: MagicMock,
    mock_encoder: MagicMock,
) -> None:
    """retrieve() MUST use query_embeddings (not query_texts) on the collection."""
    with patch("agents.rag_retriever._get_encoder", return_value=mock_encoder):
        retriever = RAGRetriever(chromadb_client=chroma_with_three_docs)
        retriever.retrieve("paypal.com urgent", top_k=3)

    collection = chroma_with_three_docs.get_collection.return_value
    call_kwargs = collection.query.call_args.kwargs
    assert "query_embeddings" in call_kwargs, (
        "Must use query_embeddings, not query_texts — "
        "bypassing SentenceTransformer would break the embedding-based retrieval."
    )
    assert "query_texts" not in call_kwargs


def test_retrieve_passes_embedding_list_to_chromadb(
    chroma_with_three_docs: MagicMock,
    mock_encoder: MagicMock,
) -> None:
    """The embedding passed to ChromaDB must be a list of floats (not numpy array)."""
    with patch("agents.rag_retriever._get_encoder", return_value=mock_encoder):
        retriever = RAGRetriever(chromadb_client=chroma_with_three_docs)
        retriever.retrieve("query")

    collection = chroma_with_three_docs.get_collection.return_value
    embeddings_arg = collection.query.call_args.kwargs["query_embeddings"]
    assert isinstance(embeddings_arg, list), "query_embeddings must be a list"
    assert len(embeddings_arg) == 1, "Single query → list of one embedding"
    assert isinstance(embeddings_arg[0], list), "Each embedding must be list[float]"


def test_retrieve_forwards_top_k_as_n_results(
    chroma_with_three_docs: MagicMock,
    mock_encoder: MagicMock,
) -> None:
    """top_k parameter must be forwarded as n_results to collection.query()."""
    with patch("agents.rag_retriever._get_encoder", return_value=mock_encoder):
        retriever = RAGRetriever(chromadb_client=chroma_with_three_docs)
        retriever.retrieve("query", top_k=5)

    collection = chroma_with_three_docs.get_collection.return_value
    assert collection.query.call_args.kwargs["n_results"] == 5


def test_retrieve_uses_rag_top_k_as_default(
    chroma_with_three_docs: MagicMock,
    mock_encoder: MagicMock,
) -> None:
    """Default top_k must equal RAG_TOP_K constant (currently 3)."""
    with patch("agents.rag_retriever._get_encoder", return_value=mock_encoder):
        retriever = RAGRetriever(chromadb_client=chroma_with_three_docs)
        retriever.retrieve("query")

    collection = chroma_with_three_docs.get_collection.return_value
    assert collection.query.call_args.kwargs["n_results"] == RAG_TOP_K


# ── Custom collection name ────────────────────────────────────────────────────

def test_retrieve_custom_collection_name(
    mock_encoder: MagicMock,
) -> None:
    """RAGRetriever accepts a custom collection_name and passes it to get_collection."""
    chroma = _make_mock_chroma(["idn pattern result"])
    with patch("agents.rag_retriever._get_encoder", return_value=mock_encoder):
        retriever = RAGRetriever(
            chromadb_client=chroma,
            collection_name="idn_patterns",
        )
        retriever.retrieve("query")
    chroma.get_collection.assert_called_once_with("idn_patterns")


def test_retrieve_default_collection_is_email_embeddings(
    chroma_with_three_docs: MagicMock,
    mock_encoder: MagicMock,
) -> None:
    """Default collection_name must be COLLECTION_EMAIL_EMBEDDINGS."""
    with patch("agents.rag_retriever._get_encoder", return_value=mock_encoder):
        retriever = RAGRetriever(chromadb_client=chroma_with_three_docs)
        retriever.retrieve("query")
    chroma_with_three_docs.get_collection.assert_called_once_with(COLLECTION_EMAIL_EMBEDDINGS)


# ── Encoder interaction ───────────────────────────────────────────────────────

def test_retrieve_calls_encoder_with_query_string(
    chroma_with_three_docs: MagicMock,
    mock_encoder: MagicMock,
) -> None:
    """encoder.encode() must receive the exact query string."""
    query = "paypal.com urgent account suspended verify now"
    with patch("agents.rag_retriever._get_encoder", return_value=mock_encoder):
        retriever = RAGRetriever(chromadb_client=chroma_with_three_docs)
        retriever.retrieve(query)
    mock_encoder.encode.assert_called_once_with(query)


# ── Empty ChromaDB result ─────────────────────────────────────────────────────

def test_retrieve_empty_collection_returns_empty_list(
    chroma_empty: MagicMock,
    mock_encoder: MagicMock,
) -> None:
    """When ChromaDB returns no documents, retrieve() returns []."""
    with patch("agents.rag_retriever._get_encoder", return_value=mock_encoder):
        retriever = RAGRetriever(chromadb_client=chroma_empty)
        result = retriever.retrieve("query")
    assert result == []


def test_retrieve_missing_documents_key_returns_empty_list(
    mock_encoder: MagicMock,
) -> None:
    """When ChromaDB result is missing 'documents' key, retrieve() returns []."""
    collection = MagicMock()
    collection.query.return_value = {}  # no "documents" key
    chroma = MagicMock()
    chroma.get_collection.return_value = collection

    with patch("agents.rag_retriever._get_encoder", return_value=mock_encoder):
        retriever = RAGRetriever(chromadb_client=chroma)
        result = retriever.retrieve("query")
    assert result == []


# ── Error handling / graceful degradation ────────────────────────────────────

def test_retrieve_chromadb_get_collection_error_returns_empty(
    mock_encoder: MagicMock,
) -> None:
    """If ChromaDB.get_collection() raises, retrieve() returns [] without re-raising."""
    chroma = MagicMock()
    chroma.get_collection.side_effect = RuntimeError("ChromaDB connection refused")

    with patch("agents.rag_retriever._get_encoder", return_value=mock_encoder):
        retriever = RAGRetriever(chromadb_client=chroma)
        result = retriever.retrieve("query")
    assert result == []


def test_retrieve_chromadb_query_error_returns_empty(
    mock_encoder: MagicMock,
) -> None:
    """If collection.query() raises, retrieve() returns [] without re-raising."""
    collection = MagicMock()
    collection.query.side_effect = RuntimeError("HNSW index not initialized")
    chroma = MagicMock()
    chroma.get_collection.return_value = collection

    with patch("agents.rag_retriever._get_encoder", return_value=mock_encoder):
        retriever = RAGRetriever(chromadb_client=chroma)
        result = retriever.retrieve("evil.com")
    assert result == []


def test_retrieve_encoder_error_returns_empty() -> None:
    """If encoder.encode() raises (e.g. OOM), retrieve() returns [] without re-raising."""
    failing_encoder = MagicMock()
    failing_encoder.encode.side_effect = RuntimeError("CUDA out of memory")
    chroma = MagicMock()

    with patch("agents.rag_retriever._get_encoder", return_value=failing_encoder):
        retriever = RAGRetriever(chromadb_client=chroma)
        result = retriever.retrieve("evil.com")
    assert result == []


def test_retrieve_never_raises_on_any_error() -> None:
    """retrieve() is guaranteed to never raise — always returns list."""
    chroma = MagicMock()
    chroma.get_collection.side_effect = Exception("Unexpected catastrophic failure")

    retriever = RAGRetriever(chromadb_client=chroma)
    # Should not raise:
    result = retriever.retrieve("query")
    assert isinstance(result, list)
