"""RAG Retrieval module — Phase 3 (Sprint S2).

Provides the RAGRetriever class for semantic similarity search against ChromaDB.
Used by LLMAgent to inject contextually relevant phishing patterns into the prompt.

Pipeline position: IDN Agent → [LLM Agent uses RAGRetriever] → Fusion Agent

────────────────────────────────────────────────────────────────────────────────
DESIGN DECISIONS — DO NOT CHANGE without updating backendTesis/CLAUDE.md
────────────────────────────────────────────────────────────────────────────────
1. Embedding model: "all-MiniLM-L6-v2" (384-dimensional, sentence-transformers).
   - DO NOT swap for another model without re-indexing ALL ChromaDB collections.
   - The same model must be used at indexing time (pipeline scripts) and query time.

2. Default collection: COLLECTION_EMAIL_EMBEDDINGS = "email_embeddings".
   - Other valid collections: COLLECTION_IDN_PATTERNS, COLLECTION_TI_SIGNALS.

3. Encoder singleton: _ENCODER is a module-level variable, lazy-initialized on first
   call to _get_encoder(). This avoids loading ~90MB model on import.

4. Return type: list[str] — only the document strings (not metadata/distances).
   LLMAgent._retrieve_rag() expects list[str]; this contract MUST stay.

5. Graceful degradation: any exception → returns []. NEVER raises from retrieve().
   This ensures the LLM pipeline never fails due to a ChromaDB connectivity issue.

6. ChromaDB API used: collection.query(query_embeddings=[...], n_results=top_k)
   - query_embeddings receives a pre-computed float list (output of encoder.encode)
   - DO NOT use query_texts — that bypasses the SentenceTransformer encoder.
────────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

from sentence_transformers import SentenceTransformer

from core.constants import COLLECTION_EMAIL_EMBEDDINGS, RAG_TOP_K
from core.logger import get_logger

# ── Module-level encoder singleton ────────────────────────────────────────────
# SentenceTransformer is ~90MB — load once, reuse across requests.
# Thread-safety: Python's GIL prevents concurrent first-init races in practice.
# DO NOT change _MODEL_NAME without re-ingesting all ChromaDB collections.
_MODEL_NAME: str = "all-MiniLM-L6-v2"
_ENCODER: SentenceTransformer | None = None


def _get_encoder() -> SentenceTransformer:
    """Return the module-level SentenceTransformer singleton.

    Lazy-initialized on first call. Subsequent calls return the cached instance.
    Exposed at module level (not as a classmethod) to allow easy patching in tests:
        with patch("agents.rag_retriever._get_encoder", return_value=mock_encoder):
            ...
    """
    global _ENCODER  # noqa: PLW0603
    if _ENCODER is None:
        _ENCODER = SentenceTransformer(_MODEL_NAME)
    return _ENCODER


class RAGRetriever:
    """Retrieves semantically similar phishing email chunks from a ChromaDB collection.

    Encodes the query with all-MiniLM-L6-v2, queries ChromaDB via cosine similarity,
    and returns the top-k document strings for prompt injection.

    Stateless: safe to instantiate per-request (no mutable state after __init__).

    Usage:
        chroma = get_chromadb_client()
        retriever = RAGRetriever(chromadb_client=chroma)
        docs: list[str] = retriever.retrieve("paypal.com please verify account", top_k=3)
        # docs → ["phishing email 1 ...", "phishing email 2 ...", "phishing email 3 ..."]

    If chromadb_client is None or any error occurs, returns [].
    """

    def __init__(
        self,
        chromadb_client,  # chromadb.ClientAPI — typed as Any to avoid circular import
        collection_name: str = COLLECTION_EMAIL_EMBEDDINGS,
    ) -> None:
        """
        Args:
            chromadb_client: A chromadb.ClientAPI (or HttpClient) instance.
                             Pass None for offline/test scenarios → retrieve() returns [].
            collection_name: ChromaDB collection to query.
                             Default: COLLECTION_EMAIL_EMBEDDINGS ("email_embeddings").
                             Valid values: "email_embeddings", "idn_patterns", "ti_signals".
        """
        self._chroma = chromadb_client
        self._collection_name = collection_name
        self.logger = get_logger("rag_retriever")

    def retrieve(self, query: str, top_k: int = RAG_TOP_K) -> list[str]:
        """Encode query and retrieve top-k document strings from ChromaDB.

        Flow:
            1. Encode query string → 384-d float vector (all-MiniLM-L6-v2)
            2. Call collection.query(query_embeddings=[...], n_results=top_k)
            3. Extract documents from ChromaDB response structure
            4. Return list[str] or [] on any error

        Args:
            query: Free-text query — typically "{domain} {email_body_snippet}".
                   The encoder handles tokenization internally.
            top_k: Number of most similar documents to return.
                   Default: RAG_TOP_K (3). Must be ≥ 1.

        Returns:
            list[str]: Top-k document strings in descending similarity order.
                       [] if chromadb_client is None, collection is empty, or any error.

        Note:
            - This method is SYNCHRONOUS. LLMAgent calls it with await via asyncio.
              To use in async context, wrap with asyncio.to_thread() or call directly
              (ChromaDB HttpClient is sync; use threadpool in production if needed).
            - Never raises — catches all exceptions for graceful degradation.
        """
        if self._chroma is None:
            return []

        try:
            encoder = _get_encoder()
            # encode() → numpy.ndarray shape (384,); .tolist() → list[float] for ChromaDB
            embedding: list[float] = encoder.encode(query).tolist()

            # ChromaDB API: get the collection, then query with pre-computed embedding.
            # DO NOT pass query_texts — that would ignore the SentenceTransformer encoder.
            collection = self._chroma.get_collection(self._collection_name)
            results = collection.query(
                query_embeddings=[embedding],  # single query → list of one embedding
                n_results=top_k,
                include=["documents"],  # only documents needed; skip metadata/distances
            )

            # ChromaDB returns {"documents": [[doc1, doc2, ...]]} for a single query.
            # The outer list indexes queries; the inner list indexes results for that query.
            documents: list[str] = results.get("documents", [[]])[0]
            return documents

        except Exception as exc:
            self.logger.warning(
                f"RAG retrieval failed for query={query!r} "
                f"collection={self._collection_name!r}: {exc}"
            )
            return []
