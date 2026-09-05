"""
HybridRetriever — recuperación híbrida denso + léxico (BM25) + Reciprocal Rank
Fusion, por colección de ChromaDB.

Por qué: el vector denso difumina señal **léxica** que en phishing IDN es
decisiva — dominios homógrafos (`xn--pypal-4ve`), tokens de marca (`paypal`,
`1xbet`, `usbbog`), sufijos raros. BGE-M3 haría esto en una pasada pero pesa
1.2 GB; acá el canal sparse es `rank_bm25` in-process (RAM despreciable) sobre el
corpus traído de ChromaDB, refrescado por TTL / invalidado en cada upsert.

Degradación: sin `rank_bm25`, con colección vacía, o ante cualquier fallo del
índice → denso-solo. `RAG_HYBRID_ENABLED=False` también fuerza denso-solo.

El resultado lleva un `distance` sintético derivado del rango fusionado para que
``LLMAgent._rerank_by_source`` (ponderación λ(source), T11) siga componiendo
encima sin cambios.
"""
from __future__ import annotations

import asyncio
import re
import time
import unicodedata

from core.config import settings
from core.constants import RAG_BM25_INDEX_TTL_S, RAG_RRF_K
from core.logger import get_logger
from data_pipeline.rag_policy import eligible_document

logger = get_logger(__name__)

_TOKEN_RE = re.compile(r"\w+", re.UNICODE)
_DOMAIN_RE = re.compile(r"(?:[\w-]+(?:\.[\w-]+)+|xn--[a-z0-9-]+)", re.IGNORECASE)


def _tokenize(text: str) -> list[str]:
    """Tokens en minúscula. ``\\w`` en Py3 abarca cirílico/griego → los
    homoglifos quedan como tokens propios."""
    normalized = unicodedata.normalize("NFC", text or "").lower()
    tokens = _TOKEN_RE.findall(normalized)
    # Preserve full domains/Punycode alongside ordinary terms. A and U labels
    # share tokens, while distinct Unicode confusables are not collapsed.
    for domain in _DOMAIN_RE.findall(normalized):
        tokens.append(domain)
        tokens.extend(label for label in domain.split(".") if label.startswith("xn--"))
        try:
            decoded = domain.encode("ascii").decode("idna")
        except UnicodeError:
            continue
        if decoded != domain:
            tokens.extend([decoded, *_TOKEN_RE.findall(decoded)])
    return tokens


def _rrf_fuse(dense: list[dict], sparse: list[dict], n: int, k: int) -> list[dict]:
    """Reciprocal Rank Fusion: score(d) = Σ 1/(k + rank_en_lista)."""
    scores: dict[str, float] = {}
    payload: dict[str, dict] = {}
    for lst in (dense, sparse):
        seen: set[str] = set()
        for rank, d in enumerate(lst):
            key = d.get("id") or d.get("document") or repr(d)
            if key in seen:
                continue
            seen.add(key)
            scores[key] = scores.get(key, 0.0) + 1.0 / (k + rank + 1)
            payload.setdefault(key, d)

    ordered = sorted(scores, key=lambda kk: scores[kk], reverse=True)[:n]
    out: list[dict] = []
    total = max(len(ordered), 1)
    for rank, key in enumerate(ordered):
        d = dict(payload[key])
        d["distance"] = rank / total  # sintético: crece con el rango fusionado
        d["_rrf"] = round(scores[key], 6)
        d["_relevance"] = scores[key] / (2.0 / (k + 1))
        out.append(d)
    return out


class HybridRetriever:
    """Stateless respecto al request; mantiene un índice BM25 cacheado por
    colección."""

    def __init__(self) -> None:
        # colección -> (BM25Okapi | None, docs, built_at_monotonic)
        self._index: dict[str, tuple[object, list[dict], float]] = {}

    def invalidate(self, collection: str | None = None) -> None:
        if collection is None:
            self._index.clear()
        else:
            self._index.pop(collection, None)

    async def _get_index(self, collection: str) -> tuple[object, list[dict]]:
        now = time.monotonic()
        cached = self._index.get(collection)
        if cached is not None and now - cached[2] < RAG_BM25_INDEX_TTL_S:
            return cached[0], cached[1]

        from rank_bm25 import BM25Plus  # positive IDF also for tiny collections

        from models.chromadb_client import get_all_documents

        docs = [d for d in await get_all_documents(collection) if eligible_document(d)]
        corpus = [_tokenize(d["document"]) for d in docs]
        # Drop tokenless documents: BM25's average length must be positive.
        pairs = [(d, tokens) for d, tokens in zip(docs, corpus, strict=True) if tokens]
        docs = [d for d, _ in pairs]
        corpus = [tokens for _, tokens in pairs]
        idx = BM25Plus(corpus, delta=0) if corpus else None
        self._index[collection] = (idx, docs, now)
        logger.debug("bm25_index_built", collection=collection, n_docs=len(docs))
        return idx, docs

    async def search(
        self, collection: str, query: str, n_results: int
    ) -> list[dict]:
        """Devuelve hasta ``n_results`` docs fusionados (denso + BM25).
        Cada dict: ``{id, document, distance, metadata}`` (misma forma que
        ``query_collection``)."""
        from models.chromadb_client import query_collection

        if n_results <= 0 or not query.strip():
            return []

        async def dense_search():
            return await asyncio.wait_for(
                query_collection(collection, [query], n_results=n_results * 2),
                timeout=settings.RAG_RETRIEVAL_TIMEOUT_S,
            )

        async def sparse_search():
            idx, docs = await asyncio.wait_for(
                self._get_index(collection), timeout=settings.RAG_RETRIEVAL_TIMEOUT_S
            )
            if idx is None:
                return []
            scores = idx.get_scores(_tokenize(query))
            ranked = sorted(range(len(docs)), key=lambda i: scores[i], reverse=True)
            return [d for i in ranked if scores[i] > 0 and eligible_document(d := docs[i])][
                : n_results * 2
            ]

        jobs = [dense_search()]
        if settings.RAG_HYBRID_ENABLED:
            jobs.append(sparse_search())
        results = await asyncio.gather(*jobs, return_exceptions=True)
        channels = []
        for result in results:
            if isinstance(result, BaseException):
                logger.debug("rag_channel_unavailable", collection=collection,
                             error=type(result).__name__)
                channels.append([])
            else:
                channels.append([d for d in result if eligible_document(d)])
        dense = channels[0]
        sparse = channels[1] if len(channels) > 1 else []
        if not sparse:
            return dense[:n_results]
        return _rrf_fuse(dense, sparse, n_results, RAG_RRF_K)


hybrid_retriever = HybridRetriever()
