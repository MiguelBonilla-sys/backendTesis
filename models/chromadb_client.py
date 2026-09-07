"""Async ChromaDB client — observed patterns, baseline and public references."""

from __future__ import annotations

import asyncio

import chromadb
from chromadb import AsyncHttpClient

from core.config import settings
from core.constants import (
    COLLECTION_BASELINE,
    COLLECTION_EMAIL,
    COLLECTION_IDN,
    COLLECTION_KNOWLEDGE,
    COLLECTION_TI,
)
from core.exceptions import DatabaseError
from core.logger import get_logger

logger = get_logger(__name__)

_client: AsyncHttpClient | None = None
_embed_fn = None  # cache de la EmbeddingFunction (None = default de ChromaDB)
_embed_fn_resolved = False


class _OllamaEmbedder:
    """EmbeddingFunction de ChromaDB respaldada por Ollama local
    (``POST {base}/api/embed``). httpx en vez del paquete ``ollama`` — cero deps
    nuevas. Corre client-side: los embeddings se calculan acá y se envían al
    servidor de ChromaDB."""

    def __init__(self, base_url: str, model: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model

    @staticmethod
    def name() -> str:
        return "ollama"

    def get_config(self) -> dict:
        return {"base_url": self._base_url, "model": self._model}

    @classmethod
    def build_from_config(cls, config: dict) -> _OllamaEmbedder:
        return cls(config["base_url"], config["model"])

    def __call__(self, input: list[str]) -> list[list[float]]:  # noqa: A002 — firma de ChromaDB
        import httpx

        resp = httpx.post(
            f"{self._base_url}/api/embed",
            json={"model": self._model, "input": list(input)},
            timeout=60.0,
        )
        resp.raise_for_status()
        return resp.json()["embeddings"]

    # ChromaDB 1.5.x llama estos en upsert/query respectivamente
    def embed_documents(self, input: list[str]) -> list[list[float]]:  # noqa: A002
        return self(input)

    def embed_query(self, input: list[str]) -> list[list[float]]:  # noqa: A002
        return self(input)


class _OpenAIEmbedder:
    """EmbeddingFunction respaldada por un endpoint compatible con la API de
    OpenAI (``POST {base}/embeddings``). Sirve OpenAI, fal.run, Voyage, etc. sin
    modelo local. ``auth_scheme`` = "Bearer" (OpenAI) o "Key" (fal.run)."""

    def __init__(self, base_url: str, model: str, api_key: str, auth_scheme: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._api_key = api_key
        self._auth_scheme = auth_scheme or "Bearer"

    @staticmethod
    def name() -> str:
        return "openai_compat"

    def get_config(self) -> dict:
        return {"base_url": self._base_url, "model": self._model}

    @classmethod
    def build_from_config(cls, config: dict) -> _OpenAIEmbedder:
        # El secreto no se persiste en la config de la colección → viene de settings.
        return cls(
            config["base_url"],
            config["model"],
            settings.EMBED_API_KEY,
            settings.EMBED_AUTH_SCHEME,
        )

    def __call__(self, input: list[str]) -> list[list[float]]:  # noqa: A002
        import httpx

        headers = {}
        if self._api_key:
            headers["Authorization"] = f"{self._auth_scheme} {self._api_key}"
        resp = httpx.post(
            f"{self._base_url}/embeddings",
            json={"model": self._model, "input": list(input)},
            headers=headers,
            timeout=60.0,
        )
        resp.raise_for_status()
        data = resp.json()["data"]
        return [row["embedding"] for row in sorted(data, key=lambda r: r["index"])]

    def embed_documents(self, input: list[str]) -> list[list[float]]:  # noqa: A002
        return self(input)

    def embed_query(self, input: list[str]) -> list[list[float]]:  # noqa: A002
        return self(input)


class _HFEmbedder:
    """EmbeddingFunction contra HuggingFace Inference (``feature-extraction``).
    Sirve `google/embeddinggemma-300m` sin Ollama: mismo modelo que el Ollama
    local, endpoint remoto. La respuesta es ``[[float, ...], ...]`` (no OpenAI)."""

    def __init__(self, base_url: str, model: str, api_key: str) -> None:
        base = base_url.rstrip("/")
        self._url = f"{base}/{model}/pipeline/feature-extraction"
        self._model = model
        self._api_key = api_key

    @staticmethod
    def name() -> str:
        return "hf_feature_extraction"

    def get_config(self) -> dict:
        return {"base_url": self._url, "model": self._model}

    @classmethod
    def build_from_config(cls, config: dict) -> _HFEmbedder:
        return cls(settings.EMBED_BASE_URL, config["model"], settings.EMBED_API_KEY)

    def __call__(self, input: list[str]) -> list[list[float]]:  # noqa: A002
        import httpx

        headers = {}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        resp = httpx.post(
            self._url,
            json={"inputs": list(input), "options": {"wait_for_model": True}},
            headers=headers,
            timeout=60.0,
        )
        resp.raise_for_status()
        return resp.json()

    def embed_documents(self, input: list[str]) -> list[list[float]]:  # noqa: A002
        return self(input)

    def embed_query(self, input: list[str]) -> list[list[float]]:  # noqa: A002
        return self(input)


def _embedding_function():
    """EmbeddingFunction para las colecciones.

    Preserve the configured model even during outages. Silently switching to
    MiniLM would mix incompatible dimensions/semantic spaces in existing data.
    """
    global _embed_fn, _embed_fn_resolved
    if _embed_fn_resolved:
        return _embed_fn
    _embed_fn_resolved = True

    provider = settings.EMBED_PROVIDER.lower()
    if provider == "ollama":
        _embed_fn = _OllamaEmbedder(settings.EMBED_BASE_URL, settings.EMBED_MODEL)
    elif provider in ("openai", "openai_compat", "fal"):
        _embed_fn = _OpenAIEmbedder(
            settings.EMBED_BASE_URL,
            settings.EMBED_MODEL,
            settings.EMBED_API_KEY,
            settings.EMBED_AUTH_SCHEME,
        )
    elif provider in ("hf", "huggingface"):
        _embed_fn = _HFEmbedder(
            settings.EMBED_BASE_URL, settings.EMBED_MODEL, settings.EMBED_API_KEY
        )
    else:
        return _embed_fn  # None → default MiniLM de ChromaDB

    logger.info("chromadb_embedder", provider=provider, model=settings.EMBED_MODEL)
    return _embed_fn


# Collections that must exist at startup
_REQUIRED_COLLECTIONS: list[str] = [
    COLLECTION_EMAIL,
    COLLECTION_IDN,
    COLLECTION_TI,
    COLLECTION_BASELINE,
    COLLECTION_KNOWLEDGE,
]


async def init_chromadb() -> None:
    """Create the async HTTP client and ensure all required collections exist."""
    global _client
    try:
        kwargs: dict = {
            "host": settings.CHROMADB_HOST,
            "port": settings.CHROMADB_PORT,
            "ssl": settings.CHROMADB_SSL or bool(settings.CHROMA_API_KEY),
        }
        if settings.CHROMA_API_KEY:  # Chroma Cloud
            kwargs["headers"] = {"x-chroma-token": settings.CHROMA_API_KEY}
            kwargs["tenant"] = settings.CHROMA_TENANT
            kwargs["database"] = settings.CHROMA_DATABASE
        _client = await chromadb.AsyncHttpClient(**kwargs)
        logger.info(
            "ChromaDB client initialised",
            host=settings.CHROMADB_HOST,
            port=settings.CHROMADB_PORT,
            cloud=bool(settings.CHROMA_API_KEY),
        )
        # Eagerly create collections so agents can use them without guards
        for name in _REQUIRED_COLLECTIONS:
            await get_or_create_collection(name)
            logger.info("ChromaDB collection ready", collection=name)
    except Exception as exc:
        raise DatabaseError(
            message="Failed to initialise ChromaDB client",
            detail=str(exc),
        ) from exc


def get_client() -> AsyncHttpClient:
    """Return the active ChromaDB async HTTP client.

    Raises:
        RuntimeError: If the client has not been initialised yet.
    """
    if _client is None:
        raise RuntimeError("ChromaDB not initialised — call init_chromadb() first.")
    return _client


async def get_or_create_collection(name: str) -> chromadb.Collection:
    """Return the named collection, creating it if it does not exist."""
    client = get_client()
    ef = _embedding_function()
    try:
        if ef is not None:
            return await client.get_or_create_collection(name=name, embedding_function=ef)
        return await client.get_or_create_collection(name=name)
    except Exception as exc:
        raise DatabaseError(
            message=f"Failed to get/create ChromaDB collection '{name}'",
            detail=str(exc),
        ) from exc


async def upsert_documents(
    collection_name: str,
    ids: list[str],
    documents: list[str],
    metadatas: list[dict] | None = None,
) -> None:
    """Upsert *documents* into *collection_name*. Creates the collection if needed.

    Uses ChromaDB upsert semantics: inserts new documents and overwrites existing
    ones with the same id. Safe to call repeatedly with the same incident_id.
    """
    if not ids:
        return
    collection = await get_or_create_collection(collection_name)
    try:
        ef = _embedding_function()
        extra = {"embeddings": await asyncio.to_thread(ef, documents)} if ef else {}
        await collection.upsert(
            ids=ids,
            documents=documents,
            metadatas=metadatas or [{} for _ in ids],
            **extra,
        )
        from data_pipeline.hybrid_retrieval import hybrid_retriever

        hybrid_retriever.invalidate(collection_name)
    except Exception as exc:
        raise DatabaseError(
            message=f"ChromaDB upsert failed on collection '{collection_name}'",
            detail=str(exc),
        ) from exc


async def delete_document(collection_name: str, doc_id: str) -> None:
    """Delete a single document from *collection_name* by id.

    Missing ids are harmless; storage errors propagate so feedback stays pending.
    """
    collection = await get_or_create_collection(collection_name)
    try:
        await collection.delete(ids=[doc_id])
        from data_pipeline.hybrid_retrieval import hybrid_retriever

        hybrid_retriever.invalidate(collection_name)
    except Exception as exc:
        raise DatabaseError(
            message=f"ChromaDB delete failed on collection '{collection_name}'",
            detail=str(exc),
        ) from exc


async def query_collection(
    collection_name: str,
    query_texts: list[str],
    n_results: int = 3,
) -> list[dict]:
    """Query *collection_name* for the *n_results* nearest neighbours of each
    entry in *query_texts*.

    Returns a flat list of result dicts, each containing:
    - ``id``: document id
    - ``document``: the stored text
    - ``distance``: collection metric distance (default: squared L2)
    - ``metadata``: associated metadata dict
    """
    collection = await get_or_create_collection(collection_name)
    try:
        ef = _embedding_function()
        query = (
            {"query_embeddings": await asyncio.to_thread(ef, query_texts)}
            if ef
            else {"query_texts": query_texts}
        )
        results = await collection.query(
            **query,
            n_results=n_results,
            include=["documents", "distances", "metadatas"],
        )
    except Exception as exc:
        raise DatabaseError(
            message=f"ChromaDB query failed on collection '{collection_name}'",
            detail=str(exc),
        ) from exc

    # Flatten the nested result structure into a plain list of dicts
    flat: list[dict] = []
    ids_outer = results.get("ids") or []
    docs_outer = results.get("documents") or []
    dists_outer = results.get("distances") or []
    metas_outer = results.get("metadatas") or []

    for i, ids_row in enumerate(ids_outer):
        docs_row = docs_outer[i] if i < len(docs_outer) else []
        dists_row = dists_outer[i] if i < len(dists_outer) else []
        metas_row = metas_outer[i] if i < len(metas_outer) else []
        for j, doc_id in enumerate(ids_row):
            flat.append(
                {
                    "id": doc_id,
                    "document": docs_row[j] if j < len(docs_row) else "",
                    "distance": dists_row[j] if j < len(dists_row) else None,
                    "metadata": metas_row[j] if j < len(metas_row) else {},
                }
            )

    return flat


async def get_all_documents(collection_name: str) -> list[dict]:
    """Todos los documentos de una colección — ``[{id, document, metadata}]``.

    Usado por el retriever híbrido para construir el índice BM25 (canal léxico).
    Ante cualquier fallo devuelve ``[]`` (el híbrido cae a denso-solo).
    """
    try:
        collection = await get_or_create_collection(collection_name)
        res = await collection.get(include=["documents", "metadatas"])
    except Exception as exc:  # noqa: BLE001
        logger.warning("chromadb_get_all_failed", collection=collection_name, error=str(exc))
        return []

    ids = res.get("ids") or []
    docs = res.get("documents") or []
    metas = res.get("metadatas") or []
    return [
        {
            "id": ids[i],
            "document": docs[i] if i < len(docs) else "",
            "metadata": metas[i] if i < len(metas) else {},
        }
        for i in range(len(ids))
    ]
