"""Async ChromaDB client — manages the three vector collections."""

from __future__ import annotations

import chromadb
from chromadb import AsyncHttpClient

from core.config import settings
from core.constants import COLLECTION_EMAIL, COLLECTION_IDN, COLLECTION_TI
from core.exceptions import DatabaseError
from core.logger import get_logger

logger = get_logger(__name__)

_client: AsyncHttpClient | None = None

# Collections that must exist at startup
_REQUIRED_COLLECTIONS: list[str] = [
    COLLECTION_EMAIL,
    COLLECTION_IDN,
    COLLECTION_TI,
]


async def init_chromadb() -> None:
    """Create the async HTTP client and ensure all required collections exist."""
    global _client
    try:
        _client = await chromadb.AsyncHttpClient(
            host=settings.CHROMADB_HOST,
            port=settings.CHROMADB_PORT,
        )
        logger.info(
            "ChromaDB client initialised",
            host=settings.CHROMADB_HOST,
            port=settings.CHROMADB_PORT,
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
    try:
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
    collection = await get_or_create_collection(collection_name)
    try:
        await collection.upsert(
            ids=ids,
            documents=documents,
            metadatas=metadatas or [{} for _ in ids],
        )
    except Exception as exc:
        raise DatabaseError(
            message=f"ChromaDB upsert failed on collection '{collection_name}'",
            detail=str(exc),
        ) from exc


async def delete_document(collection_name: str, doc_id: str) -> None:
    """Delete a single document from *collection_name* by id.

    Silently ignores missing ids so callers don't need to guard existence.
    """
    collection = await get_or_create_collection(collection_name)
    try:
        await collection.delete(ids=[doc_id])
    except Exception as exc:
        logger.warning(
            "chromadb_delete_failed",
            collection=collection_name,
            doc_id=doc_id,
            error=str(exc),
        )


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
    - ``distance``: cosine distance
    - ``metadata``: associated metadata dict
    """
    collection = await get_or_create_collection(collection_name)
    try:
        results = await collection.query(
            query_texts=query_texts,
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
