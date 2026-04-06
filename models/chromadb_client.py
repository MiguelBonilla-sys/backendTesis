import chromadb

from core.config import settings
from core.constants import (
    COLLECTION_EMAIL_EMBEDDINGS,
    COLLECTION_IDN_PATTERNS,
    COLLECTION_TI_SIGNALS,
)
from core.logger import logger

_client: chromadb.HttpClient | None = None

_COLLECTIONS = [
    COLLECTION_EMAIL_EMBEDDINGS,
    COLLECTION_IDN_PATTERNS,
    COLLECTION_TI_SIGNALS,
]


def get_chromadb_client() -> chromadb.HttpClient:
    global _client
    if _client is None:
        _client = chromadb.HttpClient(
            host=settings.CHROMADB_HOST,
            port=settings.CHROMADB_PORT,
        )
        logger.info(f"ChromaDB connected at {settings.CHROMADB_HOST}:{settings.CHROMADB_PORT}")
    return _client


def ensure_collections() -> None:
    """Create ChromaDB collections on startup if they don't already exist."""
    client = get_chromadb_client()
    for name in _COLLECTIONS:
        client.get_or_create_collection(name)
        logger.info(f"ChromaDB collection ready: {name}")
