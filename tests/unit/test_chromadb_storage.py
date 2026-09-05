"""Storage errors must not acknowledge feedback; embeddings stay off the loop."""
import threading
from unittest.mock import AsyncMock, patch

import pytest

from core.exceptions import DatabaseError
from data_pipeline.hybrid_retrieval import hybrid_retriever
from models.chromadb_client import delete_document, query_collection, upsert_documents


async def test_failed_delete_propagates_and_does_not_invalidate_cache():
    collection = AsyncMock()
    collection.delete.side_effect = RuntimeError("write unavailable")
    with patch("models.chromadb_client.get_or_create_collection", return_value=collection), \
         patch.object(hybrid_retriever, "invalidate") as invalidate:
        with pytest.raises(DatabaseError, match="delete failed"):
            await delete_document("email_embeddings", "email_incident")
    invalidate.assert_not_called()


async def test_successful_delete_invalidates_only_changed_collection():
    collection = AsyncMock()
    with patch("models.chromadb_client.get_or_create_collection", return_value=collection), \
         patch.object(hybrid_retriever, "invalidate") as invalidate:
        await delete_document("email_embeddings", "email_incident")
    collection.delete.assert_awaited_once_with(ids=["email_incident"])
    invalidate.assert_called_once_with("email_embeddings")


async def test_upsert_embeds_in_worker_and_invalidates_lexical_index():
    loop_thread = threading.get_ident()
    worker_threads = []

    def embed(texts):
        worker_threads.append(threading.get_ident())
        return [[float(len(t)), 0.0] for t in texts]

    collection = AsyncMock()
    with patch("models.chromadb_client.get_or_create_collection", return_value=collection), \
         patch("models.chromadb_client._embedding_function", return_value=embed), \
         patch.object(hybrid_retriever, "invalidate") as invalidate:
        await upsert_documents("security_knowledge", ["ref"], ["content"], [{"source": "test"}])
    assert worker_threads[0] != loop_thread
    assert collection.upsert.call_args.kwargs["embeddings"] == [[7.0, 0.0]]
    invalidate.assert_called_once_with("security_knowledge")


async def test_failed_embedding_does_not_write_in_another_space():
    collection = AsyncMock()

    def embed(_texts):
        raise RuntimeError("Ollama offline")

    with patch("models.chromadb_client.get_or_create_collection", return_value=collection), \
         patch("models.chromadb_client._embedding_function", return_value=embed):
        with pytest.raises(DatabaseError, match="upsert failed"):
            await upsert_documents("security_knowledge", ["ref"], ["content"])
    collection.upsert.assert_not_awaited()


async def test_query_embeds_before_chroma_and_keeps_provenance():
    collection = AsyncMock()
    collection.query.return_value = {
        "ids": [["ref"]], "documents": [["reference text"]], "distances": [[2.4]],
        "metadatas": [[{"source_url": "https://www.unicode.org/reports/tr39/"}]],
    }
    with patch("models.chromadb_client.get_or_create_collection", return_value=collection), \
         patch("models.chromadb_client._embedding_function", return_value=lambda _: [[1.0, 0.0]]):
        results = await query_collection("security_knowledge", ["query"])
    assert collection.query.call_args.kwargs["query_embeddings"] == [[1.0, 0.0]]
    assert "query_texts" not in collection.query.call_args.kwargs
    assert results[0]["distance"] == 2.4
    assert results[0]["metadata"]["source_url"].startswith("https://www.unicode.org")


async def test_empty_upsert_does_not_create_collection():
    with patch("models.chromadb_client.get_or_create_collection") as get_collection:
        await upsert_documents("security_knowledge", [], [])
    get_collection.assert_not_called()
