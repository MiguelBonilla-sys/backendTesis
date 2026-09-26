"""Regression coverage for quota, durable identity, retention and concurrent writers."""

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest

from core.config import settings
from data_pipeline.knowledge_admission import COLLECTION_PREFIXES, admit_automatic, entity_id
from data_pipeline.knowledge_updater import KnowledgeUpdaterService
from data_pipeline.rag_policy import eligible_document
from tests.support.knowledge_storage import MemoryCollection, MemoryKnowledgePool
from tests.unit.test_knowledge_updater import _BASE_ANALYSIS


@pytest.fixture
def storage(monkeypatch):
    pool = MemoryKnowledgePool()
    collections = {
        name: MemoryCollection({"seed": {"source": "admin_confirmed"}})
        for name, _ in COLLECTION_PREFIXES
    }
    monkeypatch.setattr("data_pipeline.knowledge_admission.get_pool", lambda: pool)
    monkeypatch.setattr(
        "data_pipeline.knowledge_admission.get_or_create_collection",
        AsyncMock(side_effect=lambda name: collections[name]),
    )
    monkeypatch.setattr(settings, "AUTO_INGEST_QUOTA", 0.60)
    monkeypatch.setattr(settings, "AUTO_INGEST_MAX_DOCUMENTS", 2000)
    return pool, collections


def auto_metadata(**extra):
    return {"source": "auto_high", "ingested_at": datetime.now(UTC).isoformat(), **extra}


async def admitted(pool, *, url="https://example.test/a", incident="persisted"):
    return await admit_automatic(pool, url=url, incident_id=incident, doc_id=entity_id(url))


async def test_quota_zero_never_upserts(storage, monkeypatch):
    monkeypatch.setattr(settings, "AUTO_INGEST_QUOTA", 0.0)
    with patch("data_pipeline.knowledge_updater.upsert_documents", new_callable=AsyncMock) as write:
        await KnowledgeUpdaterService().ingest_from_analysis(**_BASE_ANALYSIS, incident_id="i")
    write.assert_not_awaited()


async def test_requires_persisted_incident_and_rejects_prior_legitimate_feedback(storage):
    pool, _ = storage
    assert not await admitted(pool, incident=None)
    pool.persisted = False
    assert not await admitted(pool)
    pool.persisted = True
    pool.blocked = True
    assert not await admitted(pool)


async def test_empty_corpus_and_full_quota_reject_new_entity(storage):
    pool, collections = storage
    for col in collections.values():
        col.rows.clear()
    assert not await admitted(pool)
    for col in collections.values():
        col.rows.update(seed={"source": "admin_confirmed"}, existing=auto_metadata())
    assert not await admitted(pool)  # 2/3 would exceed 0.60


async def test_repeat_same_entity_does_not_grow_and_admin_cannot_be_overwritten(storage):
    pool, collections = storage
    doc_id = entity_id("https://example.test/a")
    for name, prefix in COLLECTION_PREFIXES:
        collections[name].rows[prefix + doc_id] = auto_metadata()
    assert await admitted(pool)
    first_name, first_prefix = COLLECTION_PREFIXES[0]
    collections[first_name].rows[first_prefix + doc_id] = {"source": "admin_confirmed"}
    assert not await admitted(pool)


async def test_expired_auto_is_physically_removed_before_admission(storage):
    pool, collections = storage
    old = (datetime.now(UTC) - timedelta(days=40)).isoformat()
    for col in collections.values():
        col.rows["old"] = auto_metadata(ingested_at=old)
    assert await admitted(pool)
    assert all("old" in col.deleted and "seed" in col.rows for col in collections.values())


async def test_absolute_cap_and_scan_budget_fail_closed(storage, monkeypatch):
    pool, collections = storage
    monkeypatch.setattr(settings, "AUTO_INGEST_MAX_DOCUMENTS", 1)
    monkeypatch.setattr(settings, "AUTO_INGEST_QUOTA", 1.0)
    for col in collections.values():
        col.rows["one"] = auto_metadata()
    assert not await admitted(pool)
    monkeypatch.setattr(settings, "AUTO_INGEST_SCAN_LIMIT", 1)
    for col in collections.values():
        col.rows["two"] = auto_metadata()
    with pytest.raises(RuntimeError, match="scan budget"):
        await admitted(pool)


async def test_concurrent_writers_share_database_lock_and_cannot_exceed_quota(storage):
    pool, collections = storage

    async def write(collection, *, ids, documents, metadatas):
        await asyncio.sleep(0)
        collections[collection].rows.update(zip(ids, metadatas, strict=True))

    with patch("data_pipeline.knowledge_updater.upsert_documents", side_effect=write):
        await asyncio.gather(
            *[
                KnowledgeUpdaterService().ingest_from_analysis(
                    **{**_BASE_ANALYSIS, "url": f"https://sample-{i}.test/"},
                    incident_id=f"incident-{i}",
                )
                for i in range(10)
            ]
        )
    assert all(len(col.rows) == 2 for col in collections.values())  # 1 seed + 1 auto
    assert sum("pg_advisory_xact_lock" in query for query, _ in pool.calls) == 10


async def test_repeat_incidents_share_document_ids(storage):
    with patch(
        "data_pipeline.knowledge_updater.upsert_documents", new_callable=AsyncMock
    ) as upsert:
        for i in range(5):
            await KnowledgeUpdaterService().ingest_from_analysis(
                **_BASE_ANALYSIS, incident_id=f"i-{i}"
            )
    assert upsert.await_count == 15
    assert len({call.kwargs["ids"][0] for call in upsert.call_args_list}) == 3
    assert all("expires_at" in call.kwargs["metadatas"][0] for call in upsert.call_args_list)


async def test_purge_removes_stable_and_legacy_ids_for_same_url(storage):
    pool, _ = storage
    pool.incident_ids = ["earlier", "current"]
    with patch("data_pipeline.knowledge_updater.delete_document", new_callable=AsyncMock) as delete:
        await KnowledgeUpdaterService().purge_incident_documents(
            "current", url=_BASE_ANALYSIS["url"]
        )
    assert delete.await_count == 9
    for name, prefix in COLLECTION_PREFIXES:
        assert any(
            call.args == (name, prefix + entity_id(_BASE_ANALYSIS["url"]))
            for call in delete.call_args_list
        )
        assert any(call.args == (name, prefix + "earlier") for call in delete.call_args_list)


async def test_unverified_baseline_rejected_at_ingestion_boundary():
    parsed = type("Parsed", (), {"authentication_verified": False})()
    with patch(
        "data_pipeline.knowledge_updater.upsert_documents", new_callable=AsyncMock
    ) as upsert:
        await KnowledgeUpdaterService().ingest_legit_baseline(parsed)
    upsert.assert_not_awaited()


def test_entity_identity_keeps_query_path_host_and_ignores_fragment():
    assert entity_id("https://safe.vercel.app/a#fragment") == entity_id("https://safe.vercel.app/a")
    ids = [
        entity_id(url)
        for url in (
            "https://safe.vercel.app/a",
            "https://evil.vercel.app/a",
            "https://safe.vercel.app/b",
            "https://safe.vercel.app/a?x=1",
        )
    ]
    assert len(set(ids)) == 4


def test_expired_and_undated_legacy_auto_never_retrieved():
    for metadata in ({"source": "auto_high"}, auto_metadata(ingested_at="2020-01-01T00:00:00Z")):
        assert not eligible_document({"document": "old evidence", "metadata": metadata})
    assert eligible_document(
        {"document": "seed evidence", "metadata": {"source": "admin_confirmed"}}
    )
