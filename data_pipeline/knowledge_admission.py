"""Shared admission/retention guard for automatic RAG learning.

The PostgreSQL transaction lock serializes all application instances sharing the
primary DB. Storage failures fail closed; do not switch to an in-process lock.
Chroma has no multi-collection transaction: partial writes remain bounded and a
retry uses the same entity ID. Sync must run with application writers paused.
"""

from __future__ import annotations

import hashlib
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from urllib.parse import urldefrag

from core.config import settings
from core.constants import COLLECTION_EMAIL, COLLECTION_IDN, COLLECTION_TI
from models.chromadb_client import get_or_create_collection
from models.database import get_pool

AUTO_SOURCES = ("auto_ingest", "auto_high", "auto_mid", "auto_low")
COLLECTION_PREFIXES = (
    (COLLECTION_EMAIL, "email_"),
    (COLLECTION_IDN, "idn_"),
    (COLLECTION_TI, "ti_"),
)
_LOCK_ID = 730_202_609_25
_PAGE = 300


def canonical_entity_url(url: str) -> str:
    # Preserve path, query and host; never merge distinct tenants/resources.
    return urldefrag(url)[0]


def entity_id(url: str) -> str:
    return "url_" + hashlib.sha256(canonical_entity_url(url).encode()).hexdigest()


@asynccontextmanager
async def knowledge_write_lock():
    async with get_pool().acquire() as conn:
        async with conn.transaction():
            await conn.execute("SET LOCAL lock_timeout = '5s'")
            await conn.execute("SELECT pg_advisory_xact_lock($1)", _LOCK_ID)
            yield conn


def _expired(metadata: dict, now: datetime) -> bool:
    value = metadata.get("expires_at")
    try:
        timestamp = datetime.fromisoformat(
            str(value or metadata.get("ingested_at", "")).replace("Z", "+00:00")
        )
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)
        expiry = (
            timestamp if value else timestamp + timedelta(days=settings.AUTO_INGEST_RETENTION_DAYS)
        )
        return expiry <= now
    except ValueError:
        # Missing/invalid retention cannot make old automatic evidence immortal.
        return True


async def _automatic_rows(collection) -> list[tuple[str, dict]]:
    rows = []
    offset = 0
    # Fixed work budget; quota calculations fail closed beyond this amount.
    limit = settings.AUTO_INGEST_SCAN_LIMIT
    while len(rows) <= limit:
        page = await collection.get(
            where={"source": {"$in": list(AUTO_SOURCES)}},
            include=["metadatas"],
            limit=min(_PAGE, limit + 1 - len(rows)),
            offset=offset,
        )
        ids = page.get("ids") or []
        metadata = page.get("metadatas") or [{} for _ in ids]
        rows.extend(zip(ids, metadata, strict=True))
        if len(rows) > limit:
            raise RuntimeError(
                "automatic knowledge exceeds scan budget; run supervised retention maintenance"
            )
        if len(ids) < _PAGE:
            break
        offset += len(ids)
    return rows


async def admit_automatic(conn, *, url: str, incident_id: str | None, doc_id: str) -> bool:
    quota = settings.AUTO_INGEST_QUOTA
    if quota <= 0 or not incident_id or settings.AUTO_INGEST_MAX_DOCUMENTS <= 0:
        return False
    # Auto evidence must have a durable incident so human feedback can find/purge it.
    if not await conn.fetchval(
        "SELECT EXISTS(SELECT 1 FROM incidents WHERE id=$1::uuid AND url=$2)", incident_id, url
    ):
        return False
    if await conn.fetchval(
        "SELECT EXISTS(SELECT 1 FROM feedback f JOIN incidents i ON i.id=f.incident_id "
        "WHERE split_part(i.url, '#', 1)=$1 AND f.confirmed_verdict='LEGITIMATE')",
        canonical_entity_url(url),
    ):
        return False

    now = datetime.now(UTC)
    for name, prefix in COLLECTION_PREFIXES:
        collection = await get_or_create_collection(name)
        auto_rows = await _automatic_rows(collection)
        expired = [did for did, metadata in auto_rows if _expired(metadata or {}, now)]
        for i in range(0, len(expired), _PAGE):
            await collection.delete(ids=expired[i : i + _PAGE])
        if expired:
            from data_pipeline.hybrid_retrieval import hybrid_retriever

            hybrid_retriever.invalidate(name)
        automatic_ids = {did for did, metadata in auto_rows if not _expired(metadata or {}, now)}
        current_id = prefix + doc_id
        existing = await collection.get(ids=[current_id], include=["metadatas"])
        if existing.get("ids") and current_id not in automatic_ids:
            return False  # never overwrite human or seeded evidence with a prediction
        total = await collection.count()
        added = int(current_id not in automatic_ids)
        after_auto = len(automatic_ids) + added
        if after_auto > settings.AUTO_INGEST_MAX_DOCUMENTS:
            return False
        if after_auto / max(total + added, 1) > quota:
            return False
    return True
