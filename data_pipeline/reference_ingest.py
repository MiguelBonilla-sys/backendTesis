"""Prepare public Firecrawl snapshots as traceable, non-verdict RAG evidence.

No network fetches: only explicitly selected URLs from a reviewed manifest.
Original snapshots stay outside version control and can reproduce every chunk.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from core.constants import COLLECTION_KNOWLEDGE

PIPELINE = "firecrawl_reference_v1"
_ALLOWED_HOSTS = frozenset({
    "unicode.org", "www.unicode.org", "attack.mitre.org", "www.cisa.gov",
    "learn.microsoft.com", "www.incibe.es", "datatracker.ietf.org", "www.rfc-editor.org",
    "www.microsoft.com", "www.malwarebytes.com", "www.dian.gov.co",
})
_HEADING = re.compile(r"^#{1,6}\s", re.MULTILINE)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_source_url(url: str) -> str:
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in _ALLOWED_HOSTS
            or parsed.username or parsed.password or parsed.port not in (None, 443)):
        raise ValueError(f"Unapproved public reference URL: {url}")
    return urlunsplit(("https", parsed.hostname, parsed.path or "/", parsed.query, ""))


def snapshot_page(payload: dict, url: str) -> dict:
    """Accept Firecrawl search JSON and single-page scrape/MCP data envelopes."""
    data = payload.get("data", payload)
    pages = data.get("web", []) if isinstance(data, dict) else []
    if isinstance(data, dict) and "markdown" in data:
        pages = [data]
    for page in pages:
        metadata = page.get("metadata") or {}
        actual = page.get("url") or metadata.get("sourceURL") or metadata.get("url")
        if actual and actual.split("#", 1)[0] == url.split("#", 1)[0]:
            status = metadata.get("statusCode", 200)
            if not 200 <= int(status) < 300 or page.get("error"):
                raise ValueError(f"Failed scrape for {url}")
            return page
    raise ValueError(f"Selected URL missing from Firecrawl snapshot: {url}")


def select_content(markdown: str, source: dict) -> str:
    """Drop navigation and optionally retain a reviewed section range.

    Section filters operate on heading lines, so table-of-contents links cannot
    select the wrong passage. The manifest records the filters verbatim.
    """
    markdown = markdown.replace("\r\n", "\n").strip()
    headings = list(_HEADING.finditer(markdown))
    start = headings[0].start() if headings else 0
    stop = len(markdown)
    for field in ("start_heading", "stop_heading"):
        pattern = source.get(field)
        if not pattern:
            continue
        matches = [m for m in headings if re.search(
            pattern, markdown[m.start():markdown.find("\n", m.start())
                              if "\n" in markdown[m.start():] else len(markdown)]
        ) and (field == "start_heading" or m.start() > start)]
        if not matches:
            raise ValueError(f"Missing {field}={pattern!r} for {source['url']}")
        if field == "start_heading":
            start = matches[0].start()
        else:
            stop = matches[0].start()
    selected = markdown[start:stop].strip()
    if len(selected) < 200:
        raise ValueError(f"Insufficient reference content: {source['url']}")
    return selected


def split_chunks(text: str, size: int = 1400, overlap: int = 180) -> list[str]:
    """Bounded paragraph-aware chunks with overlap and no lost trailing text."""
    if size < 200 or overlap < 0 or overlap >= size // 2:
        raise ValueError("Require size >= 200 and 0 <= overlap < size/2")
    chunks = []
    start = 0
    while start < len(text):
        end = min(start + size, len(text))
        if end < len(text):
            boundary = text.rfind("\n\n", start + size // 2, end)
            if boundary >= 0:
                end = boundary
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end == len(text):
            break
        start = end - overlap
    return chunks


def prepare_references(
    sources: list[dict], snapshot_root: Path, retrieved_at: str,
) -> tuple[list[dict], list[dict]]:
    """Return chunks and per-source provenance; fail before writing on bad input."""
    root = snapshot_root.resolve()
    records, manifest = [], []
    seen_urls: set[str] = set()
    for source in sources:
        url = canonical_source_url(source["url"])
        if url in seen_urls:
            raise ValueError(f"Duplicate source URL: {url}")
        seen_urls.add(url)
        path = (root / source["snapshot"]).resolve()
        if not path.is_relative_to(root):
            raise ValueError("Snapshot path escapes snapshot root")
        page = snapshot_page(json.loads(path.read_text(encoding="utf-8")), url)
        raw = page.get("markdown") or ""
        selected = select_content(raw, source)
        source_content_hash = digest(selected)
        document_type = source.get("document_type", "security_reference")
        case_metadata = {}
        if document_type == "case_report":
            # Editorial summaries are explicit local manifest data, never generated
            # from unreviewed page metadata. Preserve the original snapshot hash.
            for field in ("case_id", "published_at", "observed_period", "evidence_type"):
                value = source.get(field)
                if not isinstance(value, str) or not value.strip():
                    raise ValueError(f"Missing case field: {field}")
                case_metadata[field] = value
            date.fromisoformat(case_metadata["published_at"])
            if case_metadata["evidence_type"] not in {"observed_campaign", "public_alert"}:
                raise ValueError("Case evidence must be an observed campaign or public alert")
            curated = source.get("curated_text")
            if not isinstance(curated, str) or len(curated.strip()) < 200:
                raise ValueError("Case reports require a reviewed summary of at least 200 chars")
            selected = curated.strip()
            case_metadata.update(content_kind="reviewed_summary",
                                 source_content_sha256=source_content_hash)
        elif document_type != "security_reference" or "curated_text" in source:
            raise ValueError("Curated text is supported only for explicit case reports")
        title = (source.get("title") or page.get("title")
                 or (page.get("metadata") or {}).get("title"))
        if not title:
            raise ValueError(f"Missing source title: {url}")
        metadata = {
            "source": "official_reference", "source_url": url, "title": title,
            "publisher": source["publisher"], "language": source.get("language", "en"),
            "topic": source["topic"], "retrieved_at": retrieved_at,
            "content_sha256": digest(selected), "snapshot_sha256": digest(raw),
            "ingestion_pipeline": PIPELINE, "document_type": document_type,
            **case_metadata,
        }
        seen_chunks: set[str] = set()
        for i, chunk in enumerate(split_chunks(selected)):
            chunk_hash = digest(chunk)
            if chunk_hash in seen_chunks:
                continue
            seen_chunks.add(chunk_hash)
            records.append({
                "id": "ref_" + digest(url + "\n" + chunk),
                "document": f"{title}\nTopic: {source['topic']}\n{chunk}",
                "metadata": {**metadata, "chunk_index": i, "chunk_sha256": chunk_hash},
            })
        manifest.append({**metadata, "snapshot": source["snapshot"],
                         "selection": {k: source[k] for k in ("start_heading", "stop_heading")
                                       if k in source},
                         "chunks": len(seen_chunks), "markdown": selected})
    return records, manifest


async def ingest_references(records: list[dict], batch_size: int = 16) -> dict:
    """Idempotent upsert; prune only stale chunks owned by this ingestion pipeline.

    All sources validate before this is called. Old versions remain until every
    new batch is stored. A failed write propagates and cannot report success.
    """
    from models.chromadb_client import get_or_create_collection, upsert_documents

    if batch_size <= 0:
        raise ValueError("batch_size must be positive")
    if not records:
        return {"upserted": 0, "removed_stale": 0}
    for offset in range(0, len(records), batch_size):
        batch = records[offset:offset + batch_size]
        await upsert_documents(
            COLLECTION_KNOWLEDGE, ids=[r["id"] for r in batch],
            documents=[r["document"] for r in batch],
            metadatas=[r["metadata"] for r in batch],
        )
    collection = await get_or_create_collection(COLLECTION_KNOWLEDGE)
    removed = 0
    urls = {r["metadata"]["source_url"] for r in records}
    for url in urls:
        previous = await collection.get(where={"$and": [
            {"source_url": url}, {"ingestion_pipeline": PIPELINE},
        ]}, include=["metadatas"])
        keep = {r["id"] for r in records if r["metadata"]["source_url"] == url}
        stale = sorted(set(previous["ids"]) - keep)
        if stale:
            await collection.delete(ids=stale)
            removed += len(stale)
    from data_pipeline.hybrid_retrieval import hybrid_retriever

    hybrid_retriever.invalidate(COLLECTION_KNOWLEDGE)
    return {"upserted": len(records), "removed_stale": removed}
