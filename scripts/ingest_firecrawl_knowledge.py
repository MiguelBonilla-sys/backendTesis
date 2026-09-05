"""Prepare and optionally ingest reviewed Firecrawl snapshots (no live crawling).

Run from backendTesis: python -m scripts.ingest_firecrawl_knowledge [--apply]
"""
from __future__ import annotations

import argparse
import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from core.config import settings
from core.constants import COLLECTION_KNOWLEDGE
from data_pipeline.reference_ingest import PIPELINE, ingest_references, prepare_references


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, default=Path("data/knowledge_sources.json"))
    parser.add_argument("--snapshots", type=Path, default=Path("../.firecrawl"))
    parser.add_argument("--output", type=Path, default=Path("../.firecrawl/knowledge"))
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    specification = json.loads(args.sources.read_text(encoding="utf-8"))
    captured_at = specification["retrieved_at"]
    records, sources = prepare_references(specification["sources"], args.snapshots, captured_at)
    args.output.mkdir(parents=True, exist_ok=True)
    for source in sources:
        url = urlsplit(source["source_url"])
        # Host/path organization, with traversal already rejected by URL review.
        safe_parts = [p for p in url.path.split("/") if p and p not in {".", ".."}]
        directory = args.output.joinpath(url.hostname, *safe_parts)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "index.md").write_text(
            f"Source: {source['source_url']}\nRetrieved: {captured_at}\n\n"
            + source.pop("markdown"),
            encoding="utf-8",
        )
    with (args.output / "chunks.jsonl").open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    manifest = {
        "pipeline": PIPELINE, "collection": COLLECTION_KNOWLEDGE,
        "prepared_at": datetime.now(UTC).isoformat(), "retrieved_at": captured_at,
        "embedding_provider": settings.EMBED_PROVIDER, "embedding_model": settings.EMBED_MODEL,
        "sources": sources, "chunks": len(records), "applied": False,
    }
    manifest_path = args.output / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.apply:
        from models.chromadb_client import get_or_create_collection, init_chromadb

        await init_chromadb()
        result = await ingest_references(records)
        collection = await get_or_create_collection(COLLECTION_KNOWLEDGE)
        manifest.update(result, applied=True, collection_count=await collection.count())
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    print(json.dumps({k: v for k, v in manifest.items() if k != "sources"}, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(main())
