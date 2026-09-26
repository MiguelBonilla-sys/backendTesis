"""Mirror Chroma collections from an explicitly chosen authority.

Writes require a fenced replica and a quiesced source across PG/Chroma sync.
Missing documents are deletions and current document/metadata updates propagate.
Bilateral missing-ID merges are rejected: they resurrect purged evidence.
Re-embedding preserves separate embedding spaces; no collection is ever deleted.
See docs/synchronization-and-learning.md.
"""

from __future__ import annotations

import argparse
import asyncio
import os

import chromadb

from core.config import settings
from core.constants import (
    COLLECTION_BASELINE,
    COLLECTION_EMAIL,
    COLLECTION_IDN,
    COLLECTION_KNOWLEDGE,
    COLLECTION_TI,
)
from core.logger import get_logger
from models.chromadb_client import (
    _embedding_function,  # noqa: PLC2701 — reuso interno deliberado
    _HFEmbedder,
    _OpenAIEmbedder,
)

logger = get_logger(__name__)

# Chroma Cloud free tier limita `.get()` a 300 filas por request → paginar.
_PAGE = 300

_COLLECTIONS = [
    COLLECTION_EMAIL,
    COLLECTION_IDN,
    COLLECTION_TI,
    COLLECTION_BASELINE,
    COLLECTION_KNOWLEDGE,
]


async def _client_from_settings():
    kwargs: dict = {
        "host": settings.CHROMADB_HOST,
        "port": settings.CHROMADB_PORT,
        "ssl": settings.CHROMADB_SSL or bool(settings.CHROMA_API_KEY),
    }
    if settings.CHROMA_API_KEY:
        kwargs["headers"] = {"x-chroma-token": settings.CHROMA_API_KEY}
        kwargs["tenant"] = settings.CHROMA_TENANT
        kwargs["database"] = settings.CHROMA_DATABASE
    return await chromadb.AsyncHttpClient(**kwargs)


async def _client_from_env():
    return await chromadb.AsyncHttpClient(
        host=os.environ["STANDBY_CHROMA_HOST"],
        port=int(os.environ.get("STANDBY_CHROMA_PORT", "443")),
        ssl=True,
        headers={"x-chroma-token": os.environ["STANDBY_CHROMA_API_KEY"]},
        tenant=os.environ["STANDBY_CHROMA_TENANT"],
        database=os.environ["STANDBY_CHROMA_DATABASE"],
    )


def _standby_embedder():
    """Embedder del destino Chroma Cloud desde `STANDBY_EMBED_*`. None si no está
    (→ vector-copy). fal/OpenAI-compat usa `Key`/`Bearer`; hf usa feature-extraction."""
    model = os.environ.get("STANDBY_EMBED_MODEL")
    if not model:
        return None
    provider = os.environ.get("STANDBY_EMBED_PROVIDER", "hf").lower()
    base = os.environ["STANDBY_EMBED_BASE_URL"]
    key = os.environ.get("STANDBY_EMBED_API_KEY", "")
    if provider in ("hf", "huggingface"):
        return _HFEmbedder(base, model, key)
    return _OpenAIEmbedder(base, model, key, os.environ.get("STANDBY_EMBED_AUTH_SCHEME", "Bearer"))


async def _get_all(col, include: list[str]) -> dict:
    """`.get()` paginado (Chroma Cloud free corta en 300 filas)."""
    out: dict = {"ids": [], **{k: [] for k in include}}
    offset = 0
    while True:
        page = await col.get(include=include, limit=_PAGE, offset=offset)
        page_ids = page.get("ids") or []
        out["ids"].extend(page_ids)
        for k in include:
            v = page.get(k)
            if v is not None:
                out[k].extend(list(v))
        if len(page_ids) < _PAGE:
            return out
        offset += _PAGE


async def _stats(client, name: str) -> tuple[int, int]:
    """(count, dim) — dim de un vector de muestra; -1 si falta la colección."""
    try:
        col = await client.get_collection(name)
        n = await col.count()
        if n == 0:
            return (0, 0)
        page = await col.get(include=["embeddings"], limit=1)
        embs = page.get("embeddings")
        dim = len(embs[0]) if embs is not None and len(embs) else 0
        return (n, dim)
    except Exception:
        return (-1, -1)


async def _check(src, dst) -> int:
    print(f"{'colección':<20} {'origen (n/dim)':>16} {'destino (n/dim)':>16}  estado")
    drift = 0
    for name in _COLLECTIONS:
        (na, da), (nb, db) = await _stats(src, name), await _stats(dst, name)
        ok = na == nb >= 0 and da == db
        note = "ok" if ok else ("DIM MISMATCH" if da != db else "COUNT DRIFT")
        drift += 0 if ok else 1
        print(f"{name:<20} {f'{na}/{da}':>16} {f'{nb}/{db}':>16}  {note}")
    print(
        "\nen paridad (conteo y dimensión)"
        if not drift
        else f"\n{drift} colección(es) con drift; verify embedding model/space before sync"
    )
    return 1 if drift else 0


async def _sync_collection(
    name: str, src, dst, *, batch: int, prune: bool, dest_embed,
    source_space: str | None = None, destination_space: str | None = None,
) -> tuple[int, int]:
    try:
        src_col = await src.get_collection(name)
    except Exception as exc:
        raise RuntimeError(f"Missing/unavailable authoritative collection {name}; refusing partial mirror") from exc

    if not source_space or (src_col.metadata or {}).get("embedding_space") != source_space:
        raise RuntimeError(f"{name}: source embedding space is unknown or does not match the declared space")
    if not destination_space or (dest_embed is None and source_space != destination_space):
        raise RuntimeError(f"{name}: vector copy requires identical declared embedding spaces")

    include = ["documents", "metadatas"] if dest_embed else ["documents", "metadatas", "embeddings"]
    data = await _get_all(src_col, include)
    src_ids = data["ids"]
    if src_ids and not dest_embed and not data["embeddings"]:
        raise SystemExit(f"[{name}] origen sin embeddings y sin STANDBY_EMBED_* para re-calcular")

    dst_col = await dst.get_or_create_collection(name, metadata={"embedding_space": destination_space})
    if (dst_col.metadata or {}).get("embedding_space") != destination_space:
        raise RuntimeError(f"{name}: destination embedding space is unknown or incompatible")
    dst_data = await _get_all(dst_col, ["documents", "metadatas"])
    dst_ids = set(dst_data["ids"])
    dst_values = {
        did: (dst_data["documents"][i], dst_data["metadatas"][i] or {})
        for i, did in enumerate(dst_data["ids"])
    }

    # Copy current metadata too (confirmation, expiry, provenance), even if ID exists.
    new_idx = [i for i, did in enumerate(src_ids)
               if dst_values.get(did) != (data["documents"][i], data["metadatas"][i] or {})]
    ids = [src_ids[i] for i in new_idx]
    docs = [data["documents"][i] for i in new_idx]
    metas = [data["metadatas"][i] for i in new_idx]
    src_embs = None if dest_embed else [data["embeddings"][i] for i in new_idx]

    for i in range(0, len(ids), batch):
        sl = slice(i, i + batch)
        embs = await asyncio.to_thread(dest_embed, docs[sl]) if dest_embed else src_embs[sl]
        if len(embs) != len(ids[sl]):
            raise RuntimeError(f"{name}: embedder returned the wrong number of vectors")
        existing = await dst_col.get(include=["embeddings"], limit=1)
        vectors = existing.get("embeddings")
        if vectors is not None and len(vectors) and any(len(e) != len(vectors[0]) for e in embs):
            raise RuntimeError(f"{name}: incompatible destination dimensions")
        # Chroma upsert merges metadata. Remove replaced rows so expired/quarantine
        # fields absent from the authority cannot survive a confirmation update.
        replacing = [did for did in ids[sl] if did in dst_ids]
        if replacing:
            await dst_col.delete(ids=replacing)
        await dst_col.upsert(
            ids=ids[sl],
            documents=docs[sl] or None,
            metadatas=metas[sl] or None,
            embeddings=embs,
        )

    pruned = 0
    if prune:
        stale = list(dst_ids - set(src_ids))
        for i in range(0, len(stale), batch):
            await dst_col.delete(ids=stale[i : i + batch])
        pruned = len(stale)
    logger.info(
        "sync_collection_done",
        collection=name,
        upserted=len(ids),
        pruned=pruned,
        reembed=bool(dest_embed),
    )
    return (len(ids), pruned)


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--batch", type=int, default=128)
    ap.add_argument("--authority", choices=("local", "standby"), required=True)
    ap.add_argument("--replica-fenced", action="store_true")
    ap.add_argument("--source-quiesced", action="store_true")
    ap.add_argument("--source-space", help="verified embedding_space metadata of every source collection")
    ap.add_argument("--destination-space", help="verified embedding_space metadata and destination embedder identity")
    ap.add_argument("--bidirectional", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--check", action="store_true", help="compare counts/dimensions only; not a content parity proof")
    args = ap.parse_args()
    if args.bidirectional:
        ap.error("bilateral merge is unsafe; choose the current --authority")
    if args.batch < 1 or args.batch > _PAGE:
        ap.error(f"--batch must be between 1 and {_PAGE}")
    if not args.check and not (args.replica_fenced and args.source_quiesced):
        ap.error("writes require --replica-fenced and --source-quiesced")
    if not args.check and not (args.source_space and args.destination_space):
        ap.error("writes require --source-space and --destination-space; unknown embedding spaces cannot be copied")

    # El cliente con auth (Chroma Cloud) DEBE crearse primero: chromadb comparte
    # estado de auth a nivel de proceso, y si el primer AsyncHttpClient es el local
    # sin auth, el segundo (Cloud) hereda "sin token" → "Permission denied".
    env_client = await _client_from_env()
    settings_client = await _client_from_settings()

    if args.check:
        src, dst = (env_client, settings_client) if args.authority == "standby" else (settings_client, env_client)
        return await _check(src, dst)

    # (origen, destino, embedder-del-destino)
    fwd = (settings_client, env_client, _standby_embedder())  # local → Cloud (re-embed HF)
    rev = (env_client, settings_client, _embedding_function())  # Cloud → local (re-embed settings)
    passes = [rev] if args.authority == "standby" else [fwd]

    total_up = total_pruned = 0
    for src, dst, dest_embed in passes:
        for name in _COLLECTIONS:
            up, pr = await _sync_collection(
                name, src, dst, batch=args.batch, prune=True, dest_embed=dest_embed,
                source_space=args.source_space, destination_space=args.destination_space,
            )
            total_up += up
            total_pruned += pr

    mode = f"authority={args.authority}"
    logger.info("sync_chroma_standby_done", upserted=total_up, pruned=total_pruned, mode=mode)
    print(f"OK — {mode} — upserted {total_up}, pruned {total_pruned}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
