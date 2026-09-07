"""Sincroniza / verifica las 5 colecciones de ChromaDB entre la instancia
autoritativa (Coolify, DBs locales) y la standby free-tier (Chroma Cloud), para
que Render tenga el MISMO corpus RAG que Coolify.

Regla: se seedea UNA sola vez (Coolify) y el resto es COPIA, no un re-seed
independiente — los feeds tipo OpenPhish cambian a diario, un re-seed daría otro corpus.

Dos modos según el embedder de cada lado:
- **re-embed** (por defecto si hay `STANDBY_EMBED_*`): copia `documents` + `metadatas`
  y RE-CALCULA los vectores con el embedder del destino. Necesario cuando origen y
  destino usan stacks distintos del mismo modelo — p. ej. Coolify sirve
  embeddinggemma por Ollama (GGUF) y Render por HuggingFace: los vectores NO son
  intercambiables (cos ~0.6 para el mismo texto).
- **vector-copy** (si no hay `STANDBY_EMBED_*`): copia también `embeddings` tal cual.
  Solo válido si ambos lados usan exactamente el mismo endpoint de embeddings.

`.get()` paginado de a 300 (límite del free tier). Upsert-only salvo `--prune`.

Direcciones:
    (default)    settings (Chroma local)  ->  STANDBY_CHROMA_* (Cloud)
    --reverse    STANDBY_CHROMA_* (Cloud) ->  settings (hidratar un Chroma local nuevo)
    --check      no escribe: conteo + dimensión de ambos lados

Env:
    STANDBY_CHROMA_HOST / _PORT / _API_KEY / _TENANT / _DATABASE   (destino Chroma)
    STANDBY_EMBED_PROVIDER=hf          (re-embed; default hf si hay STANDBY_EMBED_MODEL)
    STANDBY_EMBED_MODEL=google/embeddinggemma-300m
    STANDBY_EMBED_BASE_URL=https://router.huggingface.co/hf-inference/models
    STANDBY_EMBED_API_KEY=hf_...

Uso:  python -m scripts.sync_chroma_standby [--check] [--reverse] [--prune]
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
        else f"\n{drift} colección(es) con drift → correr el sync (o re-seedear si es DIM MISMATCH)"
    )
    return 1 if drift else 0


async def _sync_collection(
    name: str, src, dst, *, batch: int, prune: bool, dest_embed
) -> tuple[int, int]:
    try:
        src_col = await src.get_collection(name)
    except Exception:
        logger.info("sync_skip_missing_source", collection=name)
        return (0, 0)

    include = ["documents", "metadatas"] if dest_embed else ["documents", "metadatas", "embeddings"]
    data = await _get_all(src_col, include)
    ids, docs, metas = data["ids"], data["documents"], data["metadatas"]
    if not ids:
        return (0, 0)
    if not dest_embed and not data["embeddings"]:
        raise SystemExit(f"[{name}] origen sin embeddings y sin STANDBY_EMBED_* para re-calcular")

    dst_col = await dst.get_or_create_collection(name)

    pruned = 0
    if prune:
        stale = list(set((await _get_all(dst_col, []))["ids"]) - set(ids))
        for i in range(0, len(stale), batch):
            await dst_col.delete(ids=stale[i : i + batch])
        pruned = len(stale)

    for i in range(0, len(ids), batch):
        sl = slice(i, i + batch)
        embs = (
            await asyncio.to_thread(dest_embed, docs[sl]) if dest_embed else data["embeddings"][sl]
        )
        await dst_col.upsert(
            ids=ids[sl],
            documents=docs[sl] or None,
            metadatas=metas[sl] or None,
            embeddings=embs,
        )

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
    ap.add_argument("--prune", action="store_true", help="borrar en destino ids ausentes en origen")
    ap.add_argument("--reverse", action="store_true", help="Cloud → local (hidratar dev)")
    ap.add_argument(
        "--bidirectional",
        action="store_true",
        help="merge en ambos sentidos (upsert-only, sin prune) — para failback",
    )
    ap.add_argument("--check", action="store_true", help="solo comparar conteo/dim, no escribir")
    args = ap.parse_args()

    if args.bidirectional and args.prune:
        raise SystemExit("--bidirectional es incompatible con --prune (borraría lo del otro lado)")

    # El cliente con auth (Chroma Cloud) DEBE crearse primero: chromadb comparte
    # estado de auth a nivel de proceso, y si el primer AsyncHttpClient es el local
    # sin auth, el segundo (Cloud) hereda "sin token" → "Permission denied".
    env_client = await _client_from_env()
    settings_client = await _client_from_settings()

    if args.check:
        src, dst = (env_client, settings_client) if args.reverse else (settings_client, env_client)
        return await _check(src, dst)

    # (origen, destino, embedder-del-destino)
    fwd = (settings_client, env_client, _standby_embedder())  # local → Cloud (re-embed HF)
    rev = (env_client, settings_client, _embedding_function())  # Cloud → local (re-embed settings)
    passes = [rev] if args.reverse else ([fwd, rev] if args.bidirectional else [fwd])

    total_up = total_pruned = 0
    for src, dst, dest_embed in passes:
        for name in _COLLECTIONS:
            up, pr = await _sync_collection(
                name, src, dst, batch=args.batch, prune=args.prune, dest_embed=dest_embed
            )
            total_up += up
            total_pruned += pr

    mode = "bidireccional" if args.bidirectional else ("reverse" if args.reverse else "forward")
    logger.info("sync_chroma_standby_done", upserted=total_up, pruned=total_pruned, mode=mode)
    print(f"OK — {mode} — upserted {total_up}, pruned {total_pruned}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
