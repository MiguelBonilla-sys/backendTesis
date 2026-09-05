"""
Seed inicial de las colecciones ChromaDB con datos de phishing / homografía IDN.

Dos fuentes, proporción documentada en la tesis (spec F1):

  1. Homógrafos IDN **sintéticos** — generados con ``generate_idn_corpus`` a
     partir de top-1M + catálogo TR#39. Metodología estándar (ShamFinder,
     Suzuki et al. 2019) para compensar la escasez de homógrafos IDN reales.
  2. Phishing **real** — feed público de OpenPhish (``feed.txt``, gratis,
     ~500 URLs vigentes). Los dominios ``xn--`` del feed son homógrafos IDN
     reales y van a ``idn_patterns``; el resto alimenta ``email_embeddings``
     y ``ti_signals``.

Los documentos siguen el mismo formato que ``knowledge_updater`` para que la
recuperación RAG sea homogénea. Metadata ``source="seed_corpus"`` → λ=0.8 en el
re-ranking por procedencia (pesa menos que ``admin_confirmed``, más que
``auto_ingest``).

Uso:
    # dry-run (default): genera, descarga, muestra — NO escribe en ChromaDB
    python -m scripts.seed_chromadb --n-idn 500 --phish-limit 300

    # ingesta real (requiere ChromaDB activo)
    python -m scripts.seed_chromadb --n-idn 500 --phish-limit 300 --apply

    # sin red (solo sintéticos)
    python -m scripts.seed_chromadb --n-idn 500 --no-feed --apply
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import sys
from pathlib import Path

import httpx

from core.config import settings
from core.constants import COLLECTION_EMAIL, COLLECTION_IDN, COLLECTION_TI
from core.logger import get_logger
from data_pipeline.knowledge_updater import context_header
from scripts.generate_idn_corpus import generate as generate_idn

logger = get_logger(__name__)

OPENPHISH_FEED = "https://openphish.com/feed.txt"
_SEED_META = {"source": "seed_corpus", "verdict": "PHISHING"}


def _doc_id(prefix: str, text: str) -> str:
    return f"{prefix}_{hashlib.sha256(text.encode()).hexdigest()[:32]}"


def _domain_of(url: str) -> str:
    rest = url.split("://", 1)[-1]
    return rest.split("/", 1)[0].split("@")[-1].lower()


# ---------------------------------------------------------------------------
# Fuente 1 — homógrafos IDN sintéticos
# ---------------------------------------------------------------------------

def build_idn_docs(cases: list[dict]) -> tuple[list[str], list[str], list[dict]]:
    ids, docs, metas = [], [], []
    for c in cases:
        subs = "; ".join(
            f"{s['latin']}→{s['confusable']} ({s['script']})" for s in c["substitutions"]
        )
        ctx = context_header(
            verdict="PHISHING", domain=c["domain"], domain_unicode=c["unicode"],
            impersonates=c["base"], source="seed_corpus",
        )
        doc = (
            f"{ctx}\n"
            f"IDN homograph attack pattern — PHISHING\n"
            f"Domain: {c['unicode']} (punycode: {c['domain']}, impersonates: {c['base']})\n"
            f"Confusable substitutions: {subs}\n"
            f"Technique: cross-script character swap to visually mimic a top-1M domain."
        )
        ids.append(_doc_id("seed_idn", doc))
        docs.append(doc)
        metas.append({**_SEED_META, "domain": c["domain"], "synthetic": "true",
                      "base": c["base"]})
    return ids, docs, metas


# ---------------------------------------------------------------------------
# Fuente 2 — phishing real (OpenPhish)
# ---------------------------------------------------------------------------

async def fetch_openphish(limit: int, timeout: float = 20.0) -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(OPENPHISH_FEED)
            resp.raise_for_status()
    except Exception as exc:  # noqa: BLE001 — sin red se sigue solo con sintéticos
        logger.warning("openphish_fetch_failed", error=str(exc))
        return []
    urls = [ln.strip() for ln in resp.text.splitlines() if ln.strip().startswith("http")]
    logger.info("openphish_fetched", total=len(urls), kept=min(limit, len(urls)))
    return urls[:limit]


def split_phish(urls: list[str]) -> tuple[list[str], list[str]]:
    """Separa homógrafos IDN reales (``xn--``) del resto."""
    idn = [u for u in urls if "xn--" in _domain_of(u)]
    other = [u for u in urls if "xn--" not in _domain_of(u)]
    return idn, other


def build_real_idn_docs(urls: list[str]) -> tuple[list[str], list[str], list[dict]]:
    ids, docs, metas = [], [], []
    for u in urls:
        d = _domain_of(u)
        try:
            unicode_form = d.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            unicode_form = d
        ctx = context_header(
            verdict="PHISHING", domain=d, domain_unicode=unicode_form,
            source="seed_corpus",
        )
        doc = (
            f"{ctx}\n"
            f"IDN homograph attack pattern — PHISHING (real, OpenPhish)\n"
            f"Domain: {unicode_form} (punycode: {d})\n"
            f"URL: {u}\n"
            f"Technique: registered internationalized domain used in a live phishing campaign."
        )
        ids.append(_doc_id("seed_idn", doc))
        docs.append(doc)
        metas.append({**_SEED_META, "domain": d, "synthetic": "false"})
    return ids, docs, metas


def build_phish_url_docs(
    urls: list[str], prefix: str, kind: str
) -> tuple[list[str], list[str], list[dict]]:
    ids, docs, metas = [], [], []
    for u in urls:
        d = _domain_of(u)
        ctx = context_header(verdict="PHISHING", domain=d, source="seed_corpus")
        doc = (
            f"{ctx}\n"
            f"{kind} — PHISHING (real, OpenPhish feed)\n"
            f"URL: {u}\nDomain: {d}\n"
            f"Live phishing URL from a community-verified feed."
        )
        ids.append(_doc_id(prefix, doc))
        docs.append(doc)
        metas.append({**_SEED_META, "domain": d})
    return ids, docs, metas


# ---------------------------------------------------------------------------
# Orquestación
# ---------------------------------------------------------------------------

async def seed(
    n_idn: int, subs_per_domain: int, seed_val: int, phish_limit: int,
    use_feed: bool, apply: bool,
) -> int:
    synth = generate_idn(
        n=n_idn, subs_per_domain=subs_per_domain, seed=seed_val,
        top1m_path=Path(settings.TOP1M_PATH),
        confusables_path=Path(settings.CONFUSABLES_PATH),
    )

    feed_urls = await fetch_openphish(phish_limit) if use_feed else []
    real_idn, real_other = split_phish(feed_urls)

    batches: dict[str, tuple[list[str], list[str], list[dict]]] = {}
    i_ids, i_docs, i_metas = build_idn_docs(synth)
    if real_idn:
        r_ids, r_docs, r_metas = build_real_idn_docs(real_idn)
        i_ids += r_ids
        i_docs += r_docs
        i_metas += r_metas
    batches[COLLECTION_IDN] = (i_ids, i_docs, i_metas)

    if real_other:
        batches[COLLECTION_EMAIL] = build_phish_url_docs(
            real_other, "seed_email", "Phishing email URL pattern"
        )
        batches[COLLECTION_TI] = build_phish_url_docs(
            real_other, "seed_ti", "TI signal — malicious URL"
        )

    total = sum(len(v[1]) for v in batches.values())
    print(f"\nSeed listo — {total} documentos en {len(batches)} colecciones:")
    for coll, (_, docs, _) in batches.items():
        print(f"  {coll}: {len(docs)}")
    print(f"\n  sintéticos IDN: {len(synth)}   "
          f"reales IDN (xn--): {len(real_idn)}   "
          f"reales otros: {len(real_other)}")
    for coll, (_, docs, _) in batches.items():
        if docs:
            print(f"\n--- ejemplo [{coll}] ---\n{docs[0]}")

    if not apply:
        print("\nDRY-RUN: nada escrito en ChromaDB. Usá --apply para ingestar.")
        return total

    from models.chromadb_client import init_chromadb, upsert_documents

    await init_chromadb()
    for coll, (ids, docs, metas) in batches.items():
        for j in range(0, len(docs), 100):
            await upsert_documents(
                coll, ids=ids[j:j + 100], documents=docs[j:j + 100],
                metadatas=metas[j:j + 100],
            )
    logger.info("chromadb_seeded", total=total)
    print(f"\nIngestados {total} documentos con source='seed_corpus'.")
    return total


def main() -> int:
    p = argparse.ArgumentParser(description="Seed ChromaDB con phishing / homografía IDN")
    p.add_argument("--n-idn", type=int, default=500)
    p.add_argument("--subs-per-domain", type=int, default=1)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--phish-limit", type=int, default=300)
    p.add_argument("--no-feed", action="store_true", help="no descargar OpenPhish")
    grp = p.add_mutually_exclusive_group()
    grp.add_argument("--dry-run", action="store_true", default=True)
    grp.add_argument("--apply", action="store_true")
    args = p.parse_args()

    total = asyncio.run(seed(
        n_idn=args.n_idn, subs_per_domain=args.subs_per_domain, seed_val=args.seed,
        phish_limit=args.phish_limit, use_feed=not args.no_feed, apply=args.apply,
    ))
    return 0 if total > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
