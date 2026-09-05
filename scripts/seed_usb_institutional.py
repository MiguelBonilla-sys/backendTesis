"""
Seed institucional USB — llena el RAG con lo que es *legítimo* de la USB Bogotá
y con los homógrafos de más alto valor para un ataque dirigido a la USB.

Dos colecciones:

  usb_baseline  ← el grafo de dominios/servicios legítimos de la USB (público,
                  sin PII, sin .eml → NO depende del bloqueante legal T9).
  idn_patterns  ← homógrafos IDN de `usbbog` / `usb` generados con el catálogo
                  TR#39 — el atacante dirigido a la USB registraría algo así.

Fuente de los dominios: sitio institucional público (usbbog.edu.co y portales).

Uso:
    python -m scripts.seed_usb_institutional            # dry-run
    python -m scripts.seed_usb_institutional --apply    # ingesta (ChromaDB activo)
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import sys
from pathlib import Path

from core.config import settings
from core.constants import COLLECTION_BASELINE, COLLECTION_IDN
from core.logger import get_logger
from data_pipeline.knowledge_updater import context_header
from scripts.generate_idn_corpus import build_reverse_catalog, make_homograph

logger = get_logger(__name__)

# Grafo legítimo USB — dominios institucionales + servicios externos usados.
USB_LEGIT_DOMAINS: dict[str, str] = {
    "usbbog.edu.co": "Sitio principal — Universidad de San Buenaventura, sede Bogotá",
    "www.usbbog.edu.co": "Portal público institucional",
    "academia.usbbog.edu.co": "Portal de servicios / plataforma ASIS (académico)",
    "usbbogedu.sharepoint.com": "SharePoint institucional (Sistema de Gestión de Calidad)",
    "usbcali.edu.co": "USB sede Cali (dominio hermano legítimo)",
    "usbmed.edu.co": "USB sede Medellín (dominio hermano legítimo)",
    "usb.edu.co": "USB Colombia (dominio corporativo)",
    "outlook.office365.com": "Correo institucional USB (Microsoft 365)",
    "usbbog-my.sharepoint.com": "OneDrive institucional USB",
}
USB_EMAIL_DOMAIN = "usbbog.edu.co"
USB_HOMOGRAPH_TARGETS = ["usbbog.edu.co", "usb.edu.co", "academia.usbbog.edu.co"]


def _id(prefix: str, text: str) -> str:
    return f"{prefix}_{hashlib.sha256(text.encode()).hexdigest()[:32]}"


def build_baseline_docs() -> tuple[list[str], list[str], list[dict]]:
    ids, docs, metas = [], [], []
    for domain, desc in USB_LEGIT_DOMAINS.items():
        ctx = context_header(
            verdict="LEGITIMATE", domain=domain, source="institutional_baseline",
        )
        doc = (
            f"{ctx}\n"
            f"LEGITIMATE USB institutional resource\n"
            f"Domain: {domain}\n"
            f"Role: {desc}\n"
            f"Institutional email domain: {USB_EMAIL_DOMAIN} "
            f"(pattern: <user>@{USB_EMAIL_DOMAIN})\n"
            f"Any lookalike of this domain using non-Latin characters is an attack."
        )
        ids.append(_id("usb_legit", doc))
        docs.append(doc)
        metas.append({
            "source": "institutional_baseline", "verdict": "LEGITIMATE",
            "domain": domain,
        })
    return ids, docs, metas


def build_usb_homograph_docs(n_per_target: int, seed: int) -> tuple[list, list, list]:
    import random

    from agents.confusables_loader import load_confusables_catalog

    rng = random.Random(seed)
    catalog = load_confusables_catalog(Path(settings.CONFUSABLES_PATH))
    reverse = build_reverse_catalog(catalog)
    ids, docs, metas = [], [], []
    for target in USB_HOMOGRAPH_TARGETS:
        made = 0
        for _ in range(n_per_target * 20):  # margen para descartes
            case = make_homograph(target, reverse, subs_per_domain=1, rng=rng)
            if not case or case["domain"] == case["base"]:
                continue
            subs = "; ".join(
                f"{s['latin']}→{s['confusable']} ({s['script']})"
                for s in case["substitutions"]
            )
            ctx = context_header(
                verdict="PHISHING", domain=case["domain"],
                domain_unicode=case["unicode"], impersonates=case["base"],
                source="seed_corpus",
            )
            doc = (
                f"{ctx}\n"
                f"IDN homograph attack pattern targeting the USB — PHISHING\n"
                f"Domain: {case['unicode']} (punycode: {case['domain']}, "
                f"impersonates USB domain: {case['base']})\n"
                f"Confusable substitutions: {subs}\n"
                f"High-value: a credential-phishing page for USB staff/students."
            )
            ids.append(_id("usb_idn", doc))
            docs.append(doc)
            metas.append({
                "source": "seed_corpus", "verdict": "PHISHING",
                "domain": case["domain"], "synthetic": "true", "base": case["base"],
            })
            made += 1
            if made >= n_per_target:
                break
    return ids, docs, metas


async def run(n_homograph: int, seed: int, apply: bool) -> int:
    b_ids, b_docs, b_metas = build_baseline_docs()
    h_ids, h_docs, h_metas = build_usb_homograph_docs(n_homograph, seed)

    print("\nSeed institucional USB:")
    print(f"  {COLLECTION_BASELINE}: {len(b_docs)} recursos legítimos")
    print(f"  {COLLECTION_IDN}: {len(h_docs)} homógrafos de dominios USB")
    print(f"\n--- ejemplo legítimo ---\n{b_docs[0]}")
    if h_docs:
        print(f"\n--- ejemplo homógrafo USB ---\n{h_docs[0]}")

    if not apply:
        print("\nDRY-RUN: nada escrito. Usá --apply para ingestar.")
        return len(b_docs) + len(h_docs)

    from models.chromadb_client import init_chromadb, upsert_documents

    await init_chromadb()
    await upsert_documents(COLLECTION_BASELINE, ids=b_ids, documents=b_docs,
                           metadatas=b_metas)
    if h_docs:
        await upsert_documents(COLLECTION_IDN, ids=h_ids, documents=h_docs,
                               metadatas=h_metas)
    total = len(b_docs) + len(h_docs)
    logger.info("usb_institutional_seeded", total=total)
    print(f"\nIngestados {total} documentos.")
    return total


def main() -> int:
    p = argparse.ArgumentParser(description="Seed institucional USB para el RAG")
    p.add_argument("--n-homograph", type=int, default=10, help="homógrafos por dominio USB")
    p.add_argument("--seed", type=int, default=42)
    grp = p.add_mutually_exclusive_group()
    grp.add_argument("--dry-run", action="store_true", default=True)
    grp.add_argument("--apply", action="store_true")
    args = p.parse_args()
    total = asyncio.run(run(args.n_homograph, args.seed, args.apply))
    return 0 if total > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
