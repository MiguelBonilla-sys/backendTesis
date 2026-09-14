"""
Ingesta batch histórica del baseline benigno institucional USB (T9/T10 — docs/tasks.md).

Toma un directorio de archivos .eml (export de ~2 meses de correo legítimo
USB), los ANONIMIZA y los embebe en la colección ChromaDB ``usb_baseline``
con ``source=institutional_baseline``. El LLMAgent recupera estos patrones
como contexto de "correo USB normal" para reducir falsos positivos.

Desde 2026-09-14 esta NO es la única forma de poblar ``usb_baseline``: el
pipeline aprende de forma incremental en cada /analyze_eml que cumpla el gate
de ``data_pipeline.knowledge_updater.is_usb_baseline_candidate`` — no requiere
autorización porque solo usa correos que el propio usuario ya pidió analizar.
Este script sigue existiendo para quien consiga la autorización institucional
y quiera acelerar la cobertura del baseline con un backfill histórico.

⚠️  BLOQUEANTE LEGAL (T9) — solo para este import batch: ejecutar únicamente
    con autorización formal del área de TI de la USB (responsable del
    tratamiento, Ley 1581/2012). La anonimización de abajo es condición
    necesaria, no suficiente — la autorización institucional debe estar
    documentada en la tesis.

Anonimización pre-embedding (lo que se CONSERVA vs lo que se DESCARTA) — ver
el detalle en ``data_pipeline.knowledge_updater.build_baseline_document``:
    CONSERVA (patrón estructural, no PII):
      - dominio del remitente (ej. @usbbog.edu.co)
      - categoría de asunto (normalizada: nombres/números/montos → tokens)
      - SPF/DKIM pass, mismatch sender/return-path
      - estructura de URLs (dominios, no paths con tokens)
      - conteo y tipo de adjuntos (no sus nombres)
    DESCARTA (PII):
      - nombres propios, direcciones de correo personales
      - cuerpo del email (nunca se embebe)
      - números de documento, teléfonos, montos

Uso:
    # dry-run: anonimiza y muestra, NO escribe en ChromaDB
    python -m scripts.ingest_usb_baseline --dir ./eml_usb --dry-run

    # ingesta real (requiere ChromaDB activo + autorización T9)
    python -m scripts.ingest_usb_baseline --dir ./eml_usb --apply
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from core.constants import COLLECTION_BASELINE
from core.logger import get_logger
from data_pipeline.knowledge_updater import (
    anonymize_subject,
    build_baseline_document,
    url_domains,
)
from utils.email_parser import parse_eml

logger = get_logger(__name__)

__all__ = [
    "anonymize_subject",
    "build_baseline_document",
    "ingest_directory",
    "main",
    "url_domains",
]


async def ingest_directory(eml_dir: Path, apply: bool) -> int:
    """Anonimiza e ingesta todos los .eml del directorio. Retorna # procesados."""
    eml_files = sorted(eml_dir.glob("*.eml"))
    if not eml_files:
        print(f"Sin archivos .eml en {eml_dir}")
        return 0

    ids: list[str] = []
    docs: list[str] = []
    metas: list[dict] = []

    for path in eml_files:
        try:
            parsed = parse_eml(path.read_bytes())
        except Exception as exc:  # noqa: BLE001 — corpus heterogéneo, registrar y seguir
            logger.warning("baseline_parse_failed", file=path.name, error=str(exc))
            continue
        doc_id, doc, meta = build_baseline_document(parsed)
        ids.append(f"baseline_{doc_id}")
        docs.append(doc)
        metas.append(meta)

    print(f"Anonimizados {len(docs)} correos de {len(eml_files)} archivos.")
    if docs:
        print("\n--- Ejemplo anonimizado (verificación PII) ---")
        print(docs[0])
        print("---------------------------------------------\n")

    if not apply:
        print("DRY-RUN: nada escrito en ChromaDB. Revisá el ejemplo arriba.")
        return len(docs)

    from models.chromadb_client import init_chromadb, upsert_documents

    await init_chromadb()
    # batch en lotes de 100 para no saturar el endpoint de embeddings
    for i in range(0, len(docs), 100):
        await upsert_documents(
            COLLECTION_BASELINE,
            ids=ids[i : i + 100],
            documents=docs[i : i + 100],
            metadatas=metas[i : i + 100],
        )
    logger.info("usb_baseline_ingested", count=len(docs))
    print(f"Ingestados {len(docs)} patrones en la colección '{COLLECTION_BASELINE}'.")
    return len(docs)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ingesta anonimizada del baseline benigno USB (T10)"
    )
    parser.add_argument("--dir", required=True, help="Directorio con archivos .eml")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Anonimiza y muestra sin escribir (default)",
    )
    group.add_argument(
        "--apply", action="store_true", help="Escribe en ChromaDB (requiere autorización T9)"
    )
    args = parser.parse_args()

    apply = args.apply  # --apply tiene precedencia sobre el default dry-run
    count = asyncio.run(ingest_directory(Path(args.dir), apply=apply))
    return 0 if count > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
