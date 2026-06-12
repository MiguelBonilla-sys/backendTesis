"""
Ingesta del baseline benigno institucional USB (T10 — docs/tasks.md).

Toma un directorio de archivos .eml (export de ~2 meses de correo legítimo
USB), los ANONIMIZA y los embebe en la colección ChromaDB ``usb_baseline``
con ``source=institutional_baseline``. El LLMAgent recupera estos patrones
como contexto de "correo USB normal" para reducir falsos positivos.

⚠️  BLOQUEANTE LEGAL (T9): ejecutar solo con autorización formal del área de
    TI de la USB (responsable del tratamiento, Ley 1581/2012). La
    anonimización de abajo es condición necesaria, no suficiente — la
    autorización institucional debe estar documentada en la tesis.

Anonimización pre-embedding (lo que se CONSERVA vs lo que se DESCARTA):
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
import hashlib
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from core.constants import COLLECTION_BASELINE
from core.logger import get_logger
from utils.email_parser import parse_eml

logger = get_logger(__name__)

# Patrones de PII a tokenizar en el asunto (orden importa)
_PII_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"[\w.\-]+@[\w.\-]+\.\w+"), "<EMAIL>"),
    (re.compile(r"\$\s?[\d.,]+|\b[\d.,]+\s?(COP|USD|pesos)\b", re.I), "<MONTO>"),
    (re.compile(r"\b\d{6,}\b"), "<NUM>"),                  # documentos, IDs largos
    (re.compile(r"\b\d{1,3}([.\s]\d{3})+\b"), "<NUM>"),    # montos con separador
    (re.compile(r"\b\d+\b"), "<N>"),                       # números sueltos
]

# Nombres propios: heurística conservadora — secuencias de 2+ palabras
# capitalizadas se reemplazan (saluda a "Juan Pérez" → <NOMBRE>).
_PROPER_NAME = re.compile(r"\b([A-ZÁÉÍÓÚÑ][a-záéíóúñ]+(?:\s+[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+)+)")


def anonymize_subject(subject: str) -> str:
    """Normaliza el asunto a un patrón estructural sin PII."""
    s = _PROPER_NAME.sub("<NOMBRE>", subject)
    for pattern, token in _PII_PATTERNS:
        s = pattern.sub(token, s)
    return s.strip()[:200]


def url_domains(urls: list[str]) -> list[str]:
    """Extrae solo los dominios de las URLs — descarta paths con tokens."""
    domains: list[str] = []
    for u in urls:
        m = re.search(r"https?://([^/]+)", u)
        if m:
            domains.append(m.group(1).lower())
    # dedup preservando orden
    seen: set[str] = set()
    return [d for d in domains if not (d in seen or seen.add(d))]


def build_baseline_document(parsed) -> tuple[str, dict]:
    """
    Construye el documento anonimizado + metadata para ``usb_baseline``.
    Devuelve (texto_embebible, metadata). NO incluye cuerpo ni PII.
    """
    domains = url_domains(parsed.urls)
    doc = (
        f"LEGITIMATE institutional email\n"
        f"Sender domain: {parsed.sender_domain}\n"
        f"Subject pattern: {anonymize_subject(parsed.subject)}\n"
        f"SPF: {'pass' if parsed.spf_pass else 'fail'}, "
        f"DKIM: {'pass' if parsed.dkim_pass else 'fail'}, "
        f"sender/return-path mismatch: {parsed.sender_domain_mismatch}\n"
        f"URL domains: {', '.join(domains) if domains else 'none'}\n"
        f"Attachments: {len(parsed.attachment_names)}"
    )
    # doc_id estable por hash del contenido anonimizado (no del original)
    doc_id = hashlib.sha256(doc.encode()).hexdigest()[:32]
    metadata = {
        "verdict": "LEGITIMATE",
        "source": "institutional_baseline",
        "sender_domain": parsed.sender_domain,
        "spf_pass": str(parsed.spf_pass),
        "dkim_pass": str(parsed.dkim_pass),
        "ingested_at": datetime.now(timezone.utc).isoformat(),
    }
    return doc_id, doc, metadata


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
    group.add_argument("--dry-run", action="store_true", default=True,
                       help="Anonimiza y muestra sin escribir (default)")
    group.add_argument("--apply", action="store_true",
                       help="Escribe en ChromaDB (requiere autorización T9)")
    args = parser.parse_args()

    apply = args.apply  # --apply tiene precedencia sobre el default dry-run
    count = asyncio.run(ingest_directory(Path(args.dir), apply=apply))
    return 0 if count > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
