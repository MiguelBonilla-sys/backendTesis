"""
KnowledgeUpdaterService — cierra el loop de aprendizaje continuo.

Responsabilidades:
- ingest_from_analysis(): auto-ingesta post-scan para s_risk >= AUTO_INGEST_THRESHOLD
- ingest_confirmed_feedback(): ingesta un feedback confirmado por admin
- process_feedback_queue(): procesa cola pendiente (feedback.ingested=false)
- ingest_legit_baseline(): aprendizaje incremental del baseline USB (T10) — ver abajo

Los 3 ChromaDB collections se actualizan por cada análisis confirmado:
  email_embeddings ← contexto completo del análisis + veredicto
  idn_patterns     ← chars confusables + dominio unicode + ataque
  ti_signals       ← scores TI + razones (completa el collection vacío)

Baseline institucional (usb_baseline, T10): el diseño original (T9) requería
autorización formal de TI de la USB para un import batch de ~2 meses de
buzones históricos — sigue disponible en scripts/ingest_usb_baseline.py para
quien la consiga, pero deja de ser bloqueante. En su lugar, ``ingest_legit_baseline``
aprende de forma incremental: cuando /analyze_eml procesa un correo que el
propio usuario ya decidió analizar y ese correo resulta institucional (dominio
USB, SPF+DKIM pass, veredicto LEGITIMATE de muy baja incertidumbre — ver
``is_usb_baseline_candidate``), su patrón estructural (sin PII) se agrega al
mismo baseline. No es un import de datos de terceros: es la traza de un
análisis que el estudiante mismo pidió.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime

from core.constants import (
    COLLECTION_BASELINE,
    COLLECTION_EMAIL,
    COLLECTION_IDN,
    COLLECTION_TI,
    INSTITUTIONAL_DOMAIN_SUFFIXES,
    USB_BASELINE_MAX_RISK,
)
from core.logger import get_logger
from core.redaction import redact
from models.chromadb_client import delete_document, upsert_documents
from models.database import execute, fetch

logger = get_logger(__name__)

AUTO_INGEST_THRESHOLD: float = 0.90  # s_risk >= this → tier "auto_high"

# --------------------------------------------------------------------------- #
# Baseline USB — anonimización pre-embedding (T10)
# Compartido con scripts/ingest_usb_baseline.py (import batch, T9) para que
# ambas rutas de ingesta produzcan el mismo formato de documento/metadata.
# --------------------------------------------------------------------------- #

# Patrones de PII a tokenizar en el asunto (orden importa)
_PII_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"[\w.\-]+@[\w.\-]+\.\w+"), "<EMAIL>"),
    (re.compile(r"\$\s?[\d.,]+|\b[\d.,]+\s?(COP|USD|pesos)\b", re.I), "<MONTO>"),
    (re.compile(r"\b\d{6,}\b"), "<NUM>"),  # documentos, IDs largos
    (re.compile(r"\b\d{1,3}([.\s]\d{3})+\b"), "<NUM>"),  # montos con separador
    (re.compile(r"\b\d+\b"), "<N>"),  # números sueltos
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


def build_baseline_document(parsed) -> tuple[str, str, dict]:
    """
    Construye el documento anonimizado + metadata para ``usb_baseline``.
    Devuelve (doc_id, texto_embebible, metadata). NO incluye cuerpo ni PII.
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
        "ingested_at": datetime.now(UTC).isoformat(),
    }
    return doc_id, doc, metadata


def is_usb_baseline_candidate(
    *, sender_domain: str, spf_pass: bool, dkim_pass: bool, verdict: str, s_risk: float
) -> bool:
    """
    Gate estricto del baseline incremental (T10): dominio institucional propio
    (no basta con estar en TRUSTED_DOMAIN_SUFFIXES, que incluye proveedores
    externos) + SPF y DKIM pass (no solo el From: — evita spoofing) + veredicto
    LEGITIMATE de muy baja incertidumbre. Cualquier condición que falle excluye
    el correo del baseline; no degrada a un gate más laxo.
    """
    if verdict != "LEGITIMATE" or s_risk > USB_BASELINE_MAX_RISK:
        return False
    if not (spf_pass and dkim_pass):
        return False
    domain = (sender_domain or "").lower()
    return any(
        domain == suffix or domain.endswith(f".{suffix}")
        for suffix in INSTITUTIONAL_DOMAIN_SUFFIXES
    )


def context_header(
    *,
    verdict: str,
    domain: str,
    domain_unicode: str = "",
    impersonates: str = "",
    source: str = "",
) -> str:
    """Línea de contexto que se antepone a cada chunk del RAG — ancla de
    recuperación para el canal denso y el BM25 (contextual retrieval,
    versión determinista, sin LLM). Ej.:
    ``[ctx verdict=PHISHING domain=pаypal impersonates=paypal.com source=seed_corpus]``
    """
    dec = domain_unicode or domain
    parts = [f"verdict={verdict}", f"domain={dec}"]
    if impersonates and impersonates != dec:
        parts.append(f"impersonates={impersonates}")
    if source:
        parts.append(f"source={source}")
    return "[ctx " + " ".join(parts) + "]"


def _invalidate_bm25() -> None:
    """Fuerza el rebuild del índice BM25 tras un cambio de corpus de alto valor
    (feedback admin, purga de FP). La auto-ingesta se apoya en el TTL."""
    try:
        from data_pipeline.hybrid_retrieval import hybrid_retriever

        hybrid_retriever.invalidate()
    except Exception:  # noqa: BLE001 — best-effort
        pass


def tier_for(verdict: str, s_risk: float) -> str:
    """Tier de confianza del documento auto-ingestado (peso en SOURCE_WEIGHTS)."""
    if s_risk >= AUTO_INGEST_THRESHOLD:
        return "auto_high"
    if verdict == "SUSPICIOUS" or 0.40 <= s_risk < AUTO_INGEST_THRESHOLD:
        return "auto_mid"
    return "auto_low"


class KnowledgeUpdaterService:
    """Stateless service — todos los métodos son async, seguros para llamadas concurrentes."""

    async def ingest_from_analysis(
        self,
        *,
        url: str,
        domain: str,
        verdict: str,
        s_risk: float,
        s_idn_local: float,
        s_ti: float,
        s_llm: float,
        confusable_chars: list[str],
        domain_unicode: str,
        homograph_ratio: float,
        visual_similarity: float,
        is_mixed_script: bool,
        reasons: list[str],
        llm_reason: str,
        s_vt: float = 0.0,
        s_urlscan: float = 0.0,
        s_gsb: float = 0.0,
        incident_id: str | None = None,
        auto_ingested: bool = True,
        tier: str = "auto_ingest",
    ) -> None:
        """
        Ingesta resultado de análisis en los 3 ChromaDB collections.

        Con ``LEARN_FROM_EVERY_ANALYSIS`` se llama para *cada* análisis; ``tier``
        (``auto_high``/``auto_mid``/``auto_low``, ver ``tier_for``) fija el peso
        del documento en el re-ranking por procedencia. ``auto_ingested=False``
        → ``source="admin_confirmed"`` (feedback humano, peso 1.0).
        Falla silenciosamente para no interrumpir el pipeline principal.
        """
        ts = datetime.now(UTC).isoformat()
        source = tier if auto_ingested else "admin_confirmed"
        doc_id = incident_id or hashlib.sha256(f"{url}:{ts}".encode()).hexdigest()[:32]

        confusable_str = (
            ", ".join(repr(c) for c in confusable_chars) if confusable_chars else "none"
        )
        ctx = context_header(
            verdict=verdict,
            domain=domain,
            domain_unicode=domain_unicode,
            source=source,
        )

        email_doc = (
            f"{ctx}\n"
            f"{verdict} URL: {url}\n"
            f"Domain: {domain_unicode or domain}\n"
            f"s_risk={s_risk:.2f}, s_idn={s_idn_local:.2f}, "
            f"s_ti={s_ti:.2f}, s_llm={s_llm:.2f}\n"
            f"Reasons: {'; '.join(reasons)}\n"
            f"LLM analysis: {llm_reason}"
        )

        idn_doc = (
            f"{ctx}\n"
            f"IDN attack pattern — {verdict}\n"
            f"Domain: {domain_unicode or domain} (original: {domain})\n"
            f"Confusable chars: {confusable_str}\n"
            f"homograph_ratio={homograph_ratio:.2f}, "
            f"visual_similarity={visual_similarity:.2f}, "
            f"mixed_script={is_mixed_script}"
        )

        ti_doc = (
            f"{ctx}\n"
            f"TI signals — {verdict}: {domain}\n"
            f"VirusTotal={s_vt:.2f}, URLScan={s_urlscan:.2f}, "
            f"GSB={s_gsb:.2f}, aggregate={s_ti:.2f}\n"
            f"Reasons: {'; '.join(reasons)}"
        )

        metadata: dict[str, str] = {
            "verdict": verdict,
            "domain": domain,
            "s_risk": str(round(s_risk, 4)),
            "source": source,
            "ingested_at": ts,
        }

        try:
            await upsert_documents(
                COLLECTION_EMAIL,
                ids=[f"email_{doc_id}"],
                documents=[redact(email_doc)],
                metadatas=[metadata],
            )
            await upsert_documents(
                COLLECTION_IDN,
                ids=[f"idn_{doc_id}"],
                documents=[redact(idn_doc)],
                metadatas=[
                    {
                        **metadata,
                        "is_mixed_script": str(is_mixed_script),
                        "homograph_ratio": str(homograph_ratio),
                    }
                ],
            )
            await upsert_documents(
                COLLECTION_TI,
                ids=[f"ti_{doc_id}"],
                documents=[redact(ti_doc)],
                metadatas=[
                    {
                        **metadata,
                        "s_vt": str(s_vt),
                        "s_urlscan": str(s_urlscan),
                        "s_gsb": str(s_gsb),
                    }
                ],
            )
            logger.info(
                "knowledge_ingested",
                doc_id=doc_id,
                verdict=verdict,
                s_risk=round(s_risk, 4),
                source=source,
            )
        except Exception as exc:
            logger.error("knowledge_ingest_failed", doc_id=doc_id, error=str(exc))
            if not auto_ingested:
                raise

    async def ingest_confirmed_feedback(
        self,
        *,
        feedback_id: str,
        incident_id: str,
        confirmed_verdict: str,
        note: str | None,
        url: str,
        domain: str,
        domain_unicode: str,
        confusable_chars: list[str],
        homograph_ratio: float,
        visual_similarity: float,
        is_mixed_script: bool,
        s_risk: float,
        s_idn_local: float,
        s_ti: float,
        s_llm: float,
        s_vt: float,
        s_urlscan: float,
        s_gsb: float,
        reasons: list[str],
        llm_reason: str,
    ) -> None:
        """Ingesta feedback confirmado por admin y marca el registro como procesado."""
        if confirmed_verdict == "LEGITIMATE":
            await self.purge_incident_documents(incident_id)
            await execute(
                "UPDATE feedback SET ingested = true, ingested_at = NOW() WHERE id = $1",
                feedback_id,
            )
            return
        await self.ingest_from_analysis(
            url=url,
            domain=domain,
            verdict=confirmed_verdict,
            s_risk=s_risk,
            s_idn_local=s_idn_local,
            s_ti=s_ti,
            s_llm=s_llm,
            confusable_chars=confusable_chars,
            domain_unicode=domain_unicode,
            homograph_ratio=homograph_ratio,
            visual_similarity=visual_similarity,
            is_mixed_script=is_mixed_script,
            reasons=reasons,
            llm_reason=llm_reason,
            s_vt=s_vt,
            s_urlscan=s_urlscan,
            s_gsb=s_gsb,
            incident_id=incident_id,
            auto_ingested=False,
        )

        await execute(
            "UPDATE feedback SET ingested = true, ingested_at = NOW() WHERE id = $1",
            feedback_id,
        )
        _invalidate_bm25()

    async def ingest_legit_baseline(self, parsed) -> None:
        """
        Aprendizaje incremental del baseline USB (T10) — llamar solo cuando
        ``is_usb_baseline_candidate`` ya dio True sobre el mismo correo.

        ``parsed`` es un ``utils.email_parser.ParsedEmail`` (o cualquier objeto
        con los mismos atributos). Reutiliza ``build_baseline_document``, el
        mismo formato que produce el import batch (scripts/ingest_usb_baseline.py)
        para que ambas rutas convivan en la colección sin duplicar lógica.
        Falla silenciosamente — no debe interrumpir la respuesta de /analyze_eml.
        """
        doc_id, doc, metadata = build_baseline_document(parsed)
        try:
            await upsert_documents(
                COLLECTION_BASELINE,
                ids=[f"baseline_{doc_id}"],
                documents=[doc],
                metadatas=[metadata],
            )
            logger.info(
                "usb_baseline_ingested",
                sender_domain=parsed.sender_domain,
                incremental=True,
            )
        except Exception as exc:
            logger.error("usb_baseline_ingest_failed", error=str(exc))

    async def purge_incident_documents(self, incident_id: str) -> None:
        """
        Remueve los documentos de un incidente de las 3 ChromaDB collections.

        Anti-envenenamiento (T11): cuando un admin marca un incidente como
        falso positivo (confirmed_verdict=LEGITIMATE), sus documentos
        auto-ingestados dejan de existir como contexto RAG — un FP en el
        conocimiento refuerza futuros FPs sobre dominios parecidos.

        Los doc ids siguen la convención ``{email|idn|ti}_{incident_id}``
        (``ingest_from_analysis`` con ``incident_id`` explícito).
        ``delete_document`` ignora ids inexistentes, por lo que es seguro
        llamarlo para incidentes que nunca fueron auto-ingestados.
        """
        for collection, prefix in (
            (COLLECTION_EMAIL, "email_"),
            (COLLECTION_IDN, "idn_"),
            (COLLECTION_TI, "ti_"),
        ):
            await delete_document(collection, f"{prefix}{incident_id}")
        _invalidate_bm25()
        logger.info("knowledge_purged", incident_id=incident_id)

    async def process_feedback_queue(self, batch_size: int = 50) -> int:
        """
        Procesa la cola de feedback pendiente (ingested=false).
        Llamar desde lifespan startup o tarea periódica.
        Retorna el número de registros procesados.
        """
        rows = await fetch(
            """
            SELECT f.id, f.incident_id, f.confirmed_verdict, f.note,
                   i.url, i.domain, i.s_risk, i.s_idn, i.s_llm, i.s_ti,
                   i.llm_reason, i.reasons
              FROM feedback f
              JOIN incidents i ON i.id = f.incident_id
             WHERE f.ingested = false
             ORDER BY f.created_at ASC
             LIMIT $1
            """,
            batch_size,
        )

        processed = 0
        for row in rows:
            try:
                reasons_list: list[str] = row["reasons"] if isinstance(row["reasons"], list) else []
                await self.ingest_confirmed_feedback(
                    feedback_id=str(row["id"]),
                    incident_id=str(row["incident_id"]),
                    confirmed_verdict=row["confirmed_verdict"],
                    note=row["note"],
                    url=row["url"],
                    domain=row["domain"],
                    domain_unicode=row["domain"],
                    confusable_chars=[],
                    homograph_ratio=0.0,
                    visual_similarity=0.0,
                    is_mixed_script=False,
                    s_risk=float(row["s_risk"]),
                    s_idn_local=float(row["s_idn"]),
                    s_ti=float(row["s_ti"]),
                    s_llm=float(row["s_llm"]),
                    s_vt=0.0,
                    s_urlscan=0.0,
                    s_gsb=0.0,
                    reasons=reasons_list,
                    llm_reason=row["llm_reason"] or "",
                )
                processed += 1
            except Exception as exc:
                logger.error(
                    "feedback_queue_item_failed",
                    feedback_id=str(row["id"]),
                    error=str(exc),
                )

        if processed:
            logger.info("feedback_queue_processed", count=processed)
        return processed


# Application singleton
knowledge_updater = KnowledgeUpdaterService()
