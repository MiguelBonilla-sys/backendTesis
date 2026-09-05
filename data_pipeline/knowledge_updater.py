"""
KnowledgeUpdaterService — cierra el loop de aprendizaje continuo.

Responsabilidades:
- ingest_from_analysis(): auto-ingesta post-scan para s_risk >= AUTO_INGEST_THRESHOLD
- ingest_confirmed_feedback(): ingesta un feedback confirmado por admin
- process_feedback_queue(): procesa cola pendiente (feedback.ingested=false)

Los 3 ChromaDB collections se actualizan por cada análisis confirmado:
  email_embeddings ← contexto completo del análisis + veredicto
  idn_patterns     ← chars confusables + dominio unicode + ataque
  ti_signals       ← scores TI + razones (completa el collection vacío)
"""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from core.constants import COLLECTION_EMAIL, COLLECTION_IDN, COLLECTION_TI
from core.logger import get_logger
from core.redaction import redact
from models.chromadb_client import delete_document, upsert_documents
from models.database import execute, fetch

logger = get_logger(__name__)

AUTO_INGEST_THRESHOLD: float = 0.90  # s_risk >= this → tier "auto_high"


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
        doc_id = incident_id or hashlib.sha256(
            f"{url}:{ts}".encode()
        ).hexdigest()[:32]

        confusable_str = (
            ", ".join(repr(c) for c in confusable_chars) if confusable_chars else "none"
        )
        ctx = context_header(
            verdict=verdict, domain=domain, domain_unicode=domain_unicode,
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
                metadatas=[{
                    **metadata,
                    "is_mixed_script": str(is_mixed_script),
                    "homograph_ratio": str(homograph_ratio),
                }],
            )
            await upsert_documents(
                COLLECTION_TI,
                ids=[f"ti_{doc_id}"],
                documents=[redact(ti_doc)],
                metadatas=[{
                    **metadata,
                    "s_vt": str(s_vt),
                    "s_urlscan": str(s_urlscan),
                    "s_gsb": str(s_gsb),
                }],
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
                reasons_list: list[str] = (
                    row["reasons"] if isinstance(row["reasons"], list) else []
                )
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
