"""
Incidents router — GET /api/v1/incidents, GET /api/v1/incidents/{incident_id}
                    GET /api/v1/metrics/summary, GET /api/v1/settings

Lista y consulta incidentes almacenados en PostgreSQL.
Dashboard read-only — no acciones de bloqueo en v1.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import TypeVar
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, ConfigDict

from auth.dependencies import require_admin
from data_pipeline.knowledge_updater import knowledge_updater
from schemas.feedback import FeedbackRequest, FeedbackResponse
from core.constants import ALPHA, BETA, GAMMA, THETA, W_GSB, W_URLSCAN, W_VT
from core.exceptions import DatabaseError
from core.logger import get_logger
from core.rate_limiter import check_rate_limit, get_client_ip
from models.database import execute, fetch, fetchrow
from schemas.incidents import IncidentListResponse, IncidentRecord

_T = TypeVar("_T")


class MetricsSummary(BaseModel):
    total_analyses_today: int
    phishing_today: int
    suspicious_today: int
    safe_today: int
    avg_latency_ms: float
    cache_hit_rate: float


class FusionSettings(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    alpha: float
    beta: float
    gamma: float
    theta: float
    lambda_: float = Field(alias="lambda")
    ti_vt_weight: float
    ti_urlscan_weight: float
    ti_gsb_weight: float

logger = get_logger(__name__)
router = APIRouter(tags=["incidents"])


# --------------------------------------------------------------------------- #
# GET /incidents
# --------------------------------------------------------------------------- #

@router.get(
    "/incidents",
    response_model=IncidentListResponse,
    summary="Lista incidentes con paginación",
    description=(
        "Retorna incidentes ordenados por fecha descendente. "
        "Filtro opcional por verdict. Dashboard read-only — sin acciones de bloqueo en v1."
    ),
)
async def list_incidents(
    http_request: Request,
    page: int = Query(default=1, ge=1, description="Número de página (base 1)"),
    page_size: int = Query(default=20, ge=1, le=100, description="Registros por página"),
    verdict: str | None = Query(
        default=None,
        pattern="^(PHISHING|LEGITIMATE|SUSPICIOUS)$",
        description="Filtrar por veredicto",
    ),
    current_user: dict = Depends(require_admin),
) -> IncidentListResponse:
    """
    Lista incidentes almacenados en PostgreSQL.

    Soporta paginación (page / page_size) y filtro opcional por verdict.
    Los resultados se ordenan por `created_at DESC`.
    Rate limit: 30 req/min por IP (CA-4).
    """
    # Rate limiting: 30 req/min por IP (CA-4)
    client_ip = get_client_ip(http_request)
    await check_rate_limit(f"rl:incidents:{client_ip}", limit=30, window_seconds=60)

    offset = (page - 1) * page_size

    try:
        # ------------------------------------------------------------------ #
        # Total count
        # ------------------------------------------------------------------ #
        if verdict:
            count_row = await fetchrow(
                "SELECT COUNT(*) AS count FROM incidents WHERE verdict = $1",
                verdict,
            )
        else:
            count_row = await fetchrow("SELECT COUNT(*) AS count FROM incidents")

        total: int = int(count_row["count"]) if count_row else 0

        # ------------------------------------------------------------------ #
        # Paginated rows
        # ------------------------------------------------------------------ #
        _select = """
            SELECT id, email_hash, url, domain, verdict,
                   s_risk, s_idn, s_llm, s_ti,
                   llm_reason, shap_contributions, created_at,
                   email_subject, email_from, email_to, all_urls, reasons,
                   email_body_html, email_images, email_attachments
            FROM incidents
        """

        if verdict:
            rows = await fetch(
                f"{_select} WHERE verdict = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                verdict,
                page_size,
                offset,
            )
        else:
            rows = await fetch(
                f"{_select} ORDER BY created_at DESC LIMIT $1 OFFSET $2",
                page_size,
                offset,
            )

        items = [_row_to_record(row) for row in (rows or [])]

        return IncidentListResponse(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
        )

    except HTTPException:
        raise
    except DatabaseError as exc:
        logger.error("list_incidents_db_error", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error while retrieving incidents",
        ) from exc
    except Exception as exc:
        logger.error("list_incidents_error", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve incidents",
        ) from exc


# --------------------------------------------------------------------------- #
# GET /incidents/{incident_id}
# --------------------------------------------------------------------------- #

@router.get(
    "/incidents/{incident_id}",
    response_model=IncidentRecord,
    summary="Obtiene un incidente por ID",
)
async def get_incident(
    incident_id: str,
    current_user: dict = Depends(require_admin),
) -> IncidentRecord:
    """
    Retorna un único incidente identificado por su UUID.

    Responde 404 si el incidente no existe.
    """
    try:
        row = await fetchrow(
            """
            SELECT id, email_hash, url, domain, verdict,
                   s_risk, s_idn, s_llm, s_ti,
                   llm_reason, shap_contributions, created_at,
                   email_subject, email_from, email_to, all_urls, reasons,
                   email_body_html, email_images, email_attachments
            FROM incidents
            WHERE id = $1
            """,
            incident_id,
        )

        if not row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident '{incident_id}' not found",
            )

        return _row_to_record(row)

    except HTTPException:
        raise
    except DatabaseError as exc:
        logger.error("get_incident_db_error", incident_id=incident_id, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error while retrieving incident",
        ) from exc
    except Exception as exc:
        logger.error("get_incident_error", incident_id=incident_id, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve incident",
        ) from exc


# --------------------------------------------------------------------------- #
# GET /metrics/summary
# --------------------------------------------------------------------------- #

@router.get(
    "/metrics/summary",
    response_model=MetricsSummary,
    summary="Métricas de análisis del día actual",
)
async def get_metrics_summary(
    current_user: dict = Depends(require_admin),
) -> MetricsSummary:
    """Retorna totales de hoy agrupados por veredicto."""
    try:
        today_start = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        rows = await fetch(
            """
            SELECT verdict, COUNT(*) AS cnt
            FROM incidents
            WHERE created_at >= $1
            GROUP BY verdict
            """,
            today_start,
        )
        counts: dict[str, int] = {r["verdict"]: int(r["cnt"]) for r in (rows or [])}
        total = sum(counts.values())
        return MetricsSummary(
            total_analyses_today=total,
            phishing_today=counts.get("PHISHING", 0),
            suspicious_today=counts.get("SUSPICIOUS", 0),
            safe_today=counts.get("LEGITIMATE", 0),
            avg_latency_ms=0.0,
            cache_hit_rate=0.0,
        )
    except Exception as exc:
        logger.error("metrics_summary_error", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve metrics",
        ) from exc


# --------------------------------------------------------------------------- #
# GET /settings
# --------------------------------------------------------------------------- #

@router.get(
    "/settings",
    response_model=FusionSettings,
    response_model_by_alias=True,
    summary="Parámetros actuales del modelo de fusión",
)
async def get_settings(
    current_user: dict = Depends(require_admin),
) -> FusionSettings:
    """Retorna los parámetros de fusión activos (alpha, gamma, theta, etc.)."""
    return FusionSettings(
        alpha=ALPHA,
        beta=BETA,
        gamma=GAMMA,
        theta=THETA,
        lambda_=0.30,
        ti_vt_weight=W_VT,
        ti_urlscan_weight=W_URLSCAN,
        ti_gsb_weight=W_GSB,
    )


# --------------------------------------------------------------------------- #
# GET /incidents/by_hash/{email_hash}
# --------------------------------------------------------------------------- #

@router.get(
    "/incidents/by_hash/{email_hash}",
    response_model=IncidentListResponse,
    summary="Todos los incidentes de un mismo email (agrupados por email_hash)",
)
async def get_incidents_by_hash(
    http_request: Request,
    email_hash: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    current_user: dict = Depends(require_admin),
) -> IncidentListResponse:
    """
    Retorna todos los incidentes que comparten el mismo email_hash.
    Útil para ver todos los veredictos de URLs dentro de un mismo email
    capturado por la extensión.
    """
    client_ip = get_client_ip(http_request)
    await check_rate_limit(f"rl:incidents:{client_ip}", limit=30, window_seconds=60)

    offset = (page - 1) * page_size

    try:
        count_row = await fetchrow(
            "SELECT COUNT(*) AS count FROM incidents WHERE email_hash = $1",
            email_hash,
        )
        total: int = int(count_row["count"]) if count_row else 0

        rows = await fetch(
            """
            SELECT id, email_hash, url, domain, verdict,
                   s_risk, s_idn, s_llm, s_ti,
                   llm_reason, shap_contributions, created_at,
                   email_subject, email_from, email_to, all_urls, reasons,
                   email_body_html, email_images, email_attachments
            FROM incidents
            WHERE email_hash = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            """,
            email_hash,
            page_size,
            offset,
        )

        items = [_row_to_record(row) for row in (rows or [])]
        return IncidentListResponse(items=items, total=total, page=page, page_size=page_size)

    except Exception as exc:
        logger.error("incidents_by_hash_error", email_hash=email_hash, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve incidents by hash",
        ) from exc


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _row_to_record(row: dict) -> IncidentRecord:
    """Convierte una fila asyncpg en un IncidentRecord Pydantic."""
    def _parse_jsonb(val: object, default: _T) -> _T:
        if isinstance(val, str):
            return json.loads(val) if val else default  # type: ignore[return-value]
        return val if val is not None else default  # type: ignore[return-value]

    shap_contributions: dict[str, float] = _parse_jsonb(row["shap_contributions"], {})
    all_urls: list[str] = _parse_jsonb(row.get("all_urls"), [])
    reasons: list[str] = _parse_jsonb(row.get("reasons"), [])
    email_images: list[str] = _parse_jsonb(row.get("email_images"), [])
    email_attachments: list[str] = _parse_jsonb(row.get("email_attachments"), [])

    return IncidentRecord(
        id=str(row["id"]),
        email_hash=row["email_hash"] or "",
        url=row["url"],
        domain=row["domain"],
        verdict=row["verdict"],
        s_risk=float(row["s_risk"]),
        s_idn=float(row["s_idn"]),
        s_llm=float(row["s_llm"]),
        s_ti=float(row["s_ti"]),
        llm_reason=row["llm_reason"] or "",
        shap_contributions=shap_contributions,
        created_at=row["created_at"],
        email_subject=row.get("email_subject") or "",
        email_from=row.get("email_from") or "",
        email_to=row.get("email_to") or "",
        all_urls=all_urls,
        reasons=reasons,
        email_body_html=row.get("email_body_html") or "",
        email_images=email_images,
        email_attachments=email_attachments,
    )


# ---------------------------------------------------------------------------
# Admin feedback endpoint — confirm or correct a verdict
# ---------------------------------------------------------------------------

@router.post(
    "/incidents/{incident_id}/feedback",
    response_model=FeedbackResponse,
    summary="Confirm or correct an incident verdict (admin only)",
)
async def submit_feedback(
    incident_id: UUID,
    body: FeedbackRequest,
    request: Request,
    current_user=Depends(require_admin),
) -> FeedbackResponse:
    """
    Admin confirms or corrects a verdict. Confirmed PHISHING verdicts trigger
    immediate ChromaDB ingestion so future RAG queries benefit from the pattern.
    Other verdicts are queued for batch ingestion via process_feedback_queue().
    """
    await check_rate_limit(f"rl:feedback:{get_client_ip(request)}", limit=30, window_seconds=60)

    incident = await fetchrow(
        "SELECT id, url, domain, verdict, s_risk, s_idn, s_llm, s_ti, llm_reason, reasons "
        "FROM incidents WHERE id = $1",
        incident_id,
    )
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    feedback_id = await fetchrow(
        """
        INSERT INTO feedback (incident_id, confirmed_verdict, confirmed_by, note)
        VALUES ($1, $2, $3, $4)
        RETURNING id
        """,
        incident_id,
        body.confirmed_verdict,
        getattr(current_user, "id", None),
        body.note,
    )

    ingested = False
    if body.confirmed_verdict == "LEGITIMATE":
        # Falso positivo confirmado (T11): purgar los documentos auto-ingestados
        # del incidente en el mismo flujo — un FP en el RAG refuerza futuros FPs.
        try:
            await knowledge_updater.purge_incident_documents(str(incident_id))
            await execute(
                "UPDATE feedback SET ingested = true, ingested_at = NOW() WHERE id = $1",
                feedback_id["id"],
            )
            ingested = True
        except Exception as exc:
            logger.warning(
                "feedback_purge_failed", incident_id=str(incident_id), error=str(exc)
            )
        return FeedbackResponse(
            feedback_id=feedback_id["id"],
            incident_id=incident_id,
            confirmed_verdict=body.confirmed_verdict,
            ingested=ingested,
            message=(
                "False positive confirmed — incident purged from knowledge base"
                if ingested
                else "False positive confirmed — knowledge base purge failed (queued)"
            ),
        )

    if body.confirmed_verdict == "PHISHING":
        try:
            reasons_list: list[str] = (
                incident["reasons"]
                if isinstance(incident["reasons"], list)
                else []
            )
            asyncio.create_task(
                knowledge_updater.ingest_confirmed_feedback(
                    feedback_id=str(feedback_id["id"]),
                    incident_id=str(incident_id),
                    confirmed_verdict=body.confirmed_verdict,
                    note=body.note,
                    url=incident["url"],
                    domain=incident["domain"],
                    domain_unicode=incident["domain"],
                    confusable_chars=[],
                    homograph_ratio=0.0,
                    visual_similarity=0.0,
                    is_mixed_script=False,
                    s_risk=float(incident["s_risk"]),
                    s_idn_local=float(incident["s_idn"]),
                    s_ti=float(incident["s_ti"]),
                    s_llm=float(incident["s_llm"]),
                    s_vt=0.0,
                    s_urlscan=0.0,
                    s_gsb=0.0,
                    reasons=reasons_list,
                    llm_reason=incident["llm_reason"] or "",
                ),
                name=f"feedback_ingest_{incident_id}",
            )
            ingested = True
        except Exception as exc:
            logger.warning("feedback_ingest_failed", incident_id=str(incident_id), error=str(exc))

    return FeedbackResponse(
        feedback_id=feedback_id["id"],
        incident_id=incident_id,
        confirmed_verdict=body.confirmed_verdict,
        ingested=ingested,
        message=(
            "Verdict confirmed and ingested into knowledge base"
            if ingested
            else "Verdict confirmed and queued for knowledge base ingestion"
        ),
    )
