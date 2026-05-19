"""
Incidents router — GET /api/v1/incidents, GET /api/v1/incidents/{incident_id}

Lista y consulta incidentes almacenados en PostgreSQL.
Dashboard read-only — no acciones de bloqueo en v1.
"""

from __future__ import annotations

import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from auth.dependencies import require_admin
from core.exceptions import DatabaseError
from core.logger import get_logger
from core.rate_limiter import check_rate_limit, get_client_ip
from models.database import fetch, fetchrow
from schemas.incidents import IncidentListResponse, IncidentRecord

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
    await check_rate_limit(f"rl:incidents:{get_client_ip(http_request)}", limit=30, window_seconds=60)

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
                   llm_reason, shap_contributions, created_at
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
                   llm_reason, shap_contributions, created_at
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
# Helpers
# --------------------------------------------------------------------------- #

def _row_to_record(row: dict) -> IncidentRecord:
    """Convierte una fila asyncpg en un IncidentRecord Pydantic."""
    raw_shap = row["shap_contributions"]
    if isinstance(raw_shap, str):
        shap_contributions: dict[str, float] = json.loads(raw_shap or "{}")
    elif isinstance(raw_shap, dict):
        shap_contributions = raw_shap
    else:
        shap_contributions = {}

    created_at: datetime = row["created_at"]

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
        created_at=created_at,
    )
