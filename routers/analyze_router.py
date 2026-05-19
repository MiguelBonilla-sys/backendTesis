"""
Analyze router — POST /api/v1/analyze  |  POST /api/v1/analyze_email  |  POST /api/v1/report

Orquesta el pipeline de 3 agentes:
  IDN Agent + ThreatIntel (paralelo) → LLM Agent → Fusion Agent

El resultado se persiste en PostgreSQL de forma asíncrona (fire-and-forget)
para no añadir latencia al response del cliente.

Rate limiting (D.5.6):
  CA-2 — /analyze + /analyze_email: 100 req/min/IP
  /report: 20 req/min/IP
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from agents.fusion_agent import fusion_agent
from agents.idn_agent import idn_agent
from agents.llm_agent import llm_agent
from auth.dependencies import require_auth
from core.exceptions import IDNAnalysisError, LLMTimeoutError, ThreatIntelError
from core.logger import get_logger
from core.rate_limiter import check_rate_limit, get_client_ip
from data_pipeline.threat_intel import threat_intel_service
from schemas.analyze import AnalyzeRequest, AnalyzeResponse
from utils.url_parser import extract_domain

logger = get_logger(__name__)
router = APIRouter(tags=["analyze"])


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Analiza una URL en busca de phishing IDN",
    description=(
        "Ejecuta el pipeline completo: IDN Agent → ThreatIntel → LLM Agent → "
        "Fusion Agent y retorna un veredicto con score de riesgo y explicación SHAP. "
        "Requiere JWT válido en el header Authorization: Bearer <token>."
    ),
)
async def analyze_url(
    http_request: Request,
    body: AnalyzeRequest,
    current_user: dict = Depends(require_auth),
) -> AnalyzeResponse:
    """
    Pipeline de análisis IDN:

    1. Rate limiting: 100 req/min por IP (CA-2).
    2. Extrae el dominio de la URL.
    3. IDN Agent + ThreatIntel en paralelo (asyncio.gather).
    4. LLM Agent recibe el contexto IDN como pista adicional.
    5. Fusion Agent combina los tres scores → S_risk, veredicto, SHAP.
    6. Persiste el incidente en PostgreSQL (fire-and-forget).
    """
    # Rate limiting: 100 req/min por IP (CA-2)
    client_ip = get_client_ip(http_request)
    await check_rate_limit(f"rl:analyze:{client_ip}", limit=100, window_seconds=60)

    t_start = time.perf_counter()
    url = str(body.url)

    # ------------------------------------------------------------------ #
    # Paso 0: extracción de dominio
    # ------------------------------------------------------------------ #
    try:
        domain = extract_domain(url)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"No se puede extraer el dominio de la URL: {exc}",
        ) from exc

    logger.info(
        "analyze_start",
        url=url,
        domain=domain,
        user=current_user.get("sub"),
    )

    # ------------------------------------------------------------------ #
    # Paso 1: IDN Agent + ThreatIntel en paralelo
    # ------------------------------------------------------------------ #
    try:
        idn_result, ti_result = await asyncio.gather(
            idn_agent.analyze(url),
            threat_intel_service.analyze(url, domain),
        )
    except IDNAnalysisError as exc:
        logger.error("idn_analysis_failed", url=url, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"IDN analysis failed: {exc.message}",
        ) from exc
    except ThreatIntelError as exc:
        logger.error("threat_intel_failed", url=url, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Threat intelligence lookup failed: {exc.message}",
        ) from exc
    except Exception as exc:
        logger.error("pipeline_error_stage1", url=url, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Analysis pipeline error at stage 1",
        ) from exc

    # ------------------------------------------------------------------ #
    # Paso 2: LLM Agent (usa resumen IDN como contexto adicional)
    # ------------------------------------------------------------------ #
    idn_summary = (
        f"IDN score={idn_result.s_idn_local:.2f}, "
        f"mixed_script={idn_result.is_mixed_script}, "
        f"homograph_ratio={idn_result.homograph_ratio:.2f}"
    )

    try:
        s_llm, llm_reason = await llm_agent.analyze(
            url=url,
            domain=domain,
            email_body_snippet=body.email_body_snippet,
            idn_result_summary=idn_summary,
        )
    except LLMTimeoutError as exc:
        # Graceful degradation: fallback score 0.5 (neutral) as per spec
        logger.warning(
            "llm_timeout_fallback",
            url=url,
            error=str(exc),
        )
        s_llm = 0.5
        llm_reason = "LLM timed out — neutral fallback applied"
    except Exception as exc:
        logger.error("pipeline_error_stage2", url=url, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Analysis pipeline error at stage 2 (LLM)",
        ) from exc

    # ------------------------------------------------------------------ #
    # Paso 3: Fusion Agent
    # ------------------------------------------------------------------ #
    try:
        response = await fusion_agent.fuse(
            url=url,
            domain=domain,
            idn_result=idn_result,
            ti_result=ti_result,
            s_llm=s_llm,
            llm_reason=llm_reason,
            start_time=t_start,
            email_hash=body.email_hash,
        )
    except Exception as exc:
        logger.error("pipeline_error_stage3", url=url, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Analysis pipeline error at stage 3 (Fusion)",
        ) from exc

    # ------------------------------------------------------------------ #
    # Paso 4: Persistir incidente (fire-and-forget — no bloquea el response)
    # ------------------------------------------------------------------ #
    asyncio.create_task(
        _persist_incident(response, body.email_hash),
        name=f"persist_{response.request_id}",
    )

    logger.info(
        "analyze_complete",
        url=url,
        verdict=response.verdict,
        s_risk=response.s_risk,
        processing_ms=response.processing_ms,
    )
    return response


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

async def _persist_incident(
    response: AnalyzeResponse,
    email_hash: str | None,
) -> None:
    """Inserta el incidente en PostgreSQL de forma asíncrona."""
    try:
        from models.database import execute  # late import to avoid circular deps

        await execute(
            """
            INSERT INTO incidents (
                id, email_hash, url, domain, verdict,
                s_risk, s_idn, s_llm, s_ti,
                llm_reason, shap_contributions, created_at
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8, $9,
                $10, $11, $12
            ) ON CONFLICT (id) DO NOTHING
            """,
            response.request_id,
            email_hash or "",
            response.url,
            response.domain,
            response.verdict,
            response.s_risk,
            response.agent_scores.s_idn,
            response.agent_scores.s_llm,
            response.agent_scores.s_ti,
            response.llm_reason,
            json.dumps(response.shap_explanation.feature_contributions),
            response.timestamp,
        )
        logger.info("incident_persisted", request_id=response.request_id)
    except Exception as exc:
        # Log but never propagate — DB failure must not affect the API response
        logger.error(
            "persist_incident_failed",
            request_id=response.request_id,
            error=str(exc),
        )


# --------------------------------------------------------------------------- #
# POST /analyze_email — alias of /analyze (Asset Register A09)
# --------------------------------------------------------------------------- #

@router.post(
    "/analyze_email",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Alias de /analyze para compatibilidad con Asset Register A09",
    description=(
        "Endpoint alternativo equivalente a POST /analyze. "
        "Aplica el mismo rate limit (CA-2: 100 req/min/IP) y el mismo pipeline completo."
    ),
)
async def analyze_email_url(
    http_request: Request,
    body: AnalyzeRequest,
    current_user: dict = Depends(require_auth),
) -> AnalyzeResponse:
    """Alias de /analyze — delega directamente al handler principal."""
    client_ip = get_client_ip(http_request)
    await check_rate_limit(f"rl:analyze:{client_ip}", limit=100, window_seconds=60)
    return await analyze_url(http_request, body, current_user)


# --------------------------------------------------------------------------- #
# POST /report — reporte manual de URLs (Asset Register A09)
# --------------------------------------------------------------------------- #

class ReportRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    reporter_note: str = Field(default="", max_length=500)
    reported_verdict: Literal["PHISHING", "SUSPICIOUS"] = "PHISHING"


class ReportResponse(BaseModel):
    report_id: str
    url: str
    reported_verdict: str
    message: str
    timestamp: datetime


@router.post(
    "/report",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Reporte manual de URL como phishing/suspicious",
    description=(
        "Registra una URL como phishing o suspicious de forma manual. "
        "El reporte se persiste en incidents y audit_log. "
        "Asset A09: /report endpoint. Rate limit: 20 req/min/IP."
    ),
)
async def report_url(
    http_request: Request,
    body: ReportRequest,
    current_user: dict = Depends(require_auth),
) -> ReportResponse:
    """
    Reporte manual de URL como phishing/suspicious.
    Registrado en incidents table con s_risk=1.0 (PHISHING) o 0.5 (SUSPICIOUS).
    """
    client_ip = get_client_ip(http_request)
    await check_rate_limit(f"rl:report:{client_ip}", limit=20, window_seconds=60)

    report_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    # Persist as manual incident — fire-and-forget to avoid blocking the response
    asyncio.create_task(
        _persist_manual_report(
            report_id=report_id,
            url=body.url,
            verdict=body.reported_verdict,
            reporter=current_user.get("sub", "unknown"),
            note=body.reporter_note,
            timestamp=now,
        ),
        name=f"persist_report_{report_id}",
    )

    logger.info(
        "manual_report",
        report_id=report_id,
        url=body.url,
        verdict=body.reported_verdict,
        reporter=current_user.get("sub"),
    )

    return ReportResponse(
        report_id=report_id,
        url=body.url,
        reported_verdict=body.reported_verdict,
        message="Report received and queued for processing",
        timestamp=now,
    )


async def _persist_manual_report(
    report_id: str,
    url: str,
    verdict: str,
    reporter: str,
    note: str,
    timestamp: datetime,
) -> None:
    """Guarda reporte manual en incidents table."""
    try:
        from models.database import execute  # late import to avoid circular deps

        domain = extract_domain(url) if url.startswith("http") else url
        await execute(
            """
            INSERT INTO incidents (
                id, email_hash, url, domain, verdict,
                s_risk, s_idn, s_llm, s_ti,
                llm_reason, shap_contributions, analyzed_by, created_at
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8, $9,
                $10, $11, $12, $13
            ) ON CONFLICT (id) DO NOTHING
            """,
            report_id,
            "",
            url,
            domain,
            verdict,
            1.0 if verdict == "PHISHING" else 0.5,
            0.0,
            0.0,
            0.0,
            f"Manual report: {note}" if note else "Manual report",
            json.dumps({}),
            reporter,
            timestamp,
        )
        logger.info("manual_report_persisted", report_id=report_id)
    except Exception as exc:
        logger.error("persist_manual_report_failed", report_id=report_id, error=str(exc))
