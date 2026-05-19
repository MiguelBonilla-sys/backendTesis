"""
Analyze router — POST /api/v1/analyze

Orquesta el pipeline de 3 agentes:
  IDN Agent + ThreatIntel (paralelo) → LLM Agent → Fusion Agent

El resultado se persiste en PostgreSQL de forma asíncrona (fire-and-forget)
para no añadir latencia al response del cliente.
"""

from __future__ import annotations

import asyncio
import json
import time

from fastapi import APIRouter, Depends, HTTPException, status

from agents.fusion_agent import fusion_agent
from agents.idn_agent import idn_agent
from agents.llm_agent import llm_agent
from auth.dependencies import require_auth
from core.exceptions import IDNAnalysisError, LLMTimeoutError, ThreatIntelError
from core.logger import get_logger
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
    request: AnalyzeRequest,
    current_user: dict = Depends(require_auth),
) -> AnalyzeResponse:
    """
    Pipeline de análisis IDN:

    1. Extrae el dominio de la URL.
    2. IDN Agent + ThreatIntel en paralelo (asyncio.gather).
    3. LLM Agent recibe el contexto IDN como pista adicional.
    4. Fusion Agent combina los tres scores → S_risk, veredicto, SHAP.
    5. Persiste el incidente en PostgreSQL (fire-and-forget).
    """
    t_start = time.perf_counter()
    url = str(request.url)

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
            email_body_snippet=request.email_body_snippet,
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
            email_hash=request.email_hash,
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
        _persist_incident(response, request.email_hash),
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
