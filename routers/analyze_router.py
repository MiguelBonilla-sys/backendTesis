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

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from pydantic import BaseModel, Field

from agents.fusion_agent import fusion_agent
from agents.hf_agent import hf_agent
from agents.idn_agent import idn_agent
from agents.llm_agent import llm_agent
from auth.dependencies import require_auth
from core.exceptions import IDNAnalysisError, LLMTimeoutError, ThreatIntelError
from core.logger import get_logger
from core.rate_limiter import check_rate_limit, get_client_ip
from data_pipeline.threat_intel import threat_intel_service
from schemas.analyze import AnalyzeRequest, AnalyzeResponse, EmailAnalysisResponse, EmailSignals
from utils.email_parser import ParsedEmail, parse_eml
from utils.url_parser import extract_domain, extract_effective_domain

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
    # CDN/storage abuse: resolve effective domain from filename
    # (e.g. storage.googleapis.com/b/evil.com.html → evil.com)
    # ------------------------------------------------------------------ #
    try:
        domain = extract_effective_domain(url)
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
    # Paso 1: IDN Agent + ThreatIntel + HF Agent en paralelo
    # ------------------------------------------------------------------ #
    try:
        idn_result, ti_result, s_hf = await asyncio.gather(
            idn_agent.analyze(url),
            threat_intel_service.analyze(url, domain),
            hf_agent.analyze(url, body.email_body_snippet),
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
            s_hf=s_hf,
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
# POST /analyze_eml — análisis completo de archivo .eml
# --------------------------------------------------------------------------- #

_EML_MAX_BYTES = 10 * 1024 * 1024   # 10 MB hard cap
_EML_MAX_URLS = 10                   # máximo de URLs únicas a analizar por email


@router.post(
    "/analyze_eml",
    response_model=EmailAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analiza un archivo .eml completo en busca de phishing",
    description=(
        "Parsea un archivo .eml, extrae todas las URLs, señales del remitente, "
        "SPF/DKIM y patrones de urgencia, y ejecuta el pipeline completo "
        "(IDN + ThreatIntel + LLM + Fusion) sobre cada URL. "
        "El dominio efectivo se resuelve automáticamente para abusos de CDN "
        "(ej. storage.googleapis.com hosting malware). "
        "Rate limit: 10 req/min/IP."
    ),
)
async def analyze_eml_file(
    http_request: Request,
    file: UploadFile = File(..., description="Archivo .eml a analizar"),
    current_user: dict = Depends(require_auth),
) -> EmailAnalysisResponse:
    """
    Pipeline de análisis de email completo:

    1. Rate limiting: 10 req/min por IP.
    2. Parsea el .eml → extrae URLs, cabeceras, señales de urgencia, adjuntos.
    3. Resuelve dominio efectivo por URL (CDN abuse detection).
    4. Ejecuta IDN + TI + LLM + Fusion en paralelo para hasta 10 URLs únicas.
    5. Agrega veredicto email: max(s_risk) de todas las URLs analizadas.
    """
    client_ip = get_client_ip(http_request)
    await check_rate_limit(f"rl:analyze_eml:{client_ip}", limit=10, window_seconds=60)

    if not (file.filename or "").lower().endswith(".eml"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Only .eml files are supported. Received: " + (file.filename or "unknown"),
        )

    t_start = time.perf_counter()
    content = await file.read()

    if len(content) > _EML_MAX_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large (max {_EML_MAX_BYTES // 1024 // 1024} MB)",
        )

    try:
        parsed: ParsedEmail = parse_eml(content)
    except Exception as exc:
        logger.error("eml_parse_failed", filename=file.filename, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to parse .eml file: {exc}",
        ) from exc

    email_signals = EmailSignals(
        subject=parsed.subject,
        sender=parsed.sender,
        sender_domain=parsed.sender_domain,
        return_path_domain=parsed.return_path_domain,
        sender_domain_mismatch=parsed.sender_domain_mismatch,
        has_suspicious_attachments=parsed.has_suspicious_attachments,
        is_urgent=parsed.is_urgent,
        urgency_score=parsed.urgency_score,
        spf_pass=parsed.spf_pass,
        dkim_pass=parsed.dkim_pass,
        extracted_urls=parsed.urls[:_EML_MAX_URLS],
        attachment_names=parsed.attachment_names,
    )

    # Limit and log unique URLs
    unique_urls = parsed.urls[:_EML_MAX_URLS]
    logger.info(
        "eml_analysis_start",
        email_hash=parsed.email_hash,
        subject=parsed.subject[:80],
        url_count=len(unique_urls),
        is_urgent=parsed.is_urgent,
        sender_domain=parsed.sender_domain,
    )

    # Run full pipeline on all URLs concurrently
    email_body_snippet = parsed.body_text[:500] if parsed.body_text else None
    url_tasks = [
        _analyze_single_url_for_email(
            url=url,
            email_signals=email_signals,
            email_hash=parsed.email_hash,
            email_body_snippet=email_body_snippet,
            t_start=t_start,
        )
        for url in unique_urls
    ]

    raw_results = await asyncio.gather(*url_tasks, return_exceptions=True)
    url_analyses: list[AnalyzeResponse] = [
        r for r in raw_results if isinstance(r, AnalyzeResponse)
    ]

    for i, r in enumerate(raw_results):
        if isinstance(r, Exception):
            logger.warning(
                "eml_url_analysis_failed",
                url=unique_urls[i],
                error=str(r),
            )

    # Compute email-level verdict
    if url_analyses:
        worst = max(url_analyses, key=lambda a: a.s_risk)
        email_s_risk = worst.s_risk
        email_verdict = worst.verdict
    else:
        # No URLs found — derive a partial risk score from email signals only
        email_s_risk = round(min(email_signals.urgency_score * 0.40, 0.39), 4)
        email_verdict = "SUSPICIOUS" if email_s_risk >= 0.40 else "LEGITIMATE"

    email_reasons = _aggregate_email_reasons(url_analyses, email_signals)
    processing_ms = (time.perf_counter() - t_start) * 1000.0

    logger.info(
        "eml_analysis_complete",
        email_hash=parsed.email_hash,
        email_verdict=email_verdict,
        email_s_risk=email_s_risk,
        urls_analyzed=len(url_analyses),
        processing_ms=round(processing_ms, 1),
    )

    return EmailAnalysisResponse(
        email_hash=parsed.email_hash,
        email_signals=email_signals,
        url_analyses=url_analyses,
        email_verdict=email_verdict,
        email_s_risk=email_s_risk,
        reasons=email_reasons,
        processing_ms=round(processing_ms, 1),
        timestamp=datetime.now(timezone.utc),
    )


async def _analyze_single_url_for_email(
    url: str,
    email_signals: EmailSignals,
    email_hash: str,
    email_body_snippet: str | None,
    t_start: float,
) -> AnalyzeResponse:
    """
    Ejecuta el pipeline completo para una URL en el contexto de un email.

    Usa ``extract_effective_domain`` en lugar de ``extract_domain`` para
    resolver abusos de CDN (ej. GCS bucket hosting malware).
    """
    domain = extract_effective_domain(url)

    idn_result, ti_result, s_hf = await asyncio.gather(
        idn_agent.analyze(url),
        threat_intel_service.analyze(url, domain),
        hf_agent.analyze(url, email_body_snippet),
    )

    idn_summary = (
        f"IDN score={idn_result.s_idn_local:.2f}, "
        f"mixed_script={idn_result.is_mixed_script}, "
        f"homograph_ratio={idn_result.homograph_ratio:.2f}"
    )

    try:
        s_llm, llm_reason = await llm_agent.analyze(
            url=url,
            domain=domain,
            email_body_snippet=email_body_snippet,
            idn_result_summary=idn_summary,
        )
    except LLMTimeoutError:
        s_llm = 0.5
        llm_reason = "LLM timed out — neutral fallback applied"

    return await fusion_agent.fuse(
        url=url,
        domain=domain,
        idn_result=idn_result,
        ti_result=ti_result,
        s_llm=s_llm,
        llm_reason=llm_reason,
        start_time=t_start,
        email_hash=email_hash,
        s_hf=s_hf,
        email_signals=email_signals,
    )


def _aggregate_email_reasons(
    url_analyses: list[AnalyzeResponse],
    email_signals: EmailSignals,
) -> list[str]:
    """
    Agrega razones únicas de todas las URLs analizadas más señales del email.

    Elimina duplicados y la razón de fallback "No suspicious indicators detected"
    cuando existen razones concretas de otras URLs.
    """
    seen: set[str] = set()
    reasons: list[str] = []

    for analysis in url_analyses:
        for reason in analysis.reasons:
            if reason not in seen and reason != "No suspicious indicators detected":
                seen.add(reason)
                reasons.append(reason)

    if email_signals.is_urgent and not any("urgency" in r.lower() for r in reasons):
        reasons.append("Email uses urgency/pressure tactics to coerce immediate action")
    if email_signals.sender_domain_mismatch:
        reasons.append(
            f"Sender domain ({email_signals.sender_domain!r}) does not match "
            f"return-path domain ({email_signals.return_path_domain!r})"
        )
    if email_signals.has_suspicious_attachments:
        names = ", ".join(email_signals.attachment_names[:3])
        reasons.append(f"Suspicious attachments detected: {names}")
    if not email_signals.spf_pass and email_signals.sender_domain:
        reasons.append(f"SPF authentication failed for {email_signals.sender_domain!r}")
    if not email_signals.dkim_pass and email_signals.sender_domain:
        reasons.append(
            f"DKIM verification failed for {email_signals.sender_domain!r}"
        )

    if not reasons:
        reasons.append("No suspicious indicators detected in email or URLs")

    return reasons


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
