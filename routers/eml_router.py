"""
EML router — POST /api/v1/analyze_eml  |  POST /api/v1/report

Endpoints de análisis de archivo .eml completo y reporte manual de URLs.
Separado de analyze_router para mantener cada router < 500 líneas (T8).
Comparte el pipeline por-URL vía services.analysis._analyze_single_url_for_email.

Rate limiting:
  /analyze_eml: 10 req/min/IP
  /report:      20 req/min/IP
"""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status

from auth.dependencies import require_auth
from core.logger import get_logger
from core.rate_limiter import check_rate_limit, get_client_ip
from schemas.analyze import (
    AnalyzeResponse,
    EmailAnalysisResponse,
    EmailSignals,
    ReportRequest,
    ReportResponse,
)
from services.analysis import _aggregate_email_reasons, _analyze_single_url_for_email
from services.persistence import _persist_manual_report
from utils.email_parser import ParsedEmail, parse_eml

logger = get_logger(__name__)
router = APIRouter(tags=["analyze"])

_EML_MAX_BYTES = 10 * 1024 * 1024   # 10 MB hard cap
_EML_MAX_URLS = 10                   # máximo de URLs únicas a analizar por email


# --------------------------------------------------------------------------- #
# POST /analyze_eml — análisis completo de archivo .eml
# --------------------------------------------------------------------------- #

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


# --------------------------------------------------------------------------- #
# POST /report — reporte manual de URLs (Asset Register A09)
# --------------------------------------------------------------------------- #

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
