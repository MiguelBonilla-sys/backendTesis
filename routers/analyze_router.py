"""
Analyze router — POST /api/v1/analyze  |  /analyze_email  |  /analyze_batch

Orquesta el pipeline de análisis por URL (etapas 1–3 en
services.analysis.run_pipeline_core): IDN + TI + HF + WebProbe (paralelo)
→ LLM → Fusión. El resultado se persiste en PostgreSQL de forma asíncrona
(fire-and-forget) para no añadir latencia al response.

Los endpoints /analyze_eml y /report viven en routers.eml_router.

Rate limiting (D.5.6):
  CA-2 — /analyze + /analyze_email: 100 req/min/IP
  /analyze_batch: 20 req/min/IP
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status

from auth.dependencies import require_auth
from core.exceptions import IDNAnalysisError, ThreatIntelError
from core.logger import get_logger
from core.rate_limiter import check_rate_limit, get_client_ip
from schemas.analyze import (
    AnalyzeEmailRequest,
    AnalyzeEmailResponse,
    AnalyzeRequest,
    AnalyzeResponse,
    BatchAnalyzeRequest,
    BatchAnalyzeResponse,
    EmailSignals,
)
from services.analysis import (
    _aggregate_email_reasons,
    _analyze_single_url_for_email,
    _sender_domain,
    run_pipeline_core,
    schedule_autoingest,
)
from services.persistence import (
    _persist_batch_incident,
    _persist_email_incident,
    _persist_incident,
)
from utils.email_parser import _detect_urgency
from utils.url_parser import extract_effective_domain

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
    # Etapas 1–3: IDN + TI + HF + WebProbe (paralelo) → LLM → Fusión.
    # Orquestación compartida en services.analysis.run_pipeline_core.
    # ------------------------------------------------------------------ #
    try:
        response = await run_pipeline_core(
            url,
            domain,
            t_start=t_start,
            email_hash=body.email_hash,
            email_body_snippet=body.email_body_snippet,
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
        logger.error("pipeline_error", url=url, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Analysis pipeline error",
        ) from exc

    # Persistir (fire-and-forget) + auto-ingesta de alta confianza (T11)
    asyncio.create_task(
        _persist_incident(response, body),
        name=f"persist_{response.request_id}",
    )
    schedule_autoingest(response)

    logger.info(
        "analyze_complete",
        url=url,
        verdict=response.verdict,
        s_risk=response.s_risk,
        processing_ms=response.processing_ms,
    )
    return response


# --------------------------------------------------------------------------- #
# POST /analyze_email — full email content from browser extension
# --------------------------------------------------------------------------- #

@router.post(
    "/analyze_email",
    response_model=AnalyzeEmailResponse,
    status_code=status.HTTP_200_OK,
    summary="Analiza email completo desde la extensión",
    description=(
        "Recibe el email completo capturado por la extensión (subject, from, to, "
        "body HTML, todas las URLs, imágenes). Ejecuta el pipeline completo en "
        "paralelo sobre cada URL (máx 35). Persiste 1 incidente por URL. "
        "Devuelve veredicto por URL + worst + razones agregadas del email."
    ),
)
async def analyze_email(
    http_request: Request,
    body: AnalyzeEmailRequest,
    current_user: dict = Depends(require_auth),
) -> AnalyzeEmailResponse:
    """
    Pipeline de análisis de email completo desde la extensión:

    1. Rate limiting: 30 req/min/IP.
    2. Deduplica URLs (normaliza fragmentos de tracking).
    3. Limita a 35 URLs máximo.
    4. Construye EmailSignals desde el contexto del correo.
    5. Para cada URL → _analyze_single_url_for_email (paralelo con asyncio.gather).
    6. Agregar veredicto email = max(s_risk) de todas las URLs.
    7. Generar razones agregadas (_aggregate_email_reasons).
    8. Persistir cada resultado como incidente individual (fire-and-forget).
    9. Responder con url_analyses[] + worst + reasons + email_verdict.
    """
    client_ip = get_client_ip(http_request)
    await check_rate_limit(f"rl:analyze_email:{client_ip}", limit=30, window_seconds=60)

    t_start = time.perf_counter()

    # Deduplicate: strip fragments so tracking tokens don't double URLs
    seen: set[str] = set()
    unique_urls: list[str] = []
    for u in body.all_urls[:35]:  # respect max 35
        try:
            from urllib.parse import urlparse, urlunparse
            p = urlparse(u)
            norm = urlunparse(p._replace(fragment=""))
        except Exception:
            norm = u
        if norm not in seen:
            seen.add(norm)
            unique_urls.append(u)

    if not unique_urls:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No valid URLs provided",
        )

    # Build EmailSignals from the email context (extension payload)
    _sender_dom = _sender_domain(body.email_from)
    _is_urgent, _urgency_score = _detect_urgency(
        body.email_subject or "", body.email_text_snippet or ""
    )
    _has_suspicious_attachments = any(
        att.lower().endswith(ext)
        for att in (body.attachments or [])
        for ext in (".exe", ".bat", ".cmd", ".scr", ".vbs", ".js", ".ps1",
                    ".zip", ".rar", ".7z", ".iso", ".docm", ".xlsm", ".xlam")
    )
    email_signals = EmailSignals(
        subject=body.email_subject or "",
        sender=body.email_from or "",
        sender_domain=_sender_dom,
        has_suspicious_attachments=_has_suspicious_attachments,
        is_urgent=_is_urgent,
        urgency_score=_urgency_score,
        extracted_urls=unique_urls,
        attachment_names=body.attachments,
    )

    # Run full pipeline for all URLs concurrently
    tasks = [
        _analyze_single_url_for_email(
            url=url,
            email_signals=email_signals,
            email_hash=body.email_hash or "",
            email_body_snippet=body.email_text_snippet,
            t_start=t_start,
        )
        for url in unique_urls
    ]

    raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    url_analyses: list[AnalyzeResponse] = []
    for i, result in enumerate(raw_results):
        if isinstance(result, Exception):
            logger.warning("email_url_failed", url=unique_urls[i], error=str(result))
        else:
            url_analyses.append(result)
            asyncio.create_task(
                _persist_email_incident(result, body),
                name=f"persist_email_{result.request_id}",
            )

    if not url_analyses:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="All URL analyses failed — check that URLs are reachable http/https addresses.",
        )

    worst = max(url_analyses, key=lambda a: a.s_risk)
    email_verdict = worst.verdict
    reasons = _aggregate_email_reasons(url_analyses, email_signals)
    processing_ms = (time.perf_counter() - t_start) * 1000.0

    logger.info(
        "analyze_email_complete",
        urls_requested=len(body.all_urls),
        urls_analyzed=len(url_analyses),
        worst_domain=worst.domain,
        worst_verdict=worst.verdict,
        processing_ms=round(processing_ms, 1),
        user=current_user.get("sub"),
    )

    return AnalyzeEmailResponse(
        url_analyses=url_analyses,
        worst=worst,
        email_verdict=email_verdict,
        reasons=reasons,
        processing_ms=round(processing_ms, 1),
        timestamp=datetime.now(timezone.utc),
    )


# --------------------------------------------------------------------------- #
# POST /analyze_batch — analiza múltiples URLs en paralelo
# --------------------------------------------------------------------------- #

@router.post(
    "/analyze_batch",
    response_model=BatchAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Analiza todas las URLs de un correo en paralelo",
    description=(
        "Ejecuta el pipeline completo (IDN + TI + LLM + Fusion) de forma concurrente "
        "sobre cada URL. Máximo 10 URLs por petición. Rate limit: 20 req/min/IP."
    ),
)
async def analyze_url_batch(
    http_request: Request,
    body: BatchAnalyzeRequest,
    current_user: dict = Depends(require_auth),
) -> BatchAnalyzeResponse:
    """
    Análisis paralelo de múltiples URLs:

    1. Rate limiting: 20 req/min por IP.
    2. Deduplica URLs (normaliza fragmentos de tracking).
    3. Construye EmailSignals mínimas desde el contexto del correo.
    4. Ejecuta _analyze_single_url_for_email para cada URL en paralelo.
    5. Persiste cada resultado como incidente individual (fire-and-forget).
    6. Devuelve todos los resultados + el de mayor s_risk como «worst».
    """
    client_ip = get_client_ip(http_request)
    await check_rate_limit(f"rl:analyze_batch:{client_ip}", limit=20, window_seconds=60)

    t_start = time.perf_counter()

    # Deduplicate: strip fragments so tracking tokens don't double URLs
    seen: set[str] = set()
    unique_urls: list[str] = []
    for u in body.urls:
        try:
            from urllib.parse import urlparse, urlunparse
            p = urlparse(u)
            norm = urlunparse(p._replace(fragment=""))
        except Exception:
            norm = u
        if norm not in seen:
            seen.add(norm)
            unique_urls.append(u)

    email_signals = EmailSignals(
        subject=body.email_subject or "",
        sender=body.email_from or "",
        sender_domain=_sender_domain(body.email_from),
        extracted_urls=unique_urls,
    )

    email_body_snippet = body.email_body_snippet
    email_hash = body.email_hash or ""

    tasks = [
        _analyze_single_url_for_email(
            url=url,
            email_signals=email_signals,
            email_hash=email_hash,
            email_body_snippet=email_body_snippet,
            t_start=t_start,
        )
        for url in unique_urls
    ]

    raw = await asyncio.gather(*tasks, return_exceptions=True)

    url_analyses: list[AnalyzeResponse] = []
    for i, result in enumerate(raw):
        if isinstance(result, Exception):
            logger.warning("batch_url_failed", url=unique_urls[i], error=str(result))
        else:
            url_analyses.append(result)
            asyncio.create_task(
                _persist_batch_incident(result, body),
                name=f"persist_batch_{result.request_id}",
            )

    if not url_analyses:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="All URL analyses failed — check that URLs are reachable http/https addresses.",
        )

    worst = max(url_analyses, key=lambda a: a.s_risk)
    processing_ms = (time.perf_counter() - t_start) * 1000.0

    logger.info(
        "batch_analysis_complete",
        urls_requested=len(body.urls),
        urls_analyzed=len(url_analyses),
        worst_domain=worst.domain,
        worst_verdict=worst.verdict,
        processing_ms=round(processing_ms, 1),
        user=current_user.get("sub"),
    )

    return BatchAnalyzeResponse(
        url_analyses=url_analyses,
        worst=worst,
        processing_ms=round(processing_ms, 1),
        timestamp=datetime.now(timezone.utc),
    )

