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
import time
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status

from agents.fusion_agent import fusion_agent
from agents.hf_agent import hf_agent
from agents.idn_agent import idn_agent
from agents.llm_agent import llm_agent
from agents.web_probe_agent import web_probe_agent
from auth.dependencies import require_auth
from core.exceptions import IDNAnalysisError, LLMTimeoutError, ThreatIntelError
from core.logger import get_logger
from core.rate_limiter import check_rate_limit, get_client_ip
from data_pipeline.knowledge_updater import AUTO_INGEST_THRESHOLD, knowledge_updater
from data_pipeline.threat_intel import threat_intel_service
from schemas.analyze import (
    AnalyzeEmailRequest,
    AnalyzeEmailResponse,
    AnalyzeRequest,
    AnalyzeResponse,
    BatchAnalyzeRequest,
    BatchAnalyzeResponse,
    EmailAnalysisResponse,
    EmailSignals,
    ReportRequest,
    ReportResponse,
)
from services.analysis import (
    _aggregate_email_reasons,
    _analyze_single_url_for_email,
    _sender_domain,
)
from services.persistence import (
    _persist_batch_incident,
    _persist_email_incident,
    _persist_incident,
    _persist_manual_report,
)
from utils.email_parser import ParsedEmail, _detect_urgency, parse_eml
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
    # Paso 1: IDN Agent + ThreatIntel + HF Agent + WebProbe en paralelo
    # ------------------------------------------------------------------ #
    try:
        idn_result, ti_result, s_hf, probe_result = await asyncio.gather(
            idn_agent.analyze(url),
            threat_intel_service.analyze(url, domain),
            hf_agent.analyze(url, body.email_body_snippet),
            web_probe_agent.analyze(url),
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
    _confusable_str = (
        ", ".join(repr(c) for c in idn_result.confusable_chars[:5])
        if idn_result.confusable_chars
        else "none"
    )
    idn_summary = (
        f"domain_unicode={idn_result.domain_unicode!r}, "
        f"s_idn_local={idn_result.s_idn_local:.2f}, "
        f"homograph_ratio={idn_result.homograph_ratio:.2f}, "
        f"visual_similarity={idn_result.visual_similarity:.2f}, "
        f"mixed_script={idn_result.is_mixed_script}, "
        f"confusable_chars=[{_confusable_str}], "
        f"suspicious={idn_result.is_suspicious}"
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
    # Gate anti-FP del probe (T3): el dominio efectivo post-redirect manda —
    # un acortador top-1M que redirige a un dominio desconocido NO es confiable.
    probe_final_domain = (
        probe_result.final_domain if probe_result and probe_result.final_domain else domain
    )
    probe_domain_trusted = idn_agent.is_trusted_domain(probe_final_domain)

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
            probe_result=probe_result,
            probe_domain_trusted=probe_domain_trusted,
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
        _persist_incident(response, body),
        name=f"persist_{response.request_id}",
    )

    # Auto-ingest high-confidence results into ChromaDB for future RAG retrieval
    if response.s_risk >= AUTO_INGEST_THRESHOLD:
        asyncio.create_task(
            knowledge_updater.ingest_from_analysis(
                url=response.url,
                domain=response.domain,
                verdict=response.verdict,
                s_risk=response.s_risk,
                s_idn_local=response.idn_result.s_idn_local,
                s_ti=response.ti_result.s_ti,
                s_llm=response.agent_scores.s_llm,
                confusable_chars=response.idn_result.confusable_chars,
                domain_unicode=response.idn_result.domain_unicode,
                homograph_ratio=response.idn_result.homograph_ratio,
                visual_similarity=response.idn_result.visual_similarity,
                is_mixed_script=response.idn_result.is_mixed_script,
                reasons=response.reasons,
                llm_reason=response.llm_reason,
                s_vt=response.ti_result.s_vt,
                s_urlscan=response.ti_result.s_urlscan,
                s_gsb=response.ti_result.s_gsb,
                # incident_id alinea los doc ids de ChromaDB con incidents.id —
                # permite purgarlos si un admin marca el incidente como FP (T11)
                incident_id=response.request_id,
            ),
            name=f"autoingest_{response.request_id}",
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
