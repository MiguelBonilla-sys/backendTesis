"""Analysis service — URL pipeline helpers shared across analyze endpoints."""
from __future__ import annotations

import asyncio
import re

from agents.fusion_agent import fusion_agent
from agents.hf_agent import hf_agent
from agents.idn_agent import idn_agent
from agents.llm_agent import llm_agent
from agents.web_probe_agent import web_probe_agent
from core.exceptions import LLMTimeoutError
from data_pipeline.threat_intel import threat_intel_service
from schemas.analyze import AnalyzeResponse, EmailSignals
from utils.url_parser import extract_effective_domain


def _sender_domain(email_from: str | None) -> str:
    """Extrae el dominio del campo From del email."""
    if not email_from:
        return ""
    m = re.search(r"@([\w.\-]+)", email_from)
    return m.group(1).lower() if m else ""


async def run_pipeline_core(
    url: str,
    domain: str,
    *,
    t_start: float,
    email_hash: str | None = None,
    email_body_snippet: str | None = None,
    email_signals: EmailSignals | None = None,
) -> AnalyzeResponse:
    """
    Núcleo compartido del pipeline de una URL (etapas 1–3): agentes en
    paralelo → LLM con fallback → gate anti-FP del probe → fusión.

    Único punto de orquestación reutilizado por ``/analyze`` (router) y por
    el análisis por-URL de email/batch/eml. Las excepciones de los agentes
    se propagan: el caller decide (HTTP 500 en /analyze, descarte en batch).
    El timeout del LLM se degrada acá (score neutral 0.5) — comportamiento
    idéntico en todos los endpoints.
    """
    idn_result, ti_result, s_hf, probe_result = await asyncio.gather(
        idn_agent.analyze(url),
        threat_intel_service.analyze(url, domain),
        hf_agent.analyze(url, email_body_snippet),
        web_probe_agent.analyze(url),
    )

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
            email_body_snippet=email_body_snippet,
            idn_result_summary=idn_summary,
        )
    except LLMTimeoutError:
        s_llm = 0.5
        llm_reason = "LLM timed out — neutral fallback applied"

    # Gate anti-FP del probe (T3): manda el dominio efectivo post-redirect.
    probe_final_domain = (
        probe_result.final_domain if probe_result and probe_result.final_domain else domain
    )
    probe_domain_trusted = idn_agent.is_trusted_domain(probe_final_domain)

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
        probe_result=probe_result,
        probe_domain_trusted=probe_domain_trusted,
    )


async def _analyze_single_url_for_email(
    url: str,
    email_signals: EmailSignals,
    email_hash: str,
    email_body_snippet: str | None,
    t_start: float,
) -> AnalyzeResponse:
    """
    Pipeline completo para una URL en el contexto de un email.

    Usa ``extract_effective_domain`` para resolver abusos de CDN
    (ej. GCS bucket hosting malware) antes de delegar en ``run_pipeline_core``.
    """
    domain = extract_effective_domain(url)
    return await run_pipeline_core(
        url,
        domain,
        t_start=t_start,
        email_hash=email_hash,
        email_body_snippet=email_body_snippet,
        email_signals=email_signals,
    )


def schedule_autoingest(response: AnalyzeResponse) -> None:
    """
    Encola la auto-ingesta de un resultado de alta confianza en ChromaDB
    (fire-and-forget). Solo cuando ``s_risk >= AUTO_INGEST_THRESHOLD``.

    El ``incident_id`` se alinea con ``incidents.id`` para que los documentos
    sean purgables si luego se marca como falso positivo (T11).
    """
    from data_pipeline.knowledge_updater import (
        AUTO_INGEST_THRESHOLD,
        knowledge_updater,
    )

    if response.s_risk < AUTO_INGEST_THRESHOLD:
        return

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
            incident_id=response.request_id,
        ),
        name=f"autoingest_{response.request_id}",
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

    def _add(reason: str) -> None:
        if reason not in seen:
            seen.add(reason)
            reasons.append(reason)

    if email_signals.is_urgent and not any("urgency" in r.lower() for r in reasons):
        _add("Email uses urgency/pressure tactics to coerce immediate action")
    if email_signals.sender_domain_mismatch:
        _add(
            f"Sender domain ({email_signals.sender_domain!r}) does not match "
            f"return-path domain ({email_signals.return_path_domain!r})"
        )
    if email_signals.has_suspicious_attachments:
        names = ", ".join(email_signals.attachment_names[:3])
        _add(f"Suspicious attachments detected: {names}")
    if not email_signals.spf_pass and email_signals.sender_domain:
        _add(f"SPF authentication failed for {email_signals.sender_domain!r}")
    if not email_signals.dkim_pass and email_signals.sender_domain:
        _add(f"DKIM signature verification failed for {email_signals.sender_domain!r}")

    if not reasons:
        reasons.append("No suspicious indicators detected in email or URLs")

    return reasons
