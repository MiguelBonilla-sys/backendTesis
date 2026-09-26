"""Content-only assessment: no synthetic URL, DNS lookup or web probe."""

from __future__ import annotations

import asyncio
import time

from agents.fusion_agent import fusion_agent
from agents.hf_agent import hf_agent
from agents.llm_agent import llm_agent
from core.agent_signal import telemetry_of
from schemas.analyze import AnalyzeResponse, EmailSignals, IDNResult, TIResult
from services.analysis_limits import bounded_analysis


@bounded_analysis
async def analyze_email_content(
    signals: EmailSignals,
    body: str,
    email_hash: str,
) -> tuple[AnalyzeResponse, str]:
    started = time.perf_counter()
    text = f"Subject: {signals.subject}\n{body}"[:5000]
    (s_llm, reason), (s_hf, hf_status) = await asyncio.gather(
        llm_agent.analyze(
            url="",
            domain=signals.sender_domain,
            email_body_snippet=text,
            idn_result_summary="Content-only email: no URL evidence is available.",
        ),
        hf_agent.analyze_content_with_status(text),
    )
    result = await fusion_agent.fuse(
        url="",
        domain=signals.sender_domain,
        idn_result=IDNResult(
            domain_unicode=signals.sender_domain,
            confusable_chars=[],
            homograph_ratio=0,
            visual_similarity=0,
            s_idn_local=0,
            is_mixed_script=False,
            is_suspicious=False,
        ),
        ti_result=TIResult(s_vt=0, s_urlscan=0, s_gsb=0, s_ti=0),
        s_llm=float(s_llm),
        llm_reason=reason,
        start_time=started,
        email_hash=email_hash,
        s_hf=float(s_hf),
        email_signals=signals,
    )
    result.agent_status = {"llm": telemetry_of(s_llm), "hf_content": hf_status}
    available = sum(signal.status == "ok" for signal in result.agent_status.values())
    status = "complete" if available == 2 else "partial" if available else "indeterminate"
    if status != "complete":
        if result.verdict != "PHISHING":
            result.verdict = "SUSPICIOUS"
        result.reasons.append(
            "Content analysis is incomplete; unavailable signals do not prove safety"
        )
    if signals.has_suspicious_attachments and result.verdict == "LEGITIMATE":
        result.verdict = "SUSPICIOUS"
        result.reasons.append(
            "Potentially unsafe attachment; attachment contents have not been scanned"
        )
    return result, status
