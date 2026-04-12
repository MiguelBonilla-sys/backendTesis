"""Async repository for atomic persistence of a full phishing analysis.

Privacy contract (Ley 1581/2012):
  - email_body is NEVER stored — only email_sha256 (SHA-256 of email_id) and
    extracted URLs are persisted.
  - All SQL via SQLAlchemy ORM — never raw string interpolation.

Transaction structure (all-or-nothing):
  Analysis → URLAnalysis → 3× AgentResult → XAIReport
  On any failure the entire transaction is rolled back.
"""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from agents.fusion_agent import FusionAgent
from models.orm_models import AgentResult, Analysis, URLAnalysis, XAIReport
from core.logger import get_logger

logger = get_logger("analysis_repo")


async def save_full_analysis(
    session: AsyncSession,
    trace_id: str,
    url: str,
    domain: str,
    email_sha256: str | None,
    source: str,
    idn_result: dict,
    llm_result: dict,
    fusion_result: dict,
) -> str:
    """Persist a complete analysis in a single atomic transaction.

    Args:
        session:      Async SQLAlchemy session (caller owns lifecycle).
        trace_id:     UUID string for the analysis (ties all rows together).
        url:          Original URL that was analyzed.
        domain:       Normalized domain (ASCII/punycode form).
        email_sha256: SHA-256 of the email_id — NEVER the raw email body.
        source:       Origin of the request ("extension", "manual", …).
        idn_result:   Dict returned by IDNAgent.analyze().
        llm_result:   Dict returned by LLMAgent.analyze().
        fusion_result: Dict returned by FusionAgent.analyze().

    Returns:
        trace_id on success.

    Raises:
        Exception: Any DB error — caller should log and handle.
                   The transaction is fully rolled back before raising.
    """
    shap: dict[str, float] = fusion_result.get("shap_explanation", {})
    top_features: list[str] = fusion_result.get("top_features", [])

    async with session.begin():
        # ── 1. Analysis (root row) ─────────────────────────────────────────────
        analysis = Analysis(
            trace_id=trace_id,
            url=url,
            domain=domain,
            email_sha256=email_sha256,
            source=source,
            verdict=fusion_result["verdict"],
            s_risk=fusion_result["s_risk"],
            s_idn=fusion_result["s_idn"],
            s_llm=fusion_result["s_llm"],
            s_ti=fusion_result["s_ti"],
        )
        session.add(analysis)
        await session.flush()  # populate analysis.id for FK references

        # ── 2. URL-level IDN features ──────────────────────────────────────────
        url_analysis = URLAnalysis(
            analysis_id=analysis.id,
            url=url,
            domain_normalized=idn_result.get("normalized", domain),
            is_punycode=idn_result.get("is_punycode", False),
            confusables=idn_result.get("confusables", []),
            ratio_h=idn_result.get("ratio_h", 0.0),
            sim_v=idn_result.get("sim_v", 0.0),
            s_idn_local=idn_result.get("s_idn_local", 0.0),
        )
        session.add(url_analysis)

        # ── 3. Per-agent results (3 rows) ──────────────────────────────────────
        agent_rows = [
            AgentResult(
                analysis_id=analysis.id,
                agent_name="idn_agent",
                score=idn_result.get("s_idn_local", 0.0),
                raw_output={"s_idn_local": idn_result.get("s_idn_local", 0.0)},
            ),
            AgentResult(
                analysis_id=analysis.id,
                agent_name="llm_agent",
                score=llm_result.get("s_llm", 0.5),
                raw_output={
                    "s_llm": llm_result.get("s_llm", 0.5),
                    "reasoning": llm_result.get("reasoning", ""),
                    "llm_degraded": llm_result.get("llm_degraded", False),
                },
            ),
            AgentResult(
                analysis_id=analysis.id,
                agent_name="fusion_agent",
                score=fusion_result["s_risk"],
                raw_output={
                    "s_risk": fusion_result["s_risk"],
                    "verdict": fusion_result["verdict"],
                },
            ),
        ]
        for row in agent_rows:
            session.add(row)

        # ── 4. XAI report ──────────────────────────────────────────────────────
        xai = XAIReport(
            analysis_id=analysis.id,
            shap_values=shap,
            lime_values={},   # LIME deferred to Phase 6
            top_features=top_features,
        )
        session.add(xai)

    logger.info("Analysis persisted: trace_id=%s verdict=%s", trace_id, fusion_result["verdict"])
    return trace_id
