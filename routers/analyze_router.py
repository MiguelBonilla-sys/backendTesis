"""POST /api/v1/analyze — orchestrates IDN → (LLM ‖ TI) → Fusion pipeline."""

import asyncio
import hashlib
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from agents.fusion_agent import FusionAgent
from agents.idn_agent import IDNAgent
from agents.llm_agent import LLMAgent
from auth.auth import require_auth
from core.exceptions import BackendTesisError, InvalidURLError
from core.logger import logger
from core.security import extract_domain, sanitize_url
from data_pipeline.analysis_repo import save_full_analysis
from data_pipeline.cache_manager import CacheManager
from data_pipeline.threat_intel import ThreatIntelService
from models.database import get_session
from schemas.analyze_schemas import AnalyzeRequest, AnalyzeResponse

router = APIRouter()


# ── Dependency factories (stateless per request) ──────────────────────────────

def _idn() -> IDNAgent:
    return IDNAgent()


def _llm() -> LLMAgent:
    return LLMAgent()


def _fusion() -> FusionAgent:
    return FusionAgent()


def _cache() -> CacheManager:
    return CacheManager()


def _ti() -> ThreatIntelService:
    return ThreatIntelService()


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.post("/analyze", response_model=AnalyzeResponse, status_code=status.HTTP_200_OK)
async def analyze_url(
    request: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    idn_agent: IDNAgent = Depends(_idn),
    llm_agent: LLMAgent = Depends(_llm),
    fusion_agent: FusionAgent = Depends(_fusion),
    cache: CacheManager = Depends(_cache),
    ti_service: ThreatIntelService = Depends(_ti),
    session: AsyncSession = Depends(get_session),
    _user: dict = Depends(require_auth),
) -> AnalyzeResponse:
    # Validate & sanitize input
    try:
        url = sanitize_url(request.url)
        domain = extract_domain(url)
    except InvalidURLError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc))

    # Privacy: SHA-256 of email body if present — raw body is never stored
    email_sha256: str | None = (
        hashlib.sha256(request.email_body.encode()).hexdigest()
        if request.email_body
        else None
    )
    trace_id = str(uuid.uuid4())

    try:
        # Stage 1: IDN analysis (CPU-bound, fast)
        idn_result = await idn_agent.analyze(domain)

        # Stage 2: LLM + TI in parallel (both I/O-bound)
        llm_task = asyncio.create_task(
            llm_agent.analyze(domain, request.email_body, idn_result["s_idn_local"])
        )
        ti_task = asyncio.create_task(cache.get_or_fetch_ti(domain, ti_service))
        llm_result, ti_scores = await asyncio.gather(llm_task, ti_task)

        # Stage 3: Fusion + XAI
        # is_definitive_homograph: IDN floor rule fired → mixed-script + high sim_v
        is_definitive_homograph: bool = (
            idn_result.get("is_mixed_script", False)
            and idn_result.get("s_idn_local", 0.0) >= 0.85
        )
        # llm_is_fallback: LLM timed out → s_llm is the 0.5 neutral fallback
        llm_is_fallback: bool = llm_result.get("reasoning") == "timeout"

        fusion_result = await fusion_agent.analyze(
            s_idn_local=idn_result["s_idn_local"],
            s_llm=llm_result["s_llm"],
            ti_scores=ti_scores,
            is_definitive_homograph=is_definitive_homograph,
            llm_is_fallback=llm_is_fallback,
        )

        # Persist atomically in background — response is sent before DB write completes
        background_tasks.add_task(
            save_full_analysis,
            session=session,
            trace_id=trace_id,
            url=url,
            domain=domain,
            email_sha256=email_sha256,
            source=request.source,
            idn_result=idn_result,
            llm_result=llm_result,
            fusion_result=fusion_result,
        )

        return AnalyzeResponse(
            url=request.url,
            domain=domain,
            verdict=fusion_result["verdict"],
            s_risk=fusion_result["s_risk"],
            s_idn=fusion_result["s_idn"],
            s_llm=fusion_result["s_llm"],
            s_ti=fusion_result["s_ti"],
            top_features=fusion_result.get("top_features", []),
            idn_analysis=idn_result,
            llm_analysis=llm_result,
            shap_explanation=fusion_result["shap_explanation"],
        )

    except BackendTesisError as exc:
        logger.error(f"Pipeline error for {domain!r}: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Analysis pipeline failed",
        )
