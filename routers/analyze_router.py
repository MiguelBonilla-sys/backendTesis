"""POST /api/v1/analyze — orchestrates IDN → (LLM ‖ TI) → Fusion pipeline."""

import asyncio

from fastapi import APIRouter, Depends, HTTPException, status

from agents.fusion_agent import FusionAgent
from agents.idn_agent import IDNAgent
from agents.llm_agent import LLMAgent
from core.exceptions import BackendTesisError, InvalidURLError
from core.logger import logger
from core.security import extract_domain, sanitize_url
from data_pipeline.cache_manager import CacheManager
from data_pipeline.threat_intel import ThreatIntelService
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
    idn_agent: IDNAgent = Depends(_idn),
    llm_agent: LLMAgent = Depends(_llm),
    fusion_agent: FusionAgent = Depends(_fusion),
    cache: CacheManager = Depends(_cache),
    ti_service: ThreatIntelService = Depends(_ti),
) -> AnalyzeResponse:
    # Validate & sanitize input
    try:
        url = sanitize_url(request.url)
        domain = extract_domain(url)
    except InvalidURLError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    try:
        # Stage 1: IDN (CPU-bound, fast)
        idn_result = await idn_agent.analyze(domain)

        # Stage 2: LLM + TI in parallel (both are I/O-bound)
        llm_task = asyncio.create_task(
            llm_agent.analyze(domain, request.email_body, idn_result["s_idn_local"])
        )
        ti_task = asyncio.create_task(cache.get_or_fetch_ti(domain, ti_service))
        llm_result, ti_scores = await asyncio.gather(llm_task, ti_task)

        # Stage 3: Fusion + XAI
        fusion_result = await fusion_agent.analyze(
            s_idn_local=idn_result["s_idn_local"],
            s_llm=llm_result["s_llm"],
            ti_scores=ti_scores,
        )

        return AnalyzeResponse(
            url=request.url,
            domain=domain,
            verdict=fusion_result["verdict"],
            s_risk=fusion_result["s_risk"],
            s_idn=fusion_result["s_idn"],
            s_ti=fusion_result["s_ti"],
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
