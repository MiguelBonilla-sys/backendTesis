"""GET /api/v1/metrics/summary and GET /api/v1/settings endpoints."""

from datetime import date, datetime, timezone

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.auth import require_auth
from core import constants
from models.database import get_session
from models.orm_models import Analysis

router = APIRouter()


# ── Response schemas (defined here — small, metrics-only models) ──────────────

class MetricsSummary(BaseModel):
    total_analyses_today: int
    phishing_today: int
    suspicious_today: int
    safe_today: int
    avg_latency_ms: float  # placeholder: 0.0 until latency tracking is wired
    cache_hit_rate: float  # placeholder: 0.0 until cache-hit counter is wired


class FusionSettings(BaseModel):
    alpha: float
    beta: float
    gamma: float
    theta: float
    lambda_: float = Field(alias="lambda")
    ti_vt_weight: float
    ti_urlscan_weight: float
    ti_gsb_weight: float

    model_config = {"populate_by_name": True}


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get(
    "/metrics/summary",
    response_model=MetricsSummary,
    status_code=status.HTTP_200_OK,
    summary="Aggregated analysis counts for today (requires JWT auth)",
)
async def get_metrics_summary(
    session: AsyncSession = Depends(get_session),
    _user: dict = Depends(require_auth),
) -> MetricsSummary:
    """Return today's analysis counts grouped by verdict."""
    today_midnight = datetime.combine(date.today(), datetime.min.time()).replace(
        tzinfo=timezone.utc
    )

    # Single query: count per verdict for today using conditional aggregation
    result = await session.execute(
        select(
            func.count(Analysis.id).label("total"),
            func.sum(
                func.cast(Analysis.verdict == constants.VERDICT_PHISHING, type_=None)
            ).label("phishing"),
            func.sum(
                func.cast(Analysis.verdict == constants.VERDICT_SUSPICIOUS, type_=None)
            ).label("suspicious"),
            func.sum(
                func.cast(Analysis.verdict == constants.VERDICT_SAFE, type_=None)
            ).label("safe"),
        ).where(Analysis.created_at >= today_midnight)
    )
    row = result.one()

    return MetricsSummary(
        total_analyses_today=row.total or 0,
        phishing_today=int(row.phishing or 0),
        suspicious_today=int(row.suspicious or 0),
        safe_today=int(row.safe or 0),
        avg_latency_ms=0.0,
        cache_hit_rate=0.0,
    )


@router.get(
    "/settings",
    response_model=FusionSettings,
    status_code=status.HTTP_200_OK,
    summary="Current fusion model hyperparameters (requires JWT auth)",
)
async def get_fusion_settings(
    _user: dict = Depends(require_auth),
) -> FusionSettings:
    """Return the active fusion model parameters from core/constants.py."""
    return FusionSettings(
        alpha=constants.ALPHA,
        beta=constants.BETA,
        gamma=constants.GAMMA,
        theta=constants.THETA,
        **{"lambda": 0.30},  # asymmetric loss — FN penalised 3x (security context)
        ti_vt_weight=constants.TI_VIRUSTOTAL_WEIGHT,
        ti_urlscan_weight=constants.TI_URLSCAN_WEIGHT,
        ti_gsb_weight=constants.TI_GSB_WEIGHT,
    )
