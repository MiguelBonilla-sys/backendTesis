"""GET /api/v1/incidents — paginated list and detail view for the admin dashboard.

Read-only. No write operations — the dashboard is observation-only (v1).
"""
from __future__ import annotations

import math
import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.auth import require_auth
from models.database import get_session
from models.orm_models import AgentResult, Analysis, XAIReport
from schemas.incident_schemas import (
    AgentResultDetail,
    IncidentDetailResponse,
    IncidentListItem,
    IncidentListResponse,
    XAIReportDetail,
)

router = APIRouter()


@router.get("/incidents", response_model=IncidentListResponse, status_code=status.HTTP_200_OK)
async def list_incidents(
    verdict: Literal["PHISHING", "SUSPICIOUS", "SAFE"] | None = Query(None),
    since: datetime | None = Query(None),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
    _user: dict = Depends(require_auth),
) -> IncidentListResponse:
    """Return a paginated list of analyses, newest first.

    Filters:
        verdict: restrict to PHISHING / SUSPICIOUS / SAFE.
        since:   ISO 8601 datetime — only analyses created at or after this timestamp.
    """
    stmt = select(Analysis)
    if verdict:
        stmt = stmt.where(Analysis.verdict == verdict)
    if since:
        stmt = stmt.where(Analysis.created_at >= since)

    # Total count (sub-query avoids fetching all rows into memory)
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total: int = (await session.execute(count_stmt)).scalar_one()

    # Paginated slice, newest first
    offset = (page - 1) * size
    stmt = stmt.order_by(Analysis.created_at.desc()).offset(offset).limit(size)
    rows = (await session.execute(stmt)).scalars().all()

    pages = math.ceil(total / size) if total > 0 else 0
    items = [
        IncidentListItem(
            id=a.id,
            trace_id=a.trace_id,
            domain=a.domain,
            verdict=a.verdict,
            s_risk=a.s_risk,
            reviewed=False,  # review workflow deferred to Phase 6
            created_at=a.created_at,
        )
        for a in rows
    ]
    return IncidentListResponse(items=items, total=total, page=page, size=size, pages=pages)


@router.get(
    "/incidents/{trace_id}",
    response_model=IncidentDetailResponse,
    status_code=status.HTTP_200_OK,
)
async def get_incident(
    trace_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _user: dict = Depends(require_auth),
) -> IncidentDetailResponse:
    """Return full detail for a single analysis: scores, SHAP/XAI, per-agent output."""
    # 1. Analysis row
    analysis = (
        await session.execute(select(Analysis).where(Analysis.trace_id == trace_id))
    ).scalar_one_or_none()

    if analysis is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis not found")

    # 2. Agent result rows (idn_agent, llm_agent, fusion_agent)
    agent_rows = (
        await session.execute(
            select(AgentResult).where(AgentResult.analysis_id == analysis.id)
        )
    ).scalars().all()

    # 3. XAI report (optional — absent on very old or failed analyses)
    xai_row = (
        await session.execute(
            select(XAIReport).where(XAIReport.analysis_id == analysis.id)
        )
    ).scalar_one_or_none()

    return IncidentDetailResponse(
        id=analysis.id,
        trace_id=analysis.trace_id,
        url=analysis.url,
        domain=analysis.domain,
        verdict=analysis.verdict,
        s_risk=analysis.s_risk,
        s_idn=analysis.s_idn,
        s_llm=analysis.s_llm,
        s_ti=analysis.s_ti,
        reviewed=False,
        agent_results=[
            AgentResultDetail(
                agent_name=r.agent_name,
                score=r.score,
                raw_output=r.raw_output,
                duration_ms=r.duration_ms,
            )
            for r in agent_rows
        ],
        xai_report=XAIReportDetail(
            shap_values=xai_row.shap_values,
            lime_values=xai_row.lime_values,
            top_features=xai_row.top_features,
        ) if xai_row else None,
        created_at=analysis.created_at,
    )
