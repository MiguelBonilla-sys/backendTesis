import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class IncidentListItem(BaseModel):
    id: uuid.UUID
    trace_id: uuid.UUID
    domain: str
    verdict: Literal["PHISHING", "SUSPICIOUS", "SAFE"]
    s_risk: float
    reviewed: bool
    created_at: datetime


class IncidentListResponse(BaseModel):
    items: list[IncidentListItem]
    total: int
    page: int
    size: int
    pages: int


class AgentResultDetail(BaseModel):
    agent_name: str
    score: float
    raw_output: dict
    duration_ms: int | None


class XAIReportDetail(BaseModel):
    shap_values: dict[str, float]
    lime_values: dict[str, float]
    top_features: list[str]


class IncidentDetailResponse(BaseModel):
    id: uuid.UUID
    trace_id: uuid.UUID
    url: str
    domain: str
    verdict: Literal["PHISHING", "SUSPICIOUS", "SAFE"]
    s_risk: float
    s_idn: float
    s_llm: float
    s_ti: float
    reviewed: bool
    agent_results: list[AgentResultDetail]
    xai_report: XAIReportDetail | None
    created_at: datetime
