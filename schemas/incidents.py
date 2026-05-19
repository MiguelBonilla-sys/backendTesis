"""Pydantic v2 schemas for the incidents listing endpoint."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class IncidentRecord(BaseModel):
    id: str
    email_hash: str
    url: str
    domain: str
    verdict: Literal["PHISHING", "LEGITIMATE", "SUSPICIOUS"]
    s_risk: float
    s_idn: float
    s_llm: float
    s_ti: float
    llm_reason: str
    shap_contributions: dict[str, float]
    created_at: datetime


class IncidentListResponse(BaseModel):
    items: list[IncidentRecord]
    total: int
    page: int
    page_size: int
