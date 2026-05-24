"""Pydantic v2 schemas for the incidents listing endpoint."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


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
    # Email context — populated when analysis is triggered via the browser extension
    email_subject: str = ""
    email_from: str = ""
    email_to: str = ""
    all_urls: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    # Full email content (always stored)
    email_body_html: str = ""
    email_images: list[str] = Field(default_factory=list)
    email_attachments: list[str] = Field(default_factory=list)


class IncidentListResponse(BaseModel):
    items: list[IncidentRecord]
    total: int
    page: int
    page_size: int
