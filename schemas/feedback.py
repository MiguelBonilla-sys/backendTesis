"""Pydantic v2 schemas for the admin feedback loop."""
from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class FeedbackRequest(BaseModel):
    confirmed_verdict: Literal["PHISHING", "SUSPICIOUS", "LEGITIMATE"]
    note: str | None = Field(default=None, max_length=500)


class FeedbackResponse(BaseModel):
    feedback_id: UUID
    incident_id: UUID
    confirmed_verdict: str
    ingested: bool
    message: str
