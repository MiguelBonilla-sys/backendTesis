"""Pydantic v2 request/response schemas for the POST /api/v1/analyze endpoint."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    email_hash: str | None = None  # SHA-256 hash of the email (privacy)
    email_body_snippet: str | None = Field(None, max_length=5000)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class IDNResult(BaseModel):
    domain_unicode: str
    confusable_chars: list[str]
    homograph_ratio: float
    visual_similarity: float
    s_idn_local: float
    is_mixed_script: bool
    is_suspicious: bool


class TIResult(BaseModel):
    s_vt: float
    s_urlscan: float
    s_gsb: float
    s_ti: float
    # WhoisXML domain age fields
    domain_age_days: int | None = None    # None si no disponible
    is_newly_registered: bool = False      # True si < DOMAIN_AGE_SUSPICIOUS_DAYS
    whois_registrar: str | None = None


class AgentScores(BaseModel):
    s_idn_local: float
    s_ti: float
    s_idn: float
    s_llm: float
    s_hf: float = 0.5   # HuggingFace classifier score; 0.5 (neutral) when key absent
    s_risk: float


class ShapExplanation(BaseModel):
    feature_contributions: dict[str, float]


class AnalyzeResponse(BaseModel):
    request_id: str
    url: str
    domain: str
    verdict: Literal["PHISHING", "LEGITIMATE", "SUSPICIOUS"]
    s_risk: float = Field(ge=0.0, le=1.0)
    agent_scores: AgentScores
    idn_result: IDNResult
    ti_result: TIResult
    llm_reason: str
    shap_explanation: ShapExplanation
    processing_ms: float
    timestamp: datetime
