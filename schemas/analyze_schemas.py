from typing import Literal

from pydantic import BaseModel, field_validator


class AnalyzeRequest(BaseModel):
    url: str
    email_body: str | None = None
    source: Literal["gmail", "outlook", "extension", "manual"] = "manual"

    @field_validator("url")
    @classmethod
    def url_must_be_http(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class IDNAnalysisResult(BaseModel):
    domain: str
    normalized: str
    is_punycode: bool
    confusables: list[str]
    ratio_h: float
    sim_v: float
    s_idn_local: float
    ratio_h_alert: bool


class LLMAnalysisResult(BaseModel):
    domain: str
    s_llm: float
    reasoning: str
    rag_context: list[str]
    tokens_used: int


class SHAPExplanation(BaseModel):
    idn_contribution: float
    llm_contribution: float
    ti_contribution: float
    idn_local_score: float
    baseline: float


class AnalyzeResponse(BaseModel):
    url: str
    domain: str
    verdict: Literal["PHISHING", "SUSPICIOUS", "SAFE"]
    s_risk: float
    s_idn: float
    s_ti: float
    idn_analysis: IDNAnalysisResult
    llm_analysis: LLMAnalysisResult
    shap_explanation: SHAPExplanation


class HealthResponse(BaseModel):
    status: str
    version: str
    components: dict[str, str]
