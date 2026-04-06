import pytest

from agents.fusion_agent import FusionAgent
from core.constants import VERDICT_PHISHING, VERDICT_SAFE, VERDICT_SUSPICIOUS


@pytest.fixture
def agent() -> FusionAgent:
    return FusionAgent()


@pytest.mark.asyncio
async def test_verdict_phishing(agent: FusionAgent):
    result = await agent.analyze(
        s_idn_local=0.9,
        s_llm=0.9,
        ti_scores={"virustotal": 1.0, "urlscan": 1.0, "google_safe_browsing": 1.0},
    )
    assert result["verdict"] == VERDICT_PHISHING
    assert result["s_risk"] >= 0.70


@pytest.mark.asyncio
async def test_verdict_safe(agent: FusionAgent):
    result = await agent.analyze(
        s_idn_local=0.0,
        s_llm=0.0,
        ti_scores={"virustotal": 0.0, "urlscan": 0.0, "google_safe_browsing": 0.0},
    )
    assert result["verdict"] == VERDICT_SAFE
    assert result["s_risk"] < 0.50


@pytest.mark.asyncio
async def test_verdict_suspicious(agent: FusionAgent):
    result = await agent.analyze(
        s_idn_local=0.5,
        s_llm=0.5,
        ti_scores={"virustotal": 0.4, "urlscan": 0.3, "google_safe_browsing": 0.0},
    )
    assert result["verdict"] == VERDICT_SUSPICIOUS


@pytest.mark.asyncio
async def test_shap_explanation_keys(agent: FusionAgent):
    result = await agent.analyze(
        s_idn_local=0.6,
        s_llm=0.7,
        ti_scores={"virustotal": 0.5, "urlscan": 0.5, "google_safe_browsing": 0.5},
    )
    shap = result["shap_explanation"]
    assert "idn_contribution" in shap
    assert "llm_contribution" in shap
    assert "ti_contribution" in shap
    assert shap["baseline"] == 0.5


@pytest.mark.asyncio
async def test_score_bounds(agent: FusionAgent):
    result = await agent.analyze(
        s_idn_local=0.5,
        s_llm=0.5,
        ti_scores={"virustotal": 0.5, "urlscan": 0.5, "google_safe_browsing": 0.5},
    )
    assert 0.0 <= result["s_risk"] <= 1.0
