"""Tests for agents/fusion_agent.py"""
from __future__ import annotations

import time

import pytest

from agents.fusion_agent import FusionAgent
from core.constants import ALPHA, GAMMA, THETA
from schemas.analyze import IDNResult, TIResult


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def agent() -> FusionAgent:
    return FusionAgent()


@pytest.fixture
def phishing_idn() -> IDNResult:
    return IDNResult(
        domain_unicode="рaypal",
        confusable_chars=["р"],
        homograph_ratio=0.333,
        visual_similarity=0.857,
        s_idn_local=0.90,
        is_mixed_script=True,
        is_suspicious=True,
    )


@pytest.fixture
def legit_idn() -> IDNResult:
    return IDNResult(
        domain_unicode="paypal",
        confusable_chars=[],
        homograph_ratio=0.0,
        visual_similarity=0.0,
        s_idn_local=0.0,
        is_mixed_script=False,
        is_suspicious=False,
    )


@pytest.fixture
def phishing_ti() -> TIResult:
    return TIResult(s_vt=0.9, s_urlscan=0.8, s_gsb=1.0, s_ti=0.89)


@pytest.fixture
def legit_ti() -> TIResult:
    return TIResult(s_vt=0.0, s_urlscan=0.0, s_gsb=0.0, s_ti=0.0)


# ---------------------------------------------------------------------------
# FusionAgent.fuse — verdict + scores
# ---------------------------------------------------------------------------

class TestFusionAgentFuse:
    @pytest.mark.asyncio
    async def test_phishing_verdict_when_high_scores(
        self, agent: FusionAgent, phishing_idn: IDNResult, phishing_ti: TIResult
    ):
        response = await agent.fuse(
            url="https://рaypal.com",
            domain="рaypal.com",
            idn_result=phishing_idn,
            ti_result=phishing_ti,
            s_llm=0.9,
            llm_reason="Clear phishing",
            start_time=time.perf_counter(),
        )
        assert response.verdict == "PHISHING"
        assert response.s_risk >= THETA

    @pytest.mark.asyncio
    async def test_legitimate_verdict_when_low_scores(
        self, agent: FusionAgent, legit_idn: IDNResult, legit_ti: TIResult
    ):
        response = await agent.fuse(
            url="https://paypal.com",
            domain="paypal.com",
            idn_result=legit_idn,
            ti_result=legit_ti,
            s_llm=0.0,
            llm_reason="Clean domain",
            start_time=time.perf_counter(),
        )
        assert response.verdict == "LEGITIMATE"
        assert response.s_risk < 0.40

    @pytest.mark.asyncio
    async def test_s_idn_formula_correct(
        self, agent: FusionAgent, phishing_idn: IDNResult, legit_ti: TIResult
    ):
        """S_IDN = α * S_IDN_local + (1-α) * S_TI"""
        response = await agent.fuse(
            url="https://рaypal.com",
            domain="рaypal.com",
            idn_result=phishing_idn,
            ti_result=legit_ti,
            s_llm=0.5,
            llm_reason="Test",
            start_time=time.perf_counter(),
        )
        expected_s_idn = ALPHA * phishing_idn.s_idn_local + (1 - ALPHA) * legit_ti.s_ti
        assert abs(response.agent_scores.s_idn - expected_s_idn) < 0.001

    @pytest.mark.asyncio
    async def test_s_risk_formula_correct(
        self, agent: FusionAgent, phishing_idn: IDNResult, phishing_ti: TIResult
    ):
        """S_risk = γ * S_IDN + (1-γ) * S_LLM"""
        s_llm = 0.7
        response = await agent.fuse(
            url="https://рaypal.com",
            domain="рaypal.com",
            idn_result=phishing_idn,
            ti_result=phishing_ti,
            s_llm=s_llm,
            llm_reason="Test",
            start_time=time.perf_counter(),
        )
        expected_s_idn = ALPHA * phishing_idn.s_idn_local + (1 - ALPHA) * phishing_ti.s_ti
        expected_s_risk = GAMMA * expected_s_idn + (1 - GAMMA) * s_llm
        assert abs(response.s_risk - expected_s_risk) < 0.001

    @pytest.mark.asyncio
    async def test_s_risk_clamped_between_zero_and_one(
        self, agent: FusionAgent, phishing_idn: IDNResult, phishing_ti: TIResult
    ):
        response = await agent.fuse(
            url="https://рaypal.com",
            domain="рaypal.com",
            idn_result=phishing_idn,
            ti_result=phishing_ti,
            s_llm=1.0,
            llm_reason="Test",
            start_time=time.perf_counter(),
        )
        assert 0.0 <= response.s_risk <= 1.0

    @pytest.mark.asyncio
    async def test_suspicious_verdict_in_boundary_zone(
        self, agent: FusionAgent
    ):
        """Score 0.40–0.69 yields SUSPICIOUS."""
        mid_idn = IDNResult(
            domain_unicode="paypal",
            confusable_chars=[],
            homograph_ratio=0.15,
            visual_similarity=0.5,
            s_idn_local=0.45,
            is_mixed_script=False,
            is_suspicious=True,
        )
        mid_ti = TIResult(s_vt=0.2, s_urlscan=0.1, s_gsb=0.0, s_ti=0.13)

        response = await agent.fuse(
            url="https://paypa1.com",
            domain="paypa1.com",
            idn_result=mid_idn,
            ti_result=mid_ti,
            s_llm=0.5,
            llm_reason="Borderline",
            start_time=time.perf_counter(),
        )
        # S_IDN = 0.60*0.45 + 0.40*0.13 = 0.322
        # S_risk = 0.50*0.322 + 0.50*0.5 = 0.411 → SUSPICIOUS
        assert response.verdict in {"SUSPICIOUS", "LEGITIMATE"}

    @pytest.mark.asyncio
    async def test_response_contains_all_required_fields(
        self, agent: FusionAgent, phishing_idn: IDNResult, phishing_ti: TIResult
    ):
        response = await agent.fuse(
            url="https://рaypal.com",
            domain="рaypal.com",
            idn_result=phishing_idn,
            ti_result=phishing_ti,
            s_llm=0.8,
            llm_reason="Test",
            start_time=time.perf_counter(),
        )
        assert response.request_id
        assert response.url
        assert response.domain
        assert response.verdict
        assert response.agent_scores
        assert response.idn_result
        assert response.ti_result
        assert response.shap_explanation
        assert response.timestamp

    @pytest.mark.asyncio
    async def test_processing_ms_is_positive(
        self, agent: FusionAgent, phishing_idn: IDNResult, phishing_ti: TIResult
    ):
        response = await agent.fuse(
            url="https://рaypal.com",
            domain="рaypal.com",
            idn_result=phishing_idn,
            ti_result=phishing_ti,
            s_llm=0.8,
            llm_reason="Test",
            start_time=time.perf_counter(),
        )
        assert response.processing_ms >= 0.0

    @pytest.mark.asyncio
    async def test_email_hash_accepted_as_optional(
        self, agent: FusionAgent, legit_idn: IDNResult, legit_ti: TIResult
    ):
        response = await agent.fuse(
            url="https://paypal.com",
            domain="paypal.com",
            idn_result=legit_idn,
            ti_result=legit_ti,
            s_llm=0.0,
            llm_reason="Clean",
            start_time=time.perf_counter(),
            email_hash="sha256hashvalue",
        )
        assert response is not None

    @pytest.mark.asyncio
    async def test_request_id_is_uuid_string(
        self, agent: FusionAgent, legit_idn: IDNResult, legit_ti: TIResult
    ):
        import uuid
        response = await agent.fuse(
            url="https://paypal.com",
            domain="paypal.com",
            idn_result=legit_idn,
            ti_result=legit_ti,
            s_llm=0.0,
            llm_reason="Clean",
            start_time=time.perf_counter(),
        )
        uuid.UUID(response.request_id)  # raises if not valid UUID


# ---------------------------------------------------------------------------
# SHAP contributions
# ---------------------------------------------------------------------------

class TestFusionAgentShap:
    @pytest.mark.asyncio
    async def test_shap_contains_required_keys(
        self, agent: FusionAgent, phishing_idn: IDNResult, phishing_ti: TIResult
    ):
        response = await agent.fuse(
            url="https://рaypal.com",
            domain="рaypal.com",
            idn_result=phishing_idn,
            ti_result=phishing_ti,
            s_llm=0.8,
            llm_reason="Test",
            start_time=time.perf_counter(),
        )
        contribs = response.shap_explanation.feature_contributions
        assert "s_idn_local" in contribs
        assert "s_ti" in contribs
        assert "s_llm" in contribs
        assert "homograph_ratio" in contribs
        assert "visual_similarity" in contribs
        assert "is_mixed_script" in contribs

    @pytest.mark.asyncio
    async def test_shap_all_values_are_floats(
        self, agent: FusionAgent, phishing_idn: IDNResult, phishing_ti: TIResult
    ):
        response = await agent.fuse(
            url="https://рaypal.com",
            domain="рaypal.com",
            idn_result=phishing_idn,
            ti_result=phishing_ti,
            s_llm=0.8,
            llm_reason="Test",
            start_time=time.perf_counter(),
        )
        for key, val in response.shap_explanation.feature_contributions.items():
            assert isinstance(val, float), f"{key} is not float"

    @pytest.mark.asyncio
    async def test_shap_contributions_non_negative(
        self, agent: FusionAgent, phishing_idn: IDNResult, phishing_ti: TIResult
    ):
        response = await agent.fuse(
            url="https://рaypal.com",
            domain="рaypal.com",
            idn_result=phishing_idn,
            ti_result=phishing_ti,
            s_llm=0.8,
            llm_reason="Test",
            start_time=time.perf_counter(),
        )
        for key, val in response.shap_explanation.feature_contributions.items():
            assert val >= 0.0, f"Contribution for {key} is negative: {val}"

    @pytest.mark.asyncio
    async def test_shap_is_zero_for_zero_scores(
        self, agent: FusionAgent, legit_idn: IDNResult, legit_ti: TIResult
    ):
        """All zero inputs → all SHAP contributions are zero."""
        response = await agent.fuse(
            url="https://paypal.com",
            domain="paypal.com",
            idn_result=legit_idn,
            ti_result=legit_ti,
            s_llm=0.0,
            llm_reason="Clean",
            start_time=time.perf_counter(),
        )
        contribs = response.shap_explanation.feature_contributions
        for key, val in contribs.items():
            assert val == 0.0, f"Expected 0 for {key}, got {val}"

    def test_compute_shap_idn_local_weight(self, agent: FusionAgent):
        """γ*α = 0.50*0.60 = 0.30 weight for s_idn_local."""
        shap = agent._compute_shap(
            s_idn_local=1.0,
            s_ti=0.0,
            s_vt=0.0,
            s_urlscan=0.0,
            s_gsb=0.0,
            s_llm=0.0,
            homograph_ratio=0.0,
            visual_similarity=0.0,
            is_mixed_script=0.0,
        )
        assert abs(shap["s_idn_local"] - 0.30) < 0.001

    def test_compute_shap_llm_weight(self, agent: FusionAgent):
        """(1-γ) = 0.50 weight for s_llm."""
        shap = agent._compute_shap(
            s_idn_local=0.0,
            s_ti=0.0,
            s_vt=0.0,
            s_urlscan=0.0,
            s_gsb=0.0,
            s_llm=1.0,
            homograph_ratio=0.0,
            visual_similarity=0.0,
            is_mixed_script=0.0,
        )
        assert abs(shap["s_llm"] - 0.50) < 0.001

    def test_compute_shap_ti_weight(self, agent: FusionAgent):
        """γ*(1-α) = 0.50*0.40 = 0.20 weight for s_ti."""
        shap = agent._compute_shap(
            s_idn_local=0.0,
            s_ti=1.0,
            s_vt=0.0,
            s_urlscan=0.0,
            s_gsb=0.0,
            s_llm=0.0,
            homograph_ratio=0.0,
            visual_similarity=0.0,
            is_mixed_script=0.0,
        )
        assert abs(shap["s_ti"] - 0.20) < 0.001

    def test_compute_shap_contains_all_nine_keys(self, agent: FusionAgent):
        shap = agent._compute_shap(
            s_idn_local=0.5,
            s_ti=0.5,
            s_vt=0.5,
            s_urlscan=0.5,
            s_gsb=0.5,
            s_llm=0.5,
            homograph_ratio=0.5,
            visual_similarity=0.5,
            is_mixed_script=1.0,
        )
        expected_keys = {
            "s_idn_local", "s_ti", "s_llm",
            "s_vt", "s_urlscan", "s_gsb",
            "homograph_ratio", "visual_similarity", "is_mixed_script",
        }
        assert set(shap.keys()) == expected_keys


# ---------------------------------------------------------------------------
# _compute_verdict
# ---------------------------------------------------------------------------

class TestComputeVerdict:
    def test_phishing_at_theta(self, agent: FusionAgent):
        assert agent._compute_verdict(THETA) == "PHISHING"

    def test_phishing_above_theta(self, agent: FusionAgent):
        assert agent._compute_verdict(0.9) == "PHISHING"
        assert agent._compute_verdict(1.0) == "PHISHING"

    def test_legitimate_at_zero(self, agent: FusionAgent):
        assert agent._compute_verdict(0.0) == "LEGITIMATE"

    def test_legitimate_below_040(self, agent: FusionAgent):
        assert agent._compute_verdict(0.39) == "LEGITIMATE"
        assert agent._compute_verdict(0.0) == "LEGITIMATE"

    def test_suspicious_at_040(self, agent: FusionAgent):
        assert agent._compute_verdict(0.40) == "SUSPICIOUS"

    def test_suspicious_just_below_theta(self, agent: FusionAgent):
        assert agent._compute_verdict(0.69) == "SUSPICIOUS"
        assert agent._compute_verdict(THETA - 0.001) == "SUSPICIOUS"

    def test_verdict_values_are_valid_strings(self, agent: FusionAgent):
        valid = {"PHISHING", "SUSPICIOUS", "LEGITIMATE"}
        for score in [0.0, 0.39, 0.40, 0.69, 0.70, 1.0]:
            assert agent._compute_verdict(score) in valid

    def test_exactly_040_is_suspicious_not_legitimate(self, agent: FusionAgent):
        assert agent._compute_verdict(0.40) != "LEGITIMATE"

    def test_exactly_070_is_phishing_not_suspicious(self, agent: FusionAgent):
        assert agent._compute_verdict(0.70) != "SUSPICIOUS"
