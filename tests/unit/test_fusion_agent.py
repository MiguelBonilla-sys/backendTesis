"""Tests for agents/fusion_agent.py"""
from __future__ import annotations

import time

import pytest

from agents.fusion_agent import FusionAgent
from core.constants import ALPHA, GAMMA, THETA
from schemas.analyze import EmailSignals, IDNResult, TIResult


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
        """S_risk = γ * S_IDN + (1-γ) * s_llm_combined; s_llm_combined = (1-HF_W)*s_llm + HF_W*s_hf"""
        from core.constants import HF_WEIGHT
        s_llm = 0.7
        s_hf = 0.6
        response = await agent.fuse(
            url="https://рaypal.com",
            domain="рaypal.com",
            idn_result=phishing_idn,
            ti_result=phishing_ti,
            s_llm=s_llm,
            llm_reason="Test",
            start_time=time.perf_counter(),
            s_hf=s_hf,
        )
        expected_s_idn = ALPHA * phishing_idn.s_idn_local + (1 - ALPHA) * phishing_ti.s_ti
        expected_combined = (1 - HF_WEIGHT) * s_llm + HF_WEIGHT * s_hf
        expected_s_risk = GAMMA * expected_s_idn + (1 - GAMMA) * expected_combined
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
        """All zero inputs (including s_hf=0.0) → all SHAP contributions are zero."""
        response = await agent.fuse(
            url="https://paypal.com",
            domain="paypal.com",
            idn_result=legit_idn,
            ti_result=legit_ti,
            s_llm=0.0,
            llm_reason="Clean",
            start_time=time.perf_counter(),
            s_hf=0.0,
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
            s_hf=0.0,
            homograph_ratio=0.0,
            visual_similarity=0.0,
            is_mixed_script=0.0,
        )
        assert abs(shap["s_idn_local"] - 0.30) < 0.001

    def test_compute_shap_llm_weight(self, agent: FusionAgent):
        """(1-γ)*(1-HF_WEIGHT) = 0.50*0.60 = 0.30 weight for s_llm."""
        from core.constants import HF_WEIGHT
        shap = agent._compute_shap(
            s_idn_local=0.0,
            s_ti=0.0,
            s_vt=0.0,
            s_urlscan=0.0,
            s_gsb=0.0,
            s_llm=1.0,
            s_hf=0.0,
            homograph_ratio=0.0,
            visual_similarity=0.0,
            is_mixed_script=0.0,
        )
        expected = (1.0 - GAMMA) * (1.0 - HF_WEIGHT)   # 0.50 * 0.60 = 0.30
        assert abs(shap["s_llm"] - expected) < 0.001

    def test_compute_shap_hf_weight(self, agent: FusionAgent):
        """(1-γ)*HF_WEIGHT = 0.50*0.40 = 0.20 weight for s_hf."""
        from core.constants import HF_WEIGHT
        shap = agent._compute_shap(
            s_idn_local=0.0,
            s_ti=0.0,
            s_vt=0.0,
            s_urlscan=0.0,
            s_gsb=0.0,
            s_llm=0.0,
            s_hf=1.0,
            homograph_ratio=0.0,
            visual_similarity=0.0,
            is_mixed_script=0.0,
        )
        expected = (1.0 - GAMMA) * HF_WEIGHT   # 0.50 * 0.40 = 0.20
        assert abs(shap["s_hf"] - expected) < 0.001

    def test_compute_shap_ti_weight(self, agent: FusionAgent):
        """γ*(1-α) = 0.50*0.40 = 0.20 weight for s_ti."""
        shap = agent._compute_shap(
            s_idn_local=0.0,
            s_ti=1.0,
            s_vt=0.0,
            s_urlscan=0.0,
            s_gsb=0.0,
            s_llm=0.0,
            s_hf=0.0,
            homograph_ratio=0.0,
            visual_similarity=0.0,
            is_mixed_script=0.0,
        )
        assert abs(shap["s_ti"] - 0.20) < 0.001

    def test_compute_shap_contains_all_ten_keys(self, agent: FusionAgent):
        shap = agent._compute_shap(
            s_idn_local=0.5,
            s_ti=0.5,
            s_vt=0.5,
            s_urlscan=0.5,
            s_gsb=0.5,
            s_llm=0.5,
            s_hf=0.5,
            homograph_ratio=0.5,
            visual_similarity=0.5,
            is_mixed_script=1.0,
        )
        expected_keys = {
            "s_idn_local", "s_ti", "s_llm", "s_hf",
            "s_vt", "s_urlscan", "s_gsb",
            "homograph_ratio", "visual_similarity", "is_mixed_script",
            "s_email", "s_probe",
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


# ---------------------------------------------------------------------------
# _compute_reasons
# ---------------------------------------------------------------------------

class TestComputeReasons:
    @pytest.fixture
    def clean_idn(self) -> IDNResult:
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
    def clean_ti(self) -> TIResult:
        return TIResult(s_vt=0.0, s_urlscan=0.0, s_gsb=0.0, s_ti=0.0)

    @pytest.fixture
    def agent(self) -> FusionAgent:
        return FusionAgent()

    def test_always_returns_at_least_one_reason(self, agent, clean_idn, clean_ti):
        reasons = agent._compute_reasons(clean_idn, clean_ti, 0.0, "LEGITIMATE")
        assert len(reasons) >= 1

    def test_clean_domain_gets_no_suspicious_message(self, agent, clean_idn, clean_ti):
        reasons = agent._compute_reasons(clean_idn, clean_ti, 0.0, "LEGITIMATE")
        assert any("No suspicious" in r for r in reasons)

    def test_mixed_script_produces_reason(self, agent, clean_ti):
        idn = IDNResult(
            domain_unicode="рaypal",
            confusable_chars=["р"],
            homograph_ratio=0.167,
            visual_similarity=0.857,
            s_idn_local=0.85,
            is_mixed_script=True,
            is_suspicious=True,
        )
        reasons = agent._compute_reasons(idn, clean_ti, 0.0, "SUSPICIOUS")
        assert any("mixed-script" in r.lower() or "homograph" in r.lower() for r in reasons)

    def test_high_homograph_ratio_produces_reason(self, agent, clean_ti):
        idn = IDNResult(
            domain_unicode="pаypаl",
            confusable_chars=["а", "а"],
            homograph_ratio=0.40,  # > HOMOGRAPH_THRESHOLD (0.30)
            visual_similarity=0.0,
            s_idn_local=0.50,
            is_mixed_script=False,
            is_suspicious=True,
        )
        reasons = agent._compute_reasons(idn, clean_ti, 0.0, "SUSPICIOUS")
        assert any("40%" in r or "confusable" in r.lower() for r in reasons)

    def test_confusable_chars_listed_in_reason(self, agent, clean_ti):
        idn = IDNResult(
            domain_unicode="рaypal",
            confusable_chars=["р"],
            homograph_ratio=0.10,
            visual_similarity=0.0,
            s_idn_local=0.20,
            is_mixed_script=False,
            is_suspicious=True,
        )
        reasons = agent._compute_reasons(idn, clean_ti, 0.0, "LEGITIMATE")
        assert any("confusable" in r.lower() for r in reasons)

    def test_vt_flag_produces_reason(self, agent, clean_idn):
        ti = TIResult(s_vt=0.50, s_urlscan=0.0, s_gsb=0.0, s_ti=0.25)
        reasons = agent._compute_reasons(clean_idn, ti, 0.0, "LEGITIMATE")
        assert any("virustotal" in r.lower() for r in reasons)

    def test_gsb_flag_produces_reason(self, agent, clean_idn):
        ti = TIResult(s_vt=0.0, s_urlscan=0.0, s_gsb=1.0, s_ti=0.20)
        reasons = agent._compute_reasons(clean_idn, ti, 0.0, "SUSPICIOUS")
        assert any("safe browsing" in r.lower() for r in reasons)

    def test_newly_registered_domain_produces_reason(self, agent, clean_idn):
        ti = TIResult(
            s_vt=0.0, s_urlscan=0.0, s_gsb=0.0, s_ti=0.0,
            is_newly_registered=True, domain_age_days=5,
        )
        reasons = agent._compute_reasons(clean_idn, ti, 0.0, "SUSPICIOUS")
        assert any("newly registered" in r.lower() or "5 days" in r for r in reasons)

    def test_high_llm_score_produces_reason(self, agent, clean_idn, clean_ti):
        reasons = agent._compute_reasons(clean_idn, clean_ti, 0.85, "PHISHING")
        assert any("llm" in r.lower() or "semantic" in r.lower() for r in reasons)

    def test_email_urgency_signal_produces_reason(self, agent, clean_idn, clean_ti):
        signals = EmailSignals(
            sender_domain="evil.com",
            return_path_domain="evil.com",
            is_urgent=True,
            urgency_score=0.6,
            spf_pass=True,
            dkim_pass=True,
        )
        reasons = agent._compute_reasons(clean_idn, clean_ti, 0.0, "LEGITIMATE", signals)
        assert any("urgency" in r.lower() or "pressure" in r.lower() for r in reasons)

    def test_sender_domain_mismatch_produces_reason(self, agent, clean_idn, clean_ti):
        signals = EmailSignals(
            sender_domain="sender.com",
            return_path_domain="different.com",
            sender_domain_mismatch=True,
            spf_pass=True,
            dkim_pass=True,
        )
        reasons = agent._compute_reasons(clean_idn, clean_ti, 0.0, "LEGITIMATE", signals)
        assert any("sender" in r.lower() and "return" in r.lower() for r in reasons)

    def test_returns_list_of_strings(self, agent, clean_idn, clean_ti):
        reasons = agent._compute_reasons(clean_idn, clean_ti, 0.0, "LEGITIMATE")
        assert isinstance(reasons, list)
        assert all(isinstance(r, str) for r in reasons)

    @pytest.mark.asyncio
    async def test_fuse_response_contains_reasons_list(self, agent):
        idn = IDNResult(
            domain_unicode="рaypal",
            confusable_chars=["р"],
            homograph_ratio=0.333,
            visual_similarity=0.857,
            s_idn_local=0.90,
            is_mixed_script=True,
            is_suspicious=True,
        )
        ti = TIResult(s_vt=0.9, s_urlscan=0.8, s_gsb=1.0, s_ti=0.89)
        response = await agent.fuse(
            url="https://рaypal.com",
            domain="рaypal.com",
            idn_result=idn,
            ti_result=ti,
            s_llm=0.9,
            llm_reason="Phishing detected",
            start_time=time.perf_counter(),
        )
        assert isinstance(response.reasons, list)
        assert len(response.reasons) >= 1

    @pytest.mark.asyncio
    async def test_fuse_reasons_consistent_with_verdict(self, agent):
        """PHISHING verdict must not produce 'No suspicious indicators'."""
        idn = IDNResult(
            domain_unicode="рaypal",
            confusable_chars=["р"],
            homograph_ratio=0.333,
            visual_similarity=0.857,
            s_idn_local=0.90,
            is_mixed_script=True,
            is_suspicious=True,
        )
        ti = TIResult(s_vt=0.9, s_urlscan=0.8, s_gsb=1.0, s_ti=0.89)
        response = await agent.fuse(
            url="https://рaypal.com",
            domain="рaypal.com",
            idn_result=idn,
            ti_result=ti,
            s_llm=0.9,
            llm_reason="Phishing",
            start_time=time.perf_counter(),
        )
        assert response.verdict == "PHISHING"
        assert not any("No suspicious" in r for r in response.reasons)


# ---------------------------------------------------------------------------
# SHAP reconstruction property (T2 — docs/tasks.md)
# ---------------------------------------------------------------------------

class TestShapReconstruction:
    """La suma de features primarios debe reconstruir s_risk (error < 0.01)."""

    PRIMARY = ("s_idn_local", "s_ti", "s_llm", "s_hf", "s_email", "s_probe")

    @staticmethod
    def _primary_sum(shap: dict[str, float]) -> float:
        return sum(shap[k] for k in TestShapReconstruction.PRIMARY)

    @pytest.mark.asyncio
    async def test_reconstruction_without_boosts(
        self, agent: FusionAgent, phishing_idn: IDNResult, phishing_ti: TIResult
    ):
        response = await agent.fuse(
            url="https://рaypal.com",
            domain="рaypal.com",
            idn_result=phishing_idn,
            ti_result=phishing_ti,
            s_llm=0.9,
            llm_reason="Phishing",
            start_time=time.perf_counter(),
            s_hf=0.8,
        )
        shap = response.shap_explanation.feature_contributions
        assert abs(self._primary_sum(shap) - response.s_risk) < 0.01

    @pytest.mark.asyncio
    async def test_reconstruction_with_boosts_unclamped(
        self, agent: FusionAgent, legit_idn: IDNResult, legit_ti: TIResult
    ):
        signals = EmailSignals(
            sender_domain="bank-secure.xyz",
            return_path_domain="other.ru",
            sender_domain_mismatch=True,
        )
        response = await agent.fuse(
            url="https://bank-secure.xyz",
            domain="bank-secure.xyz",
            idn_result=legit_idn,
            ti_result=legit_ti,
            s_llm=0.2,
            llm_reason="Mild",
            start_time=time.perf_counter(),
            s_hf=0.3,
            email_signals=signals,
        )
        shap = response.shap_explanation.feature_contributions
        assert response.s_risk < 1.0
        assert abs(self._primary_sum(shap) - response.s_risk) < 0.01

    @pytest.mark.asyncio
    async def test_reconstruction_when_clamp_saturates(
        self, agent: FusionAgent, phishing_idn: IDNResult, phishing_ti: TIResult
    ):
        """Boosts empujan s_risk_pre > 1.0 → clamp → SHAP reescalado."""
        from schemas.analyze import WebProbeResult

        signals = EmailSignals(
            sender_domain="рaypal.com",
            return_path_domain="evil.ru",
            sender_domain_mismatch=True,
            has_suspicious_attachments=True,
            attachment_names=["invoice.exe"],
        )
        probe = WebProbeResult(s_probe=0.60)
        response = await agent.fuse(
            url="https://рaypal.com",
            domain="рaypal.com",
            idn_result=phishing_idn,
            ti_result=phishing_ti,
            s_llm=0.9,
            llm_reason="Phishing",
            start_time=time.perf_counter(),
            s_hf=0.9,
            email_signals=signals,
            probe_result=probe,
        )
        shap = response.shap_explanation.feature_contributions
        assert response.s_risk == 1.0
        assert abs(self._primary_sum(shap) - 1.0) < 0.01
        # las contribuciones reescaladas conservan el orden relativo
        assert shap["s_probe"] > 0.0
        assert shap["s_email"] > 0.0


# ---------------------------------------------------------------------------
# Probe boost gating (T3 — docs/tasks.md)
# ---------------------------------------------------------------------------

class TestProbeBoostGate:
    """El boost del probe solo aplica con sospecha pasiva previa y nunca
    sobre dominios confiables (allowlist institucional / top-1M)."""

    @staticmethod
    def _login_probe():
        from schemas.analyze import WebProbeResult

        return WebProbeResult(
            final_url="https://login.microsoftonline.com/",
            final_domain="login.microsoftonline.com",
            status_code=200,
            has_password_field=True,
            has_login_form=True,
            s_probe=0.45,
            probe_signals=["Login form with password field detected"],
        )

    @pytest.mark.asyncio
    async def test_trusted_domain_zeroes_probe_boost(
        self, agent: FusionAgent, legit_idn: IDNResult, legit_ti: TIResult
    ):
        """Página legítima de login → LEGITIMATE aunque tenga password field."""
        response = await agent.fuse(
            url="https://login.microsoftonline.com",
            domain="login.microsoftonline.com",
            idn_result=legit_idn,
            ti_result=legit_ti,
            s_llm=0.1,
            llm_reason="Legitimate login page",
            start_time=time.perf_counter(),
            s_hf=0.1,
            probe_result=self._login_probe(),
            probe_domain_trusted=True,
        )
        assert response.verdict == "LEGITIMATE"
        assert response.agent_scores.s_probe == 0.0
        assert response.shap_explanation.feature_contributions["s_probe"] == 0.0

    @pytest.mark.asyncio
    async def test_no_passive_suspicion_zeroes_probe_boost(
        self, agent: FusionAgent, legit_idn: IDNResult, legit_ti: TIResult
    ):
        """Sin sospecha base (s_base < gate), el probe no suma por sí solo."""
        response = await agent.fuse(
            url="https://unknown-login-page.com",
            domain="unknown-login-page.com",
            idn_result=legit_idn,
            ti_result=legit_ti,
            s_llm=0.1,
            llm_reason="Nothing semantic",
            start_time=time.perf_counter(),
            s_hf=0.1,
            probe_result=self._login_probe(),
            probe_domain_trusted=False,
        )
        assert response.agent_scores.s_probe == 0.0
        assert response.verdict == "LEGITIMATE"

    @pytest.mark.asyncio
    async def test_probe_boost_applies_with_passive_suspicion(
        self, agent: FusionAgent, phishing_idn: IDNResult, legit_ti: TIResult
    ):
        """Con sospecha IDN previa, el probe corrobora y sí suma."""
        response = await agent.fuse(
            url="https://рaypal.com",
            domain="рaypal.com",
            idn_result=phishing_idn,
            ti_result=legit_ti,
            s_llm=0.5,
            llm_reason="Suspicious",
            start_time=time.perf_counter(),
            s_hf=0.5,
            probe_result=self._login_probe(),
            probe_domain_trusted=False,
        )
        assert response.agent_scores.s_probe == pytest.approx(0.45, abs=1e-6)
        assert response.verdict == "PHISHING"
