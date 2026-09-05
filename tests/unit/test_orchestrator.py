"""Tests for services/orchestrator.py — AnalysisConductor."""
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest

from schemas.analyze import (
    AgentScores,
    AnalyzeResponse,
    IDNResult,
    ShapExplanation,
    TIResult,
)
from services.orchestrator import AnalysisConductor, apply_conductor


def _resp(verdict="SUSPICIOUS", s_risk=0.55, s_hf=0.5, s_llm=0.5, s_idn_local=0.2):
    return AnalyzeResponse(
        request_id=str(uuid.uuid4()),
        url="https://example.com/login",
        domain="example.com",
        verdict=verdict,
        s_risk=s_risk,
        agent_scores=AgentScores(
            s_idn_local=s_idn_local, s_ti=0.3, s_idn=s_idn_local,
            s_llm=s_llm, s_hf=s_hf, s_probe=0.0, s_risk=s_risk,
        ),
        idn_result=IDNResult(
            domain_unicode="example.com", confusable_chars=[], homograph_ratio=0.0,
            visual_similarity=0.1, s_idn_local=s_idn_local, is_mixed_script=False,
            is_suspicious=False,
        ),
        ti_result=TIResult(s_vt=0.3, s_urlscan=0.2, s_gsb=0.1, s_ti=0.3),
        llm_reason="borderline",
        shap_explanation=ShapExplanation(feature_contributions={"s_llm": 0.2, "s_ti": 0.1}),
        reasons=["Domain is newly registered"],
        processing_ms=100.0,
        timestamp=datetime.now(UTC),
    )


@pytest.fixture
def conductor() -> AnalysisConductor:
    return AnalysisConductor()


class TestShouldReview:
    def test_suspicious_always_reviewed(self, conductor):
        assert conductor.should_review(_resp(verdict="SUSPICIOUS")) is True

    def test_hf_llm_conflict_triggers(self, conductor):
        assert conductor.should_review(
            _resp(verdict="LEGITIMATE", s_risk=0.3, s_hf=0.85, s_llm=0.2)
        ) is True

    def test_idn_shout_without_phishing_verdict_triggers(self, conductor):
        assert conductor.should_review(
            _resp(verdict="LEGITIMATE", s_risk=0.3, s_idn_local=0.6)
        ) is True

    def test_clear_phishing_not_reviewed(self, conductor):
        assert conductor.should_review(
            _resp(verdict="PHISHING", s_risk=0.9, s_hf=0.9, s_llm=0.9, s_idn_local=0.9)
        ) is False

    def test_clear_legit_not_reviewed(self, conductor):
        assert conductor.should_review(
            _resp(verdict="LEGITIMATE", s_risk=0.1, s_hf=0.1, s_llm=0.1)
        ) is False


class TestReview:
    async def test_override_changes_verdict_and_prepends_reason(self, conductor):
        r = _resp(verdict="SUSPICIOUS")
        with patch(
            "services.orchestrator.llm_agent.adjudicate",
            new_callable=AsyncMock,
            return_value=("PHISHING", "Cyrillic lookalike of a bank domain"),
        ):
            out = await conductor.review(r)
        assert out.verdict == "PHISHING"
        assert out.reasons[0].startswith("[Conductor] Re-arbitrado SUSPICIOUS → PHISHING")
        assert out.s_risk == r.s_risk  # s_risk intacto

    async def test_confirmation_keeps_verdict_adds_note(self, conductor):
        r = _resp(verdict="SUSPICIOUS")
        with patch(
            "services.orchestrator.llm_agent.adjudicate",
            new_callable=AsyncMock,
            return_value=("SUSPICIOUS", "genuinely ambiguous"),
        ):
            out = await conductor.review(r)
        assert out.verdict == "SUSPICIOUS"
        assert out.reasons[0].startswith("[Conductor] Confirma SUSPICIOUS")

    async def test_empty_verdict_keeps_deterministic(self, conductor):
        r = _resp(verdict="SUSPICIOUS")
        before = list(r.reasons)
        with patch(
            "services.orchestrator.llm_agent.adjudicate",
            new_callable=AsyncMock,
            return_value=("", ""),
        ):
            out = await conductor.review(r)
        assert out.verdict == "SUSPICIOUS"
        assert out.reasons == before

    async def test_no_review_when_case_is_clear(self, conductor):
        r = _resp(verdict="PHISHING", s_risk=0.95, s_hf=0.9, s_llm=0.9, s_idn_local=0.9)
        with patch(
            "services.orchestrator.llm_agent.adjudicate", new_callable=AsyncMock
        ) as adj:
            out = await conductor.review(r)
        adj.assert_not_awaited()
        assert out.verdict == "PHISHING"

    async def test_emits_pseudo_label_on_strong_agreement(self, conductor):
        conductor.pseudo_labels.clear()
        # LEGITIMATE con s_idn_local alto → dispara review; LLM confirma LEGITIMATE
        r = _resp(verdict="LEGITIMATE", s_risk=0.35, s_idn_local=0.55)
        with patch(
            "services.orchestrator.llm_agent.adjudicate",
            new_callable=AsyncMock, return_value=("LEGITIMATE", "confirmed benign"),
        ):
            await conductor.review(r)
        assert len(conductor.pseudo_labels) == 1
        *_signals, is_phish, is_pseudo = conductor.pseudo_labels[0]
        assert is_phish is False and is_pseudo is True

    async def test_no_pseudo_label_without_agreement(self, conductor):
        conductor.pseudo_labels.clear()
        r = _resp(verdict="SUSPICIOUS")
        with patch(
            "services.orchestrator.llm_agent.adjudicate",
            new_callable=AsyncMock, return_value=("PHISHING", "x"),
        ):
            await conductor.review(r)
        assert len(conductor.pseudo_labels) == 0  # verdicts distintos

    async def test_drift_alarm_after_window_of_overrides(self, conductor, caplog):
        with patch(
            "services.orchestrator.llm_agent.adjudicate",
            new_callable=AsyncMock, return_value=("PHISHING", "x"),
        ):
            for _ in range(100):
                await conductor.review(_resp(verdict="SUSPICIOUS"))
        assert conductor.override_rate == 1.0


class TestShapDominanceTrigger:
    def test_dominant_signal_borderline_triggers(self, conductor):
        r = _resp(verdict="LEGITIMATE", s_risk=0.35)
        r.shap_explanation.feature_contributions = {"s_hf": 0.30, "s_ti": 0.05}
        assert conductor.should_review(r) is True

    def test_dominant_signal_but_low_risk_not_triggered(self, conductor):
        r = _resp(verdict="LEGITIMATE", s_risk=0.10)
        r.shap_explanation.feature_contributions = {"s_hf": 0.08, "s_ti": 0.02}
        assert conductor.should_review(r) is False


class TestApplyConductor:
    async def test_noop_when_disabled(self):
        r = _resp(verdict="SUSPICIOUS")
        with patch("services.orchestrator.settings.CONDUCTOR_ENABLED", False), \
             patch("services.orchestrator.conductor.review", new_callable=AsyncMock) as rev:
            out = await apply_conductor(r)
        rev.assert_not_awaited()
        assert out is r

    async def test_runs_when_enabled(self):
        r = _resp(verdict="SUSPICIOUS")
        with patch("services.orchestrator.settings.CONDUCTOR_ENABLED", True), \
             patch(
                 "services.orchestrator.conductor.review",
                 new_callable=AsyncMock, return_value=r,
             ) as rev:
            await apply_conductor(r)
        rev.assert_awaited_once()
