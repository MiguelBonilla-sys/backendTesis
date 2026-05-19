"""Tests for schemas/analyze.py — Pydantic v2 validation."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from schemas.analyze import (
    AgentScores,
    AnalyzeRequest,
    AnalyzeResponse,
    IDNResult,
    ShapExplanation,
    TIResult,
)


class TestAnalyzeRequest:
    def test_valid_https_url(self):
        req = AnalyzeRequest(url="https://paypal.com/login")
        assert req.url == "https://paypal.com/login"

    def test_valid_http_url(self):
        req = AnalyzeRequest(url="http://paypal.com")
        assert req.url == "http://paypal.com"

    def test_url_strips_whitespace(self):
        req = AnalyzeRequest(url="  https://paypal.com  ")
        assert req.url == "https://paypal.com"

    def test_url_without_scheme_raises(self):
        with pytest.raises(ValidationError):
            AnalyzeRequest(url="paypal.com")

    def test_ftp_url_raises(self):
        with pytest.raises(ValidationError):
            AnalyzeRequest(url="ftp://paypal.com")

    def test_empty_url_raises(self):
        with pytest.raises(ValidationError):
            AnalyzeRequest(url="")

    def test_optional_email_hash_defaults_none(self):
        req = AnalyzeRequest(url="https://paypal.com")
        assert req.email_hash is None

    def test_optional_email_body_defaults_none(self):
        req = AnalyzeRequest(url="https://paypal.com")
        assert req.email_body_snippet is None

    def test_email_hash_stored(self):
        req = AnalyzeRequest(url="https://paypal.com", email_hash="abc123")
        assert req.email_hash == "abc123"

    def test_email_body_snippet_stored(self):
        req = AnalyzeRequest(url="https://paypal.com", email_body_snippet="Click here")
        assert req.email_body_snippet == "Click here"

    def test_url_max_length_2048(self):
        # "https://a.com/" = 14 chars, so we need >2034 more to exceed 2048
        long_url = "https://a.com/" + "a" * 2040  # total 2054 > 2048
        with pytest.raises(ValidationError):
            AnalyzeRequest(url=long_url)


class TestIDNResult:
    def test_valid_idn_result(self):
        result = IDNResult(
            domain_unicode="рaypal",
            confusable_chars=["р"],
            homograph_ratio=0.333,
            visual_similarity=0.857,
            s_idn_local=0.90,
            is_mixed_script=True,
            is_suspicious=True,
        )
        assert result.domain_unicode == "рaypal"
        assert result.s_idn_local == 0.90

    def test_confusable_chars_empty_list(self):
        result = IDNResult(
            domain_unicode="paypal",
            confusable_chars=[],
            homograph_ratio=0.0,
            visual_similarity=0.0,
            s_idn_local=0.0,
            is_mixed_script=False,
            is_suspicious=False,
        )
        assert result.confusable_chars == []

    def test_is_mixed_script_bool(self):
        result = IDNResult(
            domain_unicode="paypal",
            confusable_chars=[],
            homograph_ratio=0.0,
            visual_similarity=0.0,
            s_idn_local=0.0,
            is_mixed_script=False,
            is_suspicious=False,
        )
        assert isinstance(result.is_mixed_script, bool)


class TestTIResult:
    def test_valid_ti_result(self):
        ti = TIResult(s_vt=0.9, s_urlscan=0.8, s_gsb=1.0, s_ti=0.89)
        assert ti.s_vt == 0.9
        assert ti.s_ti == 0.89

    def test_zero_scores(self):
        ti = TIResult(s_vt=0.0, s_urlscan=0.0, s_gsb=0.0, s_ti=0.0)
        assert ti.s_ti == 0.0


class TestAgentScores:
    def test_valid_agent_scores(self):
        scores = AgentScores(
            s_idn_local=0.9,
            s_ti=0.89,
            s_idn=0.9,
            s_llm=0.8,
            s_risk=0.85,
        )
        assert scores.s_risk == 0.85


class TestShapExplanation:
    def test_valid_shap(self):
        shap = ShapExplanation(
            feature_contributions={"s_idn_local": 0.3, "s_llm": 0.5}
        )
        assert shap.feature_contributions["s_idn_local"] == 0.3

    def test_empty_contributions(self):
        shap = ShapExplanation(feature_contributions={})
        assert shap.feature_contributions == {}


class TestAnalyzeResponse:
    def test_valid_response(self):
        response = AnalyzeResponse(
            request_id="test-uuid",
            url="https://paypal.com",
            domain="paypal.com",
            verdict="PHISHING",
            s_risk=0.85,
            agent_scores=AgentScores(
                s_idn_local=0.9, s_ti=0.89, s_idn=0.9, s_llm=0.8, s_risk=0.85
            ),
            idn_result=IDNResult(
                domain_unicode="paypal",
                confusable_chars=[],
                homograph_ratio=0.0,
                visual_similarity=0.0,
                s_idn_local=0.9,
                is_mixed_script=False,
                is_suspicious=True,
            ),
            ti_result=TIResult(s_vt=0.9, s_urlscan=0.8, s_gsb=1.0, s_ti=0.89),
            llm_reason="Suspicious",
            shap_explanation=ShapExplanation(feature_contributions={"s_llm": 0.4}),
            processing_ms=100.0,
            timestamp=datetime.now(timezone.utc),
        )
        assert response.verdict == "PHISHING"
        assert 0.0 <= response.s_risk <= 1.0

    def test_invalid_verdict_raises(self):
        with pytest.raises(ValidationError):
            AnalyzeResponse(
                request_id="test-uuid",
                url="https://paypal.com",
                domain="paypal.com",
                verdict="UNKNOWN_VERDICT",
                s_risk=0.85,
                agent_scores=AgentScores(
                    s_idn_local=0.9, s_ti=0.89, s_idn=0.9, s_llm=0.8, s_risk=0.85
                ),
                idn_result=IDNResult(
                    domain_unicode="paypal",
                    confusable_chars=[],
                    homograph_ratio=0.0,
                    visual_similarity=0.0,
                    s_idn_local=0.9,
                    is_mixed_script=False,
                    is_suspicious=True,
                ),
                ti_result=TIResult(s_vt=0.9, s_urlscan=0.8, s_gsb=1.0, s_ti=0.89),
                llm_reason="Suspicious",
                shap_explanation=ShapExplanation(feature_contributions={}),
                processing_ms=100.0,
                timestamp=datetime.now(timezone.utc),
            )

    def test_s_risk_must_be_between_0_and_1(self):
        with pytest.raises(ValidationError):
            AnalyzeResponse(
                request_id="test-uuid",
                url="https://paypal.com",
                domain="paypal.com",
                verdict="PHISHING",
                s_risk=1.5,  # out of bounds
                agent_scores=AgentScores(
                    s_idn_local=0.9, s_ti=0.89, s_idn=0.9, s_llm=0.8, s_risk=0.85
                ),
                idn_result=IDNResult(
                    domain_unicode="paypal",
                    confusable_chars=[],
                    homograph_ratio=0.0,
                    visual_similarity=0.0,
                    s_idn_local=0.9,
                    is_mixed_script=False,
                    is_suspicious=True,
                ),
                ti_result=TIResult(s_vt=0.9, s_urlscan=0.8, s_gsb=1.0, s_ti=0.89),
                llm_reason="Suspicious",
                shap_explanation=ShapExplanation(feature_contributions={}),
                processing_ms=100.0,
                timestamp=datetime.now(timezone.utc),
            )
