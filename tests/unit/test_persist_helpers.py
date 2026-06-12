"""Coverage tests for _persist_incident and _persist_manual_report helpers."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from unittest.mock import MagicMock

from schemas.analyze import (
    AgentScores,
    AnalyzeRequest,
    AnalyzeResponse,
    IDNResult,
    ShapExplanation,
    TIResult,
)


def _make_body(email_hash: str | None = None) -> AnalyzeRequest:
    """Minimal AnalyzeRequest body for _persist_incident tests."""
    body = MagicMock(spec=AnalyzeRequest)
    body.email_hash = email_hash
    body.email_subject = ""
    body.email_from = ""
    body.email_to = ""
    body.all_urls = []
    return body


def _make_response(verdict: str = "PHISHING", s_risk: float = 0.85) -> AnalyzeResponse:
    return AnalyzeResponse(
        request_id=str(uuid.uuid4()),
        url="https://рaypal.com/login",
        domain="рaypal.com",
        verdict=verdict,
        s_risk=s_risk,
        agent_scores=AgentScores(
            s_idn_local=0.90, s_ti=0.89, s_idn=0.90, s_llm=0.80, s_risk=s_risk,
        ),
        idn_result=IDNResult(
            domain_unicode="рaypal",
            confusable_chars=["р"],
            homograph_ratio=0.333,
            visual_similarity=0.857,
            s_idn_local=0.90,
            is_mixed_script=True,
            is_suspicious=True,
        ),
        ti_result=TIResult(s_vt=0.9, s_urlscan=0.8, s_gsb=1.0, s_ti=0.89),
        llm_reason="Test reason",
        shap_explanation=ShapExplanation(
            feature_contributions={
                "s_idn_local": 0.27, "s_ti": 0.18, "s_llm": 0.40,
                "s_vt": 0.09, "s_urlscan": 0.05, "s_gsb": 0.04,
                "homograph_ratio": 0.04, "visual_similarity": 0.06,
                "is_mixed_script": 0.03,
            }
        ),
        processing_ms=100.0,
        timestamp=datetime.now(timezone.utc),
    )


# ─── _persist_incident ────────────────────────────────────────────────────────

class TestPersistIncident:
    """Lines 200-231 in analyze_router.py."""

    @pytest.mark.asyncio
    async def test_success_calls_execute(self):
        from services.persistence import _persist_incident
        response = _make_response()
        with patch("models.database.execute", new_callable=AsyncMock) as mock_exec:
            await _persist_incident(response, _make_body(email_hash="abc123"))
        mock_exec.assert_awaited_once()
        call_args = mock_exec.call_args
        # First positional arg is the SQL, second is the request_id
        assert call_args[0][1] == response.request_id

    @pytest.mark.asyncio
    async def test_success_with_none_email_hash(self):
        from services.persistence import _persist_incident
        response = _make_response()
        with patch("models.database.execute", new_callable=AsyncMock) as mock_exec:
            await _persist_incident(response, _make_body(email_hash=None))
        mock_exec.assert_awaited_once()
        # email_hash should default to empty string
        call_args = mock_exec.call_args[0]
        assert call_args[2] == ""  # email_hash positional arg

    @pytest.mark.asyncio
    async def test_db_failure_is_swallowed(self):
        """DB errors must never propagate — fire-and-forget guarantees API response."""
        from services.persistence import _persist_incident
        response = _make_response()
        with patch("models.database.execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.side_effect = Exception("DB connection lost")
            # Must not raise
            await _persist_incident(response, _make_body(email_hash="hash"))

    @pytest.mark.asyncio
    async def test_legitimate_verdict_persisted_correctly(self):
        from services.persistence import _persist_incident
        response = _make_response(verdict="LEGITIMATE", s_risk=0.10)
        with patch("models.database.execute", new_callable=AsyncMock) as mock_exec:
            await _persist_incident(response, _make_body(email_hash=None))
        call_args = mock_exec.call_args[0]
        assert call_args[5] == response.verdict  # verdict positional arg


# ─── _persist_manual_report ───────────────────────────────────────────────────

class TestPersistManualReport:
    """Lines 346-378 in analyze_router.py."""

    @pytest.mark.asyncio
    async def test_success_calls_execute(self):
        from services.persistence import _persist_manual_report
        report_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        with patch("models.database.execute", new_callable=AsyncMock) as mock_exec:
            await _persist_manual_report(
                report_id=report_id,
                url="https://evil.com/phish",
                verdict="PHISHING",
                reporter="admin",
                note="Looks like phishing",
                timestamp=now,
            )
        mock_exec.assert_awaited_once()
        call_args = mock_exec.call_args[0]
        assert call_args[1] == report_id

    @pytest.mark.asyncio
    async def test_phishing_verdict_sets_s_risk_1(self):
        from services.persistence import _persist_manual_report
        now = datetime.now(timezone.utc)
        with patch("models.database.execute", new_callable=AsyncMock) as mock_exec:
            await _persist_manual_report(
                report_id="rep1",
                url="https://evil.com",
                verdict="PHISHING",
                reporter="admin",
                note="",
                timestamp=now,
            )
        call_args = mock_exec.call_args[0]
        # s_risk is 1.0 for PHISHING (index 6 in SQL params)
        assert call_args[6] == 1.0

    @pytest.mark.asyncio
    async def test_suspicious_verdict_sets_s_risk_half(self):
        from services.persistence import _persist_manual_report
        now = datetime.now(timezone.utc)
        with patch("models.database.execute", new_callable=AsyncMock) as mock_exec:
            await _persist_manual_report(
                report_id="rep2",
                url="https://dodgy.com",
                verdict="SUSPICIOUS",
                reporter="admin",
                note="",
                timestamp=now,
            )
        call_args = mock_exec.call_args[0]
        # s_risk is 0.5 for SUSPICIOUS
        assert call_args[6] == 0.5

    @pytest.mark.asyncio
    async def test_non_http_url_uses_url_as_domain(self):
        """When URL has no http scheme, domain = url itself."""
        from services.persistence import _persist_manual_report
        now = datetime.now(timezone.utc)
        with patch("models.database.execute", new_callable=AsyncMock) as mock_exec:
            await _persist_manual_report(
                report_id="rep3",
                url="evil.com",
                verdict="PHISHING",
                reporter="admin",
                note="",
                timestamp=now,
            )
        mock_exec.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_db_failure_is_swallowed(self):
        """DB failures in manual report persist must never propagate."""
        from services.persistence import _persist_manual_report
        now = datetime.now(timezone.utc)
        with patch("models.database.execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.side_effect = RuntimeError("DB down")
            await _persist_manual_report(
                report_id="rep4",
                url="https://evil.com",
                verdict="PHISHING",
                reporter="admin",
                note="",
                timestamp=now,
            )

    @pytest.mark.asyncio
    async def test_empty_note_uses_default_reason(self):
        from services.persistence import _persist_manual_report
        now = datetime.now(timezone.utc)
        with patch("models.database.execute", new_callable=AsyncMock) as mock_exec:
            await _persist_manual_report(
                report_id="rep5",
                url="https://evil.com",
                verdict="PHISHING",
                reporter="admin",
                note="",
                timestamp=now,
            )
        call_args = mock_exec.call_args[0]
        # llm_reason (index 10) should be "Manual report"
        assert call_args[10] == "Manual report"

    @pytest.mark.asyncio
    async def test_non_empty_note_included_in_reason(self):
        from services.persistence import _persist_manual_report
        now = datetime.now(timezone.utc)
        with patch("models.database.execute", new_callable=AsyncMock) as mock_exec:
            await _persist_manual_report(
                report_id="rep6",
                url="https://evil.com",
                verdict="PHISHING",
                reporter="admin",
                note="Verified phishing",
                timestamp=now,
            )
        call_args = mock_exec.call_args[0]
        assert "Verified phishing" in call_args[10]
