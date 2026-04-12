"""Tests for data_pipeline/analysis_repo.py."""

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from data_pipeline.analysis_repo import save_full_analysis
from models.orm_models import AgentResult, Analysis, URLAnalysis, XAIReport


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_session() -> AsyncMock:
    """AsyncMock that behaves like AsyncSession with a working begin() and sync add()."""
    session = AsyncMock()
    # add() is sync in AsyncSession, AsyncMock makes it a coroutine by default.
    # We must explicitly set it to a MagicMock to avoid RuntimeWarnings about unawaited coroutines.
    session.add = MagicMock()
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=None)
    cm.__aexit__ = AsyncMock(return_value=False)
    session.begin = MagicMock(return_value=cm)
    return session


TRACE_ID = str(uuid.uuid4())

_IDN = {
    "normalized": "apple.com",
    "is_punycode": False,
    "confusables": [],
    "ratio_h": 0.0,
    "sim_v": 0.0,
    "s_idn_local": 0.1,
}

_LLM = {
    "s_llm": 0.2,
    "reasoning": "looks safe",
    "llm_degraded": False,
}

_FUSION = {
    "verdict": "SAFE",
    "s_risk": 0.15,
    "s_idn": 0.10,
    "s_llm": 0.20,
    "s_ti": 0.05,
    "shap_explanation": {
        "baseline": 0.5,
        "idn_contribution": -0.20,
        "llm_contribution": -0.10,
        "ti_contribution": -0.05,
        "idn_local_score": 0.10,
    },
    "top_features": ["idn_contribution", "llm_contribution", "ti_contribution"],
}


async def _call(session: AsyncMock, **overrides) -> str:
    kw = dict(
        session=session,
        trace_id=TRACE_ID,
        url="https://apple.com",
        domain="apple.com",
        email_sha256="abc" * 21 + "d",  # 64 chars
        source="extension",
        idn_result=_IDN,
        llm_result=_LLM,
        fusion_result=_FUSION,
    )
    kw.update(overrides)
    return await save_full_analysis(**kw)


# ── Return value ──────────────────────────────────────────────────────────────

async def test_returns_trace_id():
    """save_full_analysis returns the trace_id it received."""
    session = _make_session()
    result = await _call(session)
    assert result == TRACE_ID


# ── session.add call count ────────────────────────────────────────────────────

async def test_session_add_called_six_times():
    """session.add() must be called exactly 6 times: Analysis + URLAnalysis + 3×AgentResult + XAIReport."""
    session = _make_session()
    await _call(session)
    assert session.add.call_count == 6


# ── session.flush ─────────────────────────────────────────────────────────────

async def test_session_flush_called_once():
    """session.flush() is awaited exactly once, after the Analysis insert."""
    session = _make_session()
    await _call(session)
    session.flush.assert_awaited_once()


# ── Analysis row ──────────────────────────────────────────────────────────────

async def test_first_add_is_analysis():
    """The first session.add() call receives an Analysis instance."""
    session = _make_session()
    await _call(session)
    row = session.add.call_args_list[0][0][0]
    assert isinstance(row, Analysis)


async def test_analysis_verdict_and_scores():
    """Analysis row has the verdict and scores from fusion_result."""
    session = _make_session()
    await _call(session)
    row = session.add.call_args_list[0][0][0]
    assert row.verdict == "SAFE"
    assert row.s_risk == pytest.approx(0.15)
    assert row.s_idn == pytest.approx(0.10)
    assert row.s_llm == pytest.approx(0.20)
    assert row.s_ti == pytest.approx(0.05)


async def test_analysis_stores_email_sha256_not_body():
    """email_sha256 is persisted on Analysis; raw body is never accepted."""
    sha = "deadbeef" * 8  # 64-char hex
    session = _make_session()
    await _call(session, email_sha256=sha)
    row = session.add.call_args_list[0][0][0]
    assert isinstance(row, Analysis)
    assert row.email_sha256 == sha


async def test_analysis_email_sha256_none_allowed():
    """email_sha256=None is accepted (nullable column — email may be absent)."""
    session = _make_session()
    result = await _call(session, email_sha256=None)
    row = session.add.call_args_list[0][0][0]
    assert row.email_sha256 is None
    assert result == TRACE_ID


# ── URLAnalysis row ───────────────────────────────────────────────────────────

async def test_second_add_is_url_analysis():
    """The second session.add() receives a URLAnalysis instance."""
    session = _make_session()
    await _call(session)
    row = session.add.call_args_list[1][0][0]
    assert isinstance(row, URLAnalysis)


async def test_url_analysis_idn_fields():
    """URLAnalysis has s_idn_local and is_punycode from idn_result."""
    session = _make_session()
    await _call(session)
    row = session.add.call_args_list[1][0][0]
    assert row.s_idn_local == pytest.approx(0.1)
    assert row.is_punycode is False


# ── AgentResult rows (indices 2, 3, 4) ───────────────────────────────────────

async def test_three_agent_result_rows():
    """Exactly 3 AgentResult rows exist with the correct agent names."""
    session = _make_session()
    await _call(session)
    rows = [session.add.call_args_list[i][0][0] for i in range(2, 5)]
    assert all(isinstance(r, AgentResult) for r in rows)
    names = {r.agent_name for r in rows}
    assert names == {"idn_agent", "llm_agent", "fusion_agent"}


async def test_llm_agent_result_score():
    """llm_agent AgentResult score equals llm_result['s_llm']."""
    session = _make_session()
    await _call(session)
    rows = [session.add.call_args_list[i][0][0] for i in range(2, 5)]
    llm_row = next(r for r in rows if r.agent_name == "llm_agent")
    assert llm_row.score == pytest.approx(0.2)


async def test_fusion_agent_result_score():
    """fusion_agent AgentResult score equals fusion_result['s_risk']."""
    session = _make_session()
    await _call(session)
    rows = [session.add.call_args_list[i][0][0] for i in range(2, 5)]
    fusion_row = next(r for r in rows if r.agent_name == "fusion_agent")
    assert fusion_row.score == pytest.approx(0.15)


# ── XAIReport row (index 5) ───────────────────────────────────────────────────

async def test_last_add_is_xai_report():
    """The sixth session.add() call receives an XAIReport instance."""
    session = _make_session()
    await _call(session)
    row = session.add.call_args_list[5][0][0]
    assert isinstance(row, XAIReport)


async def test_xai_shap_values_match_fusion():
    """XAIReport.shap_values equals fusion_result['shap_explanation']."""
    session = _make_session()
    await _call(session)
    row = session.add.call_args_list[5][0][0]
    assert row.shap_values == _FUSION["shap_explanation"]


async def test_xai_top_features_match_fusion():
    """XAIReport.top_features equals fusion_result['top_features']."""
    session = _make_session()
    await _call(session)
    row = session.add.call_args_list[5][0][0]
    assert row.top_features == _FUSION["top_features"]


async def test_xai_lime_values_always_empty():
    """XAIReport.lime_values is always {} — LIME deferred to Phase 6."""
    session = _make_session()
    await _call(session)
    row = session.add.call_args_list[5][0][0]
    assert row.lime_values == {}


# ── Error propagation ─────────────────────────────────────────────────────────

async def test_flush_error_propagates():
    """If session.flush() raises, the exception propagates to the caller."""
    session = _make_session()
    session.flush.side_effect = Exception("DB constraint violation")
    with pytest.raises(Exception, match="DB constraint violation"):
        await _call(session)


async def test_missing_shap_defaults_to_empty_dict():
    """shap_explanation absent from fusion_result → XAIReport.shap_values == {}."""
    fusion_no_shap = {k: v for k, v in _FUSION.items() if k != "shap_explanation"}
    session = _make_session()
    await _call(session, fusion_result=fusion_no_shap)
    row = session.add.call_args_list[5][0][0]
    assert row.shap_values == {}


async def test_missing_top_features_defaults_to_empty_list():
    """top_features absent from fusion_result → XAIReport.top_features == []."""
    fusion_no_tf = {k: v for k, v in _FUSION.items() if k != "top_features"}
    session = _make_session()
    await _call(session, fusion_result=fusion_no_tf)
    row = session.add.call_args_list[5][0][0]
    assert row.top_features == []
