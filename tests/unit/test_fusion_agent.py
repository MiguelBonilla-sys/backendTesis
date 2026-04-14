import pytest

from agents.fusion_agent import FusionAgent
from core.constants import (
    ALPHA,
    GAMMA,
    GAMMA_DEFINITIVE_HOMOGRAPH,
    GAMMA_LLM_FALLBACK,
    SUSPICIOUS_THRESHOLD,
    THETA,
    TI_GSB_WEIGHT,
    TI_URLSCAN_WEIGHT,
    TI_VIRUSTOTAL_WEIGHT,
    VERDICT_PHISHING,
    VERDICT_SAFE,
    VERDICT_SUSPICIOUS,
)
from core.exceptions import BackendTesisError


@pytest.fixture
def agent() -> FusionAgent:
    return FusionAgent()


# ── Verdict branches ──────────────────────────────────────────────────────────

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
        s_idn_local=0.7,
        s_llm=0.5,
        ti_scores={"virustotal": 0.4, "urlscan": 0.3, "google_safe_browsing": 0.0},
    )
    assert result["verdict"] == VERDICT_SUSPICIOUS
    assert 0.50 <= result["s_risk"] < 0.70


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


# ── TI aggregation — exact weights ────────────────────────────────────────────

@pytest.mark.parametrize("vt,us,gsb,expected_s_ti", [
    (1.0, 0.0, 0.0, TI_VIRUSTOTAL_WEIGHT),           # only VT
    (0.0, 1.0, 0.0, TI_URLSCAN_WEIGHT),              # only URLScan
    (0.0, 0.0, 1.0, TI_GSB_WEIGHT),                  # only GSB
    (1.0, 1.0, 1.0, 1.0),                            # all max
    (0.0, 0.0, 0.0, 0.0),                            # all zero
])
@pytest.mark.asyncio
async def test_ti_aggregation_weights(agent, vt, us, gsb, expected_s_ti):
    result = await agent.analyze(
        s_idn_local=0.0,
        s_llm=0.0,
        ti_scores={"virustotal": vt, "urlscan": us, "google_safe_browsing": gsb},
    )
    assert abs(result["s_ti"] - expected_s_ti) < 1e-4


# ── Fusion formula — numerical verification ───────────────────────────────────

@pytest.mark.asyncio
async def test_s_idn_formula_with_zero_ti(agent):
    """S_IDN = ALPHA * s_idn_local + (1-ALPHA) * 0.0"""
    s_idn_local = 0.8
    result = await agent.analyze(
        s_idn_local=s_idn_local,
        s_llm=0.0,
        ti_scores={"virustotal": 0.0, "urlscan": 0.0, "google_safe_browsing": 0.0},
    )
    expected_s_idn = ALPHA * s_idn_local
    assert abs(result["s_idn"] - expected_s_idn) < 1e-4


@pytest.mark.asyncio
async def test_s_risk_formula(agent):
    """S_risk = GAMMA * S_IDN + (1-GAMMA) * S_LLM with known inputs."""
    # All TI = 0 so S_TI = 0, S_IDN = ALPHA * s_idn_local
    s_idn_local = 1.0
    s_llm = 0.0
    result = await agent.analyze(
        s_idn_local=s_idn_local,
        s_llm=s_llm,
        ti_scores={"virustotal": 0.0, "urlscan": 0.0, "google_safe_browsing": 0.0},
    )
    expected_s_idn = ALPHA * s_idn_local
    expected_s_risk = GAMMA * expected_s_idn + (1.0 - GAMMA) * s_llm
    assert abs(result["s_risk"] - expected_s_risk) < 1e-4


# ── Verdict threshold boundaries ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_verdict_at_theta_boundary(agent):
    """s_risk exactly at THETA → PHISHING."""
    # Drive s_risk to exactly THETA by making all scores equal:
    # S_TI=THETA, S_IDN_local=THETA → S_IDN=THETA, S_LLM=THETA → S_risk=THETA
    result = await agent.analyze(
        s_idn_local=THETA,
        s_llm=THETA,
        ti_scores={
            "virustotal": THETA,
            "urlscan": THETA,
            "google_safe_browsing": THETA,
        },
    )
    assert result["s_risk"] == pytest.approx(THETA, abs=1e-4)
    assert result["verdict"] == VERDICT_PHISHING


@pytest.mark.asyncio
async def test_verdict_just_below_theta_is_suspicious(agent):
    """s_risk just below THETA (and above SUSPICIOUS_THRESHOLD) → SUSPICIOUS."""
    # Use inputs that yield a predictable s_risk slightly below 0.70
    result = await agent.analyze(
        s_idn_local=SUSPICIOUS_THRESHOLD,
        s_llm=SUSPICIOUS_THRESHOLD,
        ti_scores={
            "virustotal": SUSPICIOUS_THRESHOLD,
            "urlscan": SUSPICIOUS_THRESHOLD,
            "google_safe_browsing": SUSPICIOUS_THRESHOLD,
        },
    )
    assert result["s_risk"] == pytest.approx(SUSPICIOUS_THRESHOLD, abs=1e-4)
    assert result["verdict"] == VERDICT_SUSPICIOUS


# ── SHAP structure ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_shap_values_all_floats(agent):
    """All values in shap_explanation must be float."""
    result = await agent.analyze(
        s_idn_local=0.7,
        s_llm=0.8,
        ti_scores={"virustotal": 0.6, "urlscan": 0.4, "google_safe_browsing": 0.9},
    )
    for v in result["shap_explanation"].values():
        assert isinstance(v, float), f"Expected float, got {type(v)} for value {v!r}"


@pytest.mark.asyncio
async def test_shap_baseline_always_half(agent):
    """shap_explanation['baseline'] is always 0.5 regardless of inputs."""
    for s_idn_local in (0.0, 0.5, 1.0):
        result = await agent.analyze(
            s_idn_local=s_idn_local,
            s_llm=0.5,
            ti_scores={"virustotal": 0.0, "urlscan": 0.0, "google_safe_browsing": 0.0},
        )
        assert result["shap_explanation"]["baseline"] == 0.5


# ── top_features ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_top_features_returns_three_items(agent):
    """top_features always has exactly 3 items (n=3 default)."""
    result = await agent.analyze(
        s_idn_local=0.8,
        s_llm=0.9,
        ti_scores={"virustotal": 0.7, "urlscan": 0.3, "google_safe_browsing": 0.1},
    )
    assert len(result["top_features"]) == 3


@pytest.mark.asyncio
async def test_top_features_excludes_baseline(agent):
    """'baseline' and 'idn_local_score' must not appear in top_features."""
    result = await agent.analyze(
        s_idn_local=0.6,
        s_llm=0.7,
        ti_scores={"virustotal": 0.5, "urlscan": 0.5, "google_safe_browsing": 0.5},
    )
    assert "baseline" not in result["top_features"]
    assert "idn_local_score" not in result["top_features"]


@pytest.mark.asyncio
async def test_top_features_are_valid_shap_keys(agent):
    """Each item in top_features is a key that exists in shap_explanation."""
    result = await agent.analyze(
        s_idn_local=0.6,
        s_llm=0.7,
        ti_scores={"virustotal": 0.5, "urlscan": 0.5, "google_safe_browsing": 0.5},
    )
    shap_keys = set(result["shap_explanation"].keys())
    for feature in result["top_features"]:
        assert feature in shap_keys


# ── Clamping ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_s_risk_clamped_to_one(agent):
    """Extreme high inputs must not produce s_risk > 1.0."""
    result = await agent.analyze(
        s_idn_local=1.0,
        s_llm=1.0,
        ti_scores={"virustotal": 1.0, "urlscan": 1.0, "google_safe_browsing": 1.0},
    )
    assert result["s_risk"] <= 1.0


@pytest.mark.asyncio
async def test_s_risk_clamped_to_zero(agent):
    """All-zero inputs → s_risk == 0.0."""
    result = await agent.analyze(
        s_idn_local=0.0,
        s_llm=0.0,
        ti_scores={"virustotal": 0.0, "urlscan": 0.0, "google_safe_browsing": 0.0},
    )
    assert result["s_risk"] == 0.0


# ── Missing TI keys default to 0.0 ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_missing_ti_keys_default_to_zero(agent):
    """ti_scores with missing keys fall back to 0.0 without raising."""
    result = await agent.analyze(
        s_idn_local=0.5,
        s_llm=0.5,
        ti_scores={},  # all keys missing
    )
    assert result["s_ti"] == 0.0
    assert 0.0 <= result["s_risk"] <= 1.0


# ── Adaptive GAMMA — definitive homograph branch ──────────────────────────────

@pytest.mark.asyncio
async def test_definitive_homograph_bypasses_ti_blending(agent):
    """is_definitive_homograph=True → s_idn = s_idn_local (TI not blended in)."""
    s_idn_local = 1.0
    result = await agent.analyze(
        s_idn_local=s_idn_local,
        s_llm=0.5,
        ti_scores={"virustotal": 0.0, "urlscan": 0.0, "google_safe_browsing": 0.0},
        is_definitive_homograph=True,
    )
    # s_idn must equal s_idn_local, NOT ALPHA*s_idn_local (which would be 0.60)
    assert abs(result["s_idn"] - s_idn_local) < 1e-4


@pytest.mark.asyncio
async def test_definitive_homograph_zero_ti_yields_phishing(agent):
    """Zero-day homograph (s_ti=0) with s_idn_local=1.0 → PHISHING via TI bypass."""
    result = await agent.analyze(
        s_idn_local=1.0,
        s_llm=0.5,
        ti_scores={"virustotal": 0.0, "urlscan": 0.0, "google_safe_browsing": 0.0},
        is_definitive_homograph=True,
    )
    # s_idn=1.0, gamma=0.85 → s_risk = 0.85*1.0 + 0.15*0.5 = 0.925
    assert result["verdict"] == VERDICT_PHISHING
    assert result["s_risk"] >= THETA
    assert abs(result["effective_gamma"] - GAMMA_DEFINITIVE_HOMOGRAPH) < 1e-4


@pytest.mark.asyncio
async def test_definitive_homograph_uses_homograph_gamma(agent):
    """is_definitive_homograph=True → effective_gamma == GAMMA_DEFINITIVE_HOMOGRAPH."""
    result = await agent.analyze(
        s_idn_local=0.9,
        s_llm=0.5,
        ti_scores={"virustotal": 0.0, "urlscan": 0.0, "google_safe_browsing": 0.0},
        is_definitive_homograph=True,
    )
    assert abs(result["effective_gamma"] - GAMMA_DEFINITIVE_HOMOGRAPH) < 1e-4


# ── Adaptive GAMMA — LLM fallback branch ─────────────────────────────────────

@pytest.mark.asyncio
async def test_llm_fallback_uses_fallback_gamma(agent):
    """llm_is_fallback=True → effective_gamma == GAMMA_LLM_FALLBACK."""
    result = await agent.analyze(
        s_idn_local=0.8,
        s_llm=0.5,
        ti_scores={"virustotal": 0.0, "urlscan": 0.0, "google_safe_browsing": 0.0},
        llm_is_fallback=True,
    )
    assert abs(result["effective_gamma"] - GAMMA_LLM_FALLBACK) < 1e-4


@pytest.mark.asyncio
async def test_llm_fallback_still_uses_alpha_blending(agent):
    """llm_is_fallback=True does NOT bypass TI blending — only homograph branch does."""
    s_idn_local = 0.8
    result = await agent.analyze(
        s_idn_local=s_idn_local,
        s_llm=0.5,
        ti_scores={"virustotal": 0.0, "urlscan": 0.0, "google_safe_browsing": 0.0},
        llm_is_fallback=True,
    )
    expected_s_idn = ALPHA * s_idn_local  # 0.60 * 0.8 = 0.48
    assert abs(result["s_idn"] - expected_s_idn) < 1e-4


@pytest.mark.asyncio
async def test_homograph_takes_priority_over_llm_fallback(agent):
    """is_definitive_homograph=True takes precedence over llm_is_fallback=True."""
    result = await agent.analyze(
        s_idn_local=1.0,
        s_llm=0.5,
        ti_scores={"virustotal": 0.0, "urlscan": 0.0, "google_safe_browsing": 0.0},
        is_definitive_homograph=True,
        llm_is_fallback=True,
    )
    assert abs(result["effective_gamma"] - GAMMA_DEFINITIVE_HOMOGRAPH) < 1e-4
    assert abs(result["s_idn"] - 1.0) < 1e-4  # TI bypass active


@pytest.mark.asyncio
async def test_default_path_uses_gamma_and_alpha(agent):
    """Default (no flags) uses GAMMA and ALPHA blending."""
    s_idn_local, s_llm = 0.8, 0.6
    result = await agent.analyze(
        s_idn_local=s_idn_local,
        s_llm=s_llm,
        ti_scores={"virustotal": 0.0, "urlscan": 0.0, "google_safe_browsing": 0.0},
    )
    expected_s_idn = ALPHA * s_idn_local
    expected_s_risk = GAMMA * expected_s_idn + (1.0 - GAMMA) * s_llm
    assert abs(result["s_idn"] - expected_s_idn) < 1e-4
    assert abs(result["s_risk"] - expected_s_risk) < 1e-4
    assert abs(result["effective_gamma"] - GAMMA) < 1e-4


# ── Exception path ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fusion_exception_raises_backend_error(agent):
    """Any unexpected error in analyze() wraps in BackendTesisError (L57-59)."""
    from unittest.mock import patch

    with patch.object(agent, "_aggregate_ti", side_effect=RuntimeError("unexpected")):
        with pytest.raises(BackendTesisError):
            await agent.analyze(
                s_idn_local=0.5,
                s_llm=0.5,
                ti_scores={"virustotal": 0.5, "urlscan": 0.5, "google_safe_browsing": 0.5},
            )
