"""Tests for core/calibration.py — recalibración adaptativa de θ (T12)."""
from __future__ import annotations

import pytest

from core.calibration import (
    RECAL_MIN_FEEDBACK,
    THETA_DRIFT_MAX,
    choose_theta,
    get_effective_theta,
    reset_effective_theta,
    set_effective_theta,
)
from core.constants import THETA


@pytest.fixture(autouse=True)
def _restore_theta():
    yield
    reset_effective_theta()


# ---------------------------------------------------------------------------
# Effective theta runtime state
# ---------------------------------------------------------------------------

class TestEffectiveTheta:
    def test_default_is_base_theta(self):
        assert get_effective_theta() == THETA

    def test_set_within_guardrails(self):
        set_effective_theta(THETA + 0.05)
        assert get_effective_theta() == pytest.approx(THETA + 0.05)

    def test_set_clamped_to_drift_max(self):
        set_effective_theta(THETA + 0.50)
        assert get_effective_theta() == pytest.approx(THETA + THETA_DRIFT_MAX)
        set_effective_theta(THETA - 0.50)
        assert get_effective_theta() == pytest.approx(THETA - THETA_DRIFT_MAX)

    def test_reset_returns_to_base(self):
        set_effective_theta(THETA + 0.05)
        reset_effective_theta()
        assert get_effective_theta() == THETA


# ---------------------------------------------------------------------------
# choose_theta — selección por loss asimétrica
# ---------------------------------------------------------------------------

def _samples(fp_scores: list[float], fn_scores: list[float], n_pad: int = 0):
    """FP: legítimos con score alto. FN: phishing con score bajo.
    n_pad agrega muestras bien clasificadas para superar el mínimo."""
    samples = [(s, False) for s in fp_scores] + [(s, True) for s in fn_scores]
    samples += [(0.05, False)] * n_pad + [(0.95, True)] * n_pad
    return samples


class TestChooseTheta:
    def test_no_adjustment_below_min_samples(self):
        result = choose_theta([(0.9, True)] * (RECAL_MIN_FEEDBACK - 1))
        assert result.adjusted is False
        assert "insufficient_feedback" in result.reason
        assert result.new_theta == result.old_theta

    def test_many_false_positives_push_theta_up(self):
        """Legítimos con s_risk ~0.72 (FPs con θ=0.70) → θ óptimo sube."""
        samples = _samples(fp_scores=[0.72] * 10, fn_scores=[], n_pad=15)
        result = choose_theta(samples)
        assert result.adjusted is True
        assert result.new_theta > THETA

    def test_many_false_negatives_push_theta_down(self):
        """Phishing confirmado con s_risk ~0.65 (FNs con θ=0.70) → θ baja."""
        samples = _samples(fp_scores=[], fn_scores=[0.65] * 10, n_pad=15)
        result = choose_theta(samples)
        assert result.adjusted is True
        assert result.new_theta < THETA

    def test_new_theta_bounded_by_drift_max(self):
        """Aunque la evidencia pida más, θ no sale del rango ±drift_max."""
        samples = _samples(fp_scores=[], fn_scores=[0.30] * 40, n_pad=0)
        result = choose_theta(samples)
        assert result.new_theta >= THETA - THETA_DRIFT_MAX - 1e-9

    def test_no_adjustment_when_current_is_optimal(self):
        """Muestras bien separadas alrededor de θ → sin cambio."""
        samples = _samples(fp_scores=[], fn_scores=[], n_pad=20)
        result = choose_theta(samples)
        assert result.adjusted is False
        assert result.reason == "optimum_equals_current"

    def test_fn_weighs_more_than_fp(self):
        """Con #FP == #FN equidistantes, la loss favorece eliminar FNs (bajar θ)."""
        samples = _samples(fp_scores=[0.72] * 8, fn_scores=[0.68] * 8, n_pad=15)
        result = choose_theta(samples)
        # bajar θ a 0.68 elimina 8 FNs (peso 0.70 c/u) al costo de 0 FPs extra;
        # subir θ a >0.72 elimina 8 FPs (peso 0.30 c/u) al costo de 0 FNs extra.
        # Ambas eliminan su clase — pero la loss restante favorece matar FNs.
        assert result.new_theta <= 0.68
