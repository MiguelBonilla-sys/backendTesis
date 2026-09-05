"""Tests for core/online_calibration.py — choose_weights + effective weights."""
import pytest

from core.constants import ALPHA, GAMMA, HF_WEIGHT
from core.online_calibration import (
    WEIGHT_DRIFT_MAX,
    choose_weights,
    get_effective_weights,
    reset_effective_weights,
    set_effective_weights,
)


@pytest.fixture(autouse=True)
def _reset():
    reset_effective_weights()
    yield
    reset_effective_weights()


class TestEffectiveWeights:
    def test_default_is_thesis_constants(self):
        w = get_effective_weights()
        assert w == {"alpha": ALPHA, "gamma": GAMMA, "w_hf": HF_WEIGHT}

    def test_set_clamps_to_drift_band(self):
        set_effective_weights({"alpha": 0.99, "gamma": 0.0, "w_hf": 0.42})
        w = get_effective_weights()
        assert w["alpha"] == pytest.approx(ALPHA + WEIGHT_DRIFT_MAX)
        assert w["gamma"] == pytest.approx(GAMMA - WEIGHT_DRIFT_MAX)
        assert w["w_hf"] == pytest.approx(0.42)

    def test_reset(self):
        set_effective_weights({"alpha": ALPHA + 0.1})
        reset_effective_weights()
        assert get_effective_weights()["alpha"] == ALPHA


def _mk(n, s_idn, s_ti, s_llm, s_hf, phish, pseudo=False):
    return [(s_idn, s_ti, s_llm, s_hf, phish, pseudo) for _ in range(n)]


class TestChooseWeights:
    def test_insufficient_labels_no_adjust(self):
        r = choose_weights(_mk(5, 0.9, 0.1, 0.1, 0.1, True), theta=0.70)
        assert r.adjusted is False
        assert r.new == r.old
        assert "insufficient_labels" in r.reason

    def test_pseudo_labels_count_half(self):
        # 60 pseudo == 30 efectivas < 40 → no ajusta
        r = choose_weights(
            _mk(60, 0.9, 0.1, 0.1, 0.1, True, pseudo=True), theta=0.70
        )
        assert r.adjusted is False
        assert r.n_labels == pytest.approx(30.0)

    def test_shifts_weight_toward_dominant_correct_signal(self):
        # Phishing con rama IDN fuerte que la fusión base deja apenas bajo θ
        # (FN); subir γ dentro de la banda los cruza. Legit se queda abajo.
        samples = (
            _mk(40, 0.90, 0.80, 0.50, 0.50, True)   # base s_risk ≈ 0.68 → FN
            + _mk(20, 0.05, 0.05, 0.05, 0.05, False)
        )
        r = choose_weights(samples, theta=0.70)
        assert r.adjusted is True
        assert r.new["gamma"] >= r.old["gamma"]  # más peso a la rama IDN
        assert r.loss < 0.7 * 40  # base = todos FN; el ajuste reduce la loss

    def test_never_exceeds_drift_band(self):
        samples = _mk(80, 1.0, 0.0, 0.0, 0.0, True)
        r = choose_weights(samples, theta=0.70)
        for k, base in (("alpha", ALPHA), ("gamma", GAMMA), ("w_hf", HF_WEIGHT)):
            assert abs(r.new[k] - base) <= WEIGHT_DRIFT_MAX + 1e-9

    def test_optimum_equals_current_when_already_good(self):
        # mezcla balanceada correctamente clasificada con los pesos base
        good = _mk(25, 0.9, 0.9, 0.9, 0.9, True) + _mk(25, 0.05, 0.05, 0.05, 0.05, False)
        r = choose_weights(good, theta=0.70)
        assert r.adjusted is False
