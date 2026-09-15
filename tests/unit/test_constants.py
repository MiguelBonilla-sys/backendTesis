"""Tests for core/constants.py — weight and threshold sanity checks."""

from __future__ import annotations

import pytest

from core.constants import (
    ALPHA,
    BETA,
    F_MIX,
    GAMMA,
    HOMOGRAPH_THRESHOLD,
    IDN_CACHE_PREFIX,
    LLM_FALLBACK_SCORE,
    LLM_TIMEOUT_S,
    RAG_TOP_K,
    SIM_V_EARLY_EXIT,
    THETA,
    TI_CACHE_PREFIX,
    W_GSB,
    W_URLSCAN,
    W_VT,
)


class TestTIWeights:
    def test_ti_weights_sum_to_one(self):
        assert abs(W_VT + W_URLSCAN + W_GSB - 1.0) < 1e-9

    def test_w_vt_value(self):
        assert W_VT == 0.50

    def test_w_urlscan_value(self):
        assert W_URLSCAN == 0.30

    def test_w_gsb_value(self):
        assert W_GSB == 0.20

    def test_all_ti_weights_positive(self):
        assert W_VT > 0
        assert W_URLSCAN > 0
        assert W_GSB > 0


class TestIDNParameters:
    def test_beta_value(self):
        assert BETA == 0.40

    def test_alpha_value(self):
        assert ALPHA == 0.60

    def test_gamma_value(self):
        assert GAMMA == 0.50

    def test_theta_value(self):
        assert THETA == 0.30

    def test_f_mix_value(self):
        assert F_MIX == 1.6

    def test_homograph_threshold_value(self):
        assert HOMOGRAPH_THRESHOLD == 0.30

    def test_sim_v_early_exit_value(self):
        assert SIM_V_EARLY_EXIT == 0.95

    def test_alpha_beta_in_unit_interval(self):
        assert 0.0 < ALPHA < 1.0
        assert 0.0 < BETA < 1.0

    def test_gamma_is_half(self):
        assert GAMMA == 0.50

    def test_theta_above_neutral_degradation_floor(self):
        """Reemplaza test_theta_above_half (2026-09-15, T6): "phishing = más
        de la mitad de confianza" no es el invariante correcto bajo loss
        asimétrica (λ=0.30, FN pesa 3× más que FP) — θ puede estar legítimamente
        por debajo de 0.5. El invariante real: cuando TODAS las señales externas
        degradan a neutral (LLM=HF=0.5, TI=probe=idn_local=0 — sin información,
        no evidencia de riesgo), s_risk cae exactamente en (1-GAMMA)*0.5. Si θ
        no supera ese piso, cualquier dominio queda PHISHING apenas el LLM y el
        HF fallan a la vez — encontrado en tests/integration/test_phishing_evaluation.py
        (google.com etc. con s_risk=0.25 bajo mocks neutrales)."""
        neutral_degradation_floor = (1 - GAMMA) * 0.5
        assert THETA > neutral_degradation_floor


class TestLLMConstants:
    def test_llm_fallback_score_is_neutral(self):
        assert LLM_FALLBACK_SCORE == 0.5

    def test_llm_timeout_positive(self):
        assert LLM_TIMEOUT_S > 0


class TestCacheConstants:
    def test_ti_cache_prefix(self):
        assert TI_CACHE_PREFIX == "ti:"

    def test_idn_cache_prefix(self):
        assert IDN_CACHE_PREFIX == "idn:"

    def test_rag_top_k_positive(self):
        assert RAG_TOP_K > 0
