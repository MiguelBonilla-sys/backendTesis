"""Tests for scripts/eval_baseline_vs_pipeline.py — lógica pura (T4)."""
from __future__ import annotations

from scripts.eval_baseline_vs_pipeline import _binary_metrics, mcnemar


class TestBinaryMetrics:
    def test_perfect_classifier(self):
        pairs = [(True, True)] * 5 + [(False, False)] * 5
        m = _binary_metrics(pairs)
        assert m["precision"] == 1.0
        assert m["recall"] == 1.0
        assert m["f1"] == 1.0
        assert m["meets_thesis_target"] is True

    def test_all_false_positives_zero_precision(self):
        pairs = [(True, False)] * 4
        m = _binary_metrics(pairs)
        assert m["precision"] == 0.0
        assert m["meets_thesis_target"] is False

    def test_partial(self):
        # 8 TP, 2 FN, 1 FP, 9 TN
        pairs = [(True, True)] * 8 + [(False, True)] * 2 + [(True, False)] + [(False, False)] * 9
        m = _binary_metrics(pairs)
        assert m["tp"] == 8 and m["fn"] == 2 and m["fp"] == 1 and m["tn"] == 9
        assert m["recall"] == 0.8
        assert round(m["precision"], 4) == round(8 / 9, 4)


class TestMcNemar:
    def test_no_discordant_pairs_is_tie(self):
        bc = [True, True, False]
        pc = [True, True, False]
        result = mcnemar(bc, pc)
        assert result["favors"] == "tie"
        assert result["significant_at_0.05"] is False

    def test_pipeline_clearly_better_is_significant(self):
        # 30 casos donde pipeline acierta y baseline falla, 0 al revés
        bc = [False] * 30
        pc = [True] * 30
        result = mcnemar(bc, pc)
        assert result["favors"] == "pipeline"
        assert result["significant_at_0.05"] is True

    def test_small_difference_not_significant(self):
        # b=2, c=3 — diferencia mínima, no significativa
        bc = [True, True, False, False, False]
        pc = [False, False, True, True, True]
        result = mcnemar(bc, pc)
        assert result["favors"] == "pipeline"
        assert result["significant_at_0.05"] is False

    def test_direction_favors_baseline(self):
        bc = [True] * 20
        pc = [False] * 20
        result = mcnemar(bc, pc)
        assert result["favors"] == "baseline"
