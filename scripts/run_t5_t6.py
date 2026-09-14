"""
Orquestador T5 (corpus real+sintético) + T6 (recalibración θ vía ROC) — 2026-09-14.

Pensado para correr en un solo paso apenas OpenCode Go recupere créditos —
sin esto, el 14/09 se quemó a medias un corpus de 600 casos con s_llm
degradado en silencio (429 → fallback 0.5) porque nada lo detectó a tiempo.

1. Sanity check del LLM gateway (UNA llamada real, sin corpus): si opencode.ai
   sigue devolviendo 429/402/403, aborta antes de gastar cuota de TI en un
   corpus que saldría con s_llm degradado.
2. Corre eval_baseline_vs_pipeline.py sobre el corpus completo de T5:
   150 homógrafos IDN sintéticos (data/idn_synth.jsonl) +
   150 phishing real, no-IDN (HF imanoop7) +
   300 legítimos (150 top1m + 150 HF) = 600 casos.
   SUSPICIOUS cuenta como detección (decisión 2026-09-14).
3. Con los raw_results de ese reporte, corre el análisis ROC de T6:
   choose_theta() (core/calibration.py, la misma función de T12) pero con
   rango de búsqueda AMPLIO — T12 lo limita a ±0.10 del θ vigente para
   ajustes incrementales en producción; T6 necesita explorar todo [0,1]
   para la calibración inicial documentada en la tesis.
   También reporta la curva ROC completa (TPR/FPR por threshold) y la
   distribución de s_risk por clase, para revisar el corte SUSPICIOUS (0.40).

Uso:
    python -m scripts.run_t5_t6 --backend http://localhost:8000
    python -m scripts.run_t5_t6 --backend http://localhost:8000 --skip-sanity-check

Salida: reports/t5_t6_<timestamp>.json (eval + ROC + recalibración) y
reports/baseline_vs_pipeline_<timestamp>.json (igual que siempre, vía
eval_baseline_vs_pipeline.run()).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from core.calibration import RECAL_LAMBDA, choose_theta
from core.constants import THETA
from core.logger import get_logger
from scripts.eval_baseline_vs_pipeline import collect_cases, print_report, run

logger = get_logger(__name__)

# Corpus T5 (documentado en docs/tasks.md T5 y docs/spec.md):
#   phishing-IDN sintético: 150 (generate_idn_corpus.py, --subs-per-domain 1)
#   phishing no-IDN real:   150 (HF imanoop7/phishing_url_classification)
#   legítimo:               300 (150 top1m + 150 HF, mismo dataset)
#   phishing-IDN real:      0 — no encontrado en datasets HF genéricos;
#     limitación conocida y documentada (ShamFinder/literatura: por eso
#     existe el corpus sintético).
_JSONL = "data/idn_synth.jsonl"
_LEGIT_JSONL = "data/legit_sample.jsonl"
_HF_DATASET = "imanoop7"
_HF_LIMIT = 300
_DEFAULT_CONCURRENCY = 3


async def sanity_check_llm(backend: str) -> bool:
    """Una llamada real de análisis contra el propio backend — si el LLM
    gateway sigue sin créditos, el s_llm que vuelve va a ser exactamente
    LLM_FALLBACK_SCORE (0.5) para una URL que normalmente no lo es."""
    import httpx

    from core.constants import LLM_FALLBACK_SCORE

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{backend}/api/v1/auth/login",
            json={"username": "admin", "password": "Admin1234!"},
            timeout=10.0,
        )
        token = resp.json()["access_token"]
        resp = await client.post(
            f"{backend}/api/v1/analyze",
            json={"url": "https://xn--pypal-4ve.com"},  # homógrafo conocido, sube el LLM
            headers={"Authorization": f"Bearer {token}"},
            timeout=30.0,
        )
        resp.raise_for_status()
        s_llm = (resp.json().get("agent_scores") or {}).get("s_llm")
        return s_llm is not None and s_llm != LLM_FALLBACK_SCORE


# ---------------------------------------------------------------------------
# T6 — ROC + recalibración de θ (rango amplio, no el ±0.10 de T12)
# ---------------------------------------------------------------------------


def roc_curve(samples: list[tuple[float, bool]], step: float = 0.01) -> list[dict]:
    """TPR/FPR por threshold — para graficar la curva ROC en la tesis."""
    positives = sum(1 for _, is_phish in samples if is_phish)
    negatives = len(samples) - positives
    curve: list[dict] = []
    t = 0.0
    while t <= 1.0 + 1e-9:
        thr = round(t, 4)
        tp = sum(1 for s, p in samples if s >= thr and p)
        fp = sum(1 for s, p in samples if s >= thr and not p)
        tpr = tp / positives if positives else 0.0
        fpr = fp / negatives if negatives else 0.0
        curve.append({"threshold": thr, "tpr": round(tpr, 4), "fpr": round(fpr, 4)})
        t += step
    return curve


def auc(curve: list[dict]) -> float:
    """AUC vía trapezoides sobre la curva ROC (ordenada por threshold desc = FPR asc)."""
    pts = sorted((c["fpr"], c["tpr"]) for c in curve)
    area = 0.0
    for (x0, y0), (x1, y1) in zip(pts, pts[1:]):  # noqa: B905 — ventana deslizante, largos difieren a propósito
        area += (x1 - x0) * (y0 + y1) / 2
    return round(area, 4)


def score_distribution(samples: list[tuple[float, bool]]) -> dict:
    """Percentiles de s_risk por clase — evidencia para revisar el corte
    SUSPICIOUS (0.40, docs/tasks.md T6)."""

    def pct(values: list[float], p: float) -> float:
        if not values:
            return 0.0
        s = sorted(values)
        idx = min(len(s) - 1, int(p * len(s)))
        return round(s[idx], 4)

    phish = sorted(s for s, is_p in samples if is_p)
    legit = sorted(s for s, is_p in samples if not is_p)
    return {
        "phishing": {
            "n": len(phish),
            "p10": pct(phish, 0.10),
            "p50": pct(phish, 0.50),
            "p90": pct(phish, 0.90),
        },
        "legitimate": {
            "n": len(legit),
            "p10": pct(legit, 0.10),
            "p50": pct(legit, 0.50),
            "p90": pct(legit, 0.90),
        },
    }


def run_t6_analysis(raw_results: list[dict]) -> dict:
    samples = [
        (r["s_risk"], r["expected"] == "PHISHING")
        for r in raw_results
        if r.get("pipeline_verdict") != "ERROR" and r.get("s_risk") is not None
    ]
    curve = roc_curve(samples)
    # Rango amplio a propósito: T12 (producción) limita el ajuste a ±0.10 del
    # θ vigente para no saltar de golpe con poco feedback; T6 es la
    # calibración inicial y necesita ver el óptimo real sin esa correa.
    recal = choose_theta(samples, base_theta=THETA, drift_max=1.0, min_samples=1)
    return {
        "n_samples": len(samples),
        "theta_base": THETA,
        "lambda_asimetrica": RECAL_LAMBDA,
        "theta_recalibrado": {
            "old_theta": recal.old_theta,
            "new_theta": recal.new_theta,
            "loss": recal.loss,
            "reason": recal.reason,
            "adjusted": recal.adjusted,
        },
        "auc": auc(curve),
        "roc_curve": curve,
        "score_distribution": score_distribution(samples),
    }


def print_t6_report(t6: dict) -> None:
    print("\n" + "=" * 64)
    print(f"{'T6 — Recalibración de θ vía ROC':^64}")
    print("=" * 64)
    print(f"Muestras: {t6['n_samples']} | AUC: {t6['auc']}")
    r = t6["theta_recalibrado"]
    print(f"θ actual (Sprint 6): {r['old_theta']}")
    print(f"θ óptimo (loss asimétrica, λ={t6['lambda_asimetrica']}): {r['new_theta']}")
    print(f"  loss={r['loss']} | {r['reason']} | ajustado={r['adjusted']}")
    dist = t6["score_distribution"]
    print("\nDistribución de s_risk (para revisar corte SUSPICIOUS=0.40):")
    for cls, d in dist.items():
        print(f"  {cls:12s} n={d['n']:4d}  p10={d['p10']}  p50={d['p50']}  p90={d['p90']}")
    print("=" * 64)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def main() -> int:
    parser = argparse.ArgumentParser(description="T5 + T6 en un solo paso")
    parser.add_argument("--backend", default="http://localhost:8000")
    parser.add_argument("--concurrency", type=int, default=_DEFAULT_CONCURRENCY)
    parser.add_argument("--output", default="reports")
    parser.add_argument(
        "--skip-sanity-check",
        action="store_true",
        help="Saltea el chequeo del LLM gateway (no recomendado tras un corte de créditos)",
    )
    args = parser.parse_args()

    if not args.skip_sanity_check:
        print("Sanity check del LLM gateway (1 llamada real)...")
        try:
            ok = await sanity_check_llm(args.backend)
        except Exception as exc:  # noqa: BLE001 — reportar y abortar, no adivinar
            print(f"ABORTADO: sanity check falló ({exc}). ¿Backend arriba?")
            return 1
        if not ok:
            print(
                "ABORTADO: s_llm volvió en LLM_FALLBACK_SCORE (0.5) — el gateway "
                "sigue sin créditos/degradado. Correr esto ahora produciría un "
                "corpus mixto (parte real, parte fallback) como el del 14/09."
            )
            return 1
        print("OK — LLM gateway responde con score real.\n")

    cases_args = argparse.Namespace(
        jsonl=_JSONL,
        legit_jsonl=_LEGIT_JSONL,
        dataset=_HF_DATASET,
        limit=_HF_LIMIT,
    )
    cases = collect_cases(cases_args)
    print(
        f"Corpus T5: {len(cases)} casos "
        f"({sum(1 for c in cases if c['expected']=='PHISHING')} phishing / "
        f"{sum(1 for c in cases if c['expected']=='LEGITIMATE')} legítimos)"
    )

    report = await run(args.backend, cases, args.concurrency)
    print_report(report)

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

    eval_file = out_dir / f"baseline_vs_pipeline_{ts}.json"
    eval_file.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"\nReporte T5 → {eval_file}")

    t6 = run_t6_analysis(report["raw_results"])
    print_t6_report(t6)

    t6_file = out_dir / f"t6_theta_recalibration_{ts}.json"
    t6_file.write_text(json.dumps(t6, indent=2, ensure_ascii=False))
    print(f"Reporte T6 → {t6_file}")

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
