"""
Comparación baseline monolítico vs pipeline multi-agente (T4 — docs/tasks.md).

Decisión bloqueada (docs/spec.md): el baseline es el clasificador HF
``pirocheto/phishing-url-detection`` standalone. Como el pipeline ya devuelve
``agent_scores.s_hf`` en cada respuesta, ambos veredictos se derivan de UNA
sola llamada a ``/api/v1/analyze`` sobre el mismo split — comparación justa:

    baseline_verdict = PHISHING  si  s_hf >= 0.5  else LEGITIMATE
    pipeline_verdict = response.verdict  (fusión de las 5 señales)

Reporta precision/recall/F1 de cada uno + test de McNemar para significancia
estadística de la diferencia (la contribución central de la tesis).

Acepta los mismos datasets que eval_datasets.py más el corpus IDN sintético:
    python -m scripts.eval_baseline_vs_pipeline --backend http://localhost:8000 \
        --jsonl data/idn_synth.jsonl --legit-jsonl data/legit_sample.jsonl
    python -m scripts.eval_baseline_vs_pipeline --dataset pirocheto --limit 300
"""
from __future__ import annotations

import argparse
import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

BASELINE_THRESHOLD = 0.5


# ---------------------------------------------------------------------------
# Carga de casos
# ---------------------------------------------------------------------------

def load_jsonl_cases(path: Path, expected: str) -> list[dict]:
    """Carga casos desde un JSONL (corpus sintético o real). Campo ``url`` o
    ``domain``/``unicode`` (homógrafo). ``expected`` etiqueta toda la lista."""
    cases: list[dict] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            url = rec.get("url")
            if not url:
                host = rec.get("unicode") or rec.get("domain")
                url = f"http://{host}" if host else None
            if url:
                cases.append({"url": url, "expected": expected,
                              "source": path.name, "synthetic": rec.get("synthetic", False)})
    return cases


# ---------------------------------------------------------------------------
# Llamada al pipeline (deriva ambos veredictos)
# ---------------------------------------------------------------------------

async def analyze(client: httpx.AsyncClient, backend: str, url: str, token: str) -> dict:
    try:
        resp = await client.post(
            f"{backend}/api/v1/analyze",
            json={"url": url},
            headers={"Authorization": f"Bearer {token}"},
            timeout=30.0,
        )
        resp.raise_for_status()
        data = resp.json()
        s_hf = (data.get("agent_scores") or {}).get("s_hf")
        return {
            "pipeline_verdict": data.get("verdict", "ERROR"),
            "s_hf": s_hf,
            "s_risk": data.get("s_risk"),
        }
    except Exception as exc:  # noqa: BLE001 — eval script, registrar y seguir
        return {"pipeline_verdict": "ERROR", "s_hf": None, "error": str(exc)}


async def get_token(backend: str) -> str:
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"{backend}/api/v1/auth/login",
                json={"username": "admin", "password": "Admin1234!"},
                timeout=10.0,
            )
            if resp.status_code == 200:
                return resp.json()["access_token"]
        except httpx.HTTPError:
            pass
    return "dev-token"


# ---------------------------------------------------------------------------
# Métricas + McNemar
# ---------------------------------------------------------------------------

def _binary_metrics(pairs: list[tuple[bool, bool]]) -> dict:
    """pairs: (predicted_phishing, actual_phishing)."""
    tp = sum(1 for p, a in pairs if p and a)
    fp = sum(1 for p, a in pairs if p and not a)
    fn = sum(1 for p, a in pairs if not p and a)
    tn = sum(1 for p, a in pairs if not p and not a)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    total = tp + fp + fn + tn
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(prec, 4), "recall": round(rec, 4),
        "f1": round(f1, 4),
        "accuracy": round((tp + tn) / total, 4) if total else 0.0,
        "meets_thesis_target": prec >= 0.80 and rec >= 0.75,
    }


def mcnemar(baseline_correct: list[bool], pipeline_correct: list[bool]) -> dict:
    """
    Test de McNemar sobre aciertos pareados (mismo input para ambos modelos).

    b = baseline acierta y pipeline falla
    c = pipeline acierta y baseline falla
    χ² con corrección de continuidad = (|b−c|−1)² / (b+c)

    p-value vía scipy si está disponible; si no, regla práctica χ² > 3.841
    (p<0.05, 1 g.l.). Devuelve también la dirección de la mejora.
    """
    b = sum(1 for bc, pc in zip(baseline_correct, pipeline_correct) if bc and not pc)
    c = sum(1 for bc, pc in zip(baseline_correct, pipeline_correct) if pc and not bc)
    n_disc = b + c
    if n_disc == 0:
        return {"b": 0, "c": 0, "chi2": 0.0, "p_value": 1.0,
                "significant_at_0.05": False, "favors": "tie"}

    chi2 = (abs(b - c) - 1) ** 2 / n_disc
    try:
        from scipy.stats import chi2 as chi2_dist  # type: ignore

        p_value = float(1.0 - chi2_dist.cdf(chi2, df=1))
    except ImportError:
        p_value = None  # type: ignore

    significant = (p_value < 0.05) if p_value is not None else (chi2 > 3.841)
    return {
        "b_baseline_only_correct": b,
        "c_pipeline_only_correct": c,
        "chi2": round(chi2, 4),
        "p_value": round(p_value, 6) if p_value is not None else "scipy-unavailable",
        "significant_at_0.05": significant,
        "favors": "pipeline" if c > b else ("baseline" if b > c else "tie"),
    }


# ---------------------------------------------------------------------------
# Loop principal
# ---------------------------------------------------------------------------

async def run(backend: str, cases: list[dict], concurrency: int) -> dict:
    token = await get_token(backend)
    sem = asyncio.Semaphore(concurrency)
    start = time.perf_counter()

    async def one(client, case):
        async with sem:
            r = await analyze(client, backend, case["url"], token)
            r["expected"] = case["expected"]
            return r

    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(*[one(client, c) for c in cases])

    baseline_pairs: list[tuple[bool, bool]] = []
    pipeline_pairs: list[tuple[bool, bool]] = []
    baseline_correct: list[bool] = []
    pipeline_correct: list[bool] = []
    errors = 0

    for r in results:
        if r["pipeline_verdict"] == "ERROR" or r.get("s_hf") is None:
            errors += 1
            continue
        actual = r["expected"] == "PHISHING"
        base_pred = r["s_hf"] >= BASELINE_THRESHOLD
        pipe_pred = r["pipeline_verdict"] == "PHISHING"
        baseline_pairs.append((base_pred, actual))
        pipeline_pairs.append((pipe_pred, actual))
        baseline_correct.append(base_pred == actual)
        pipeline_correct.append(pipe_pred == actual)

    elapsed = time.perf_counter() - start
    return {
        "n_cases": len(cases),
        "n_evaluated": len(baseline_pairs),
        "errors": errors,
        "elapsed_s": round(elapsed, 2),
        "baseline": _binary_metrics(baseline_pairs),
        "pipeline": _binary_metrics(pipeline_pairs),
        "mcnemar": mcnemar(baseline_correct, pipeline_correct),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def print_report(report: dict) -> None:
    b, p, m = report["baseline"], report["pipeline"], report["mcnemar"]
    print("\n" + "=" * 64)
    print(f"{'BASELINE (HF standalone) vs PIPELINE (5 señales)':^64}")
    print("=" * 64)
    print(f"Casos evaluados: {report['n_evaluated']} (errores: {report['errors']})")
    print(f"{'Métrica':<14}{'Baseline':>12}{'Pipeline':>12}{'Δ':>12}")
    print("-" * 64)
    for key in ("precision", "recall", "f1", "accuracy"):
        delta = p[key] - b[key]
        print(f"{key:<14}{b[key]:>12.4f}{p[key]:>12.4f}{delta:>+12.4f}")
    print("-" * 64)
    print(f"McNemar: χ²={m['chi2']} | p={m['p_value']} | "
          f"significativo(0.05)={m['significant_at_0.05']} | favorece={m['favors']}")
    print(f"  (baseline-solo correctos={m.get('b_baseline_only_correct')}, "
          f"pipeline-solo correctos={m.get('c_pipeline_only_correct')})")
    print("=" * 64)
    print("Meta tesis: Precision ≥ 0.80 | Recall ≥ 0.75")
    print(f"  baseline cumple: {b['meets_thesis_target']} | "
          f"pipeline cumple: {p['meets_thesis_target']}")


def collect_cases(args) -> list[dict]:
    cases: list[dict] = []
    if args.jsonl:
        cases += load_jsonl_cases(Path(args.jsonl), "PHISHING")
    if args.legit_jsonl:
        cases += load_jsonl_cases(Path(args.legit_jsonl), "LEGITIMATE")
    if args.dataset:
        from scripts.eval_datasets import load_hf_cases

        cases += load_hf_cases(args.dataset, args.limit)
    return cases


async def main() -> int:
    parser = argparse.ArgumentParser(description="Baseline vs pipeline + McNemar")
    parser.add_argument("--backend", default="http://localhost:8000")
    parser.add_argument("--jsonl", help="JSONL de homógrafos/phishing (expected=PHISHING)")
    parser.add_argument("--legit-jsonl", help="JSONL de dominios legítimos (expected=LEGITIMATE)")
    parser.add_argument("--dataset", help="dataset HF (ver eval_datasets.DATASETS)")
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--output", default="reports")
    args = parser.parse_args()

    cases = collect_cases(args)
    if not cases:
        print("Sin casos — pasá --jsonl, --legit-jsonl o --dataset.")
        return 1

    report = await run(args.backend, cases, args.concurrency)
    print_report(report)

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_file = out_dir / f"baseline_vs_pipeline_{ts}.json"
    out_file.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"\nReporte → {out_file}")
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(asyncio.run(main()))
