"""
Evaluation script — IDN Homograph Phishing Detector
====================================================
Downloads 5 HuggingFace datasets and evaluates the running backendTesis API.

Datasets used
─────────────
1. ealvaradob/phishing-dataset  (800k URLs, 52% legit / 48% phishing)
2. pirocheto/phishing-url       (11.4k URLs, clean parquet, balanced)
3. imanoop7/phishing_url_classification  (URL Safe/NotSafe labels)
4. AreLit/PhishNChips           (2000 emails benchmark 1:1 ratio)
5. Naren1704/phishing-dataset   (URLs + Enron email bodies)

Usage
─────
# 1. Start the backend first:
#    cd backendTesis && uvicorn main:app --port 8000

# 2. Run the evaluation (needs HuggingFace access + running backend):
#    python scripts/eval_datasets.py --backend http://localhost:8000
#    python scripts/eval_datasets.py --backend http://localhost:8000 --dataset pirocheto --limit 500
#    python scripts/eval_datasets.py --backend http://localhost:8000 --dataset all --limit 200

# Output: reports/eval_<dataset>_<timestamp>.json  +  reports/eval_summary.txt
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from datetime import datetime
from pathlib import Path

import httpx

try:
    from datasets import load_dataset
    HF_AVAILABLE = True
except ImportError:
    HF_AVAILABLE = False
    print("WARNING: `datasets` not installed — run: pip install datasets")

# ─── Dataset configurations ────────────────────────────────────────────────────

DATASETS: dict[str, dict] = {
    "ealvaradob": {
        "hf_id": "ealvaradob/phishing-dataset",
        "config": "urls_dataset",         # subset with just URLs
        "split": "train",
        "url_col": "url",
        "label_col": "label",             # 0=legitimate, 1=phishing
        "phishing_value": 1,
        "description": "800k URLs (52% legit / 48% phishing) — general phishing corpus",
        "priority": 1,
    },
    "pirocheto": {
        "hf_id": "pirocheto/phishing-url",
        "config": None,
        "split": "train",
        "url_col": "url",
        "label_col": "status",            # "phishing" | "legitimate"
        "phishing_value": "phishing",
        "description": "11.4k URLs clean parquet — ideal for quick CI evaluation",
        "priority": 2,
    },
    "imanoop7": {
        "hf_id": "imanoop7/phishing_url_classification",
        "config": None,
        "split": "train",
        "url_col": "url",
        "label_col": "label",             # 1=phishing, 0=safe
        "phishing_value": 1,
        "description": "URL classification Safe/NotSafe — includes IP-based phishing",
        "priority": 3,
    },
    "phishnchips": {
        "hf_id": "AreLit/PhishNChips",
        "config": None,
        "split": "test",
        "url_col": "url",
        "label_col": "label",             # "phishing" | "legitimate"
        "phishing_value": "phishing",
        "description": "2000-email benchmark (1000 phishing + 1000 legit) for LLM evaluation",
        "priority": 4,
    },
    "naren1704": {
        "hf_id": "Naren1704/phishing-dataset",
        "config": "urls",
        "split": "train",
        "url_col": "url",
        "label_col": "label",
        "phishing_value": "phishing",
        "description": "URLs + Enron email bodies — multi-source aggregated",
        "priority": 5,
    },
}

# ─── Curated offline test set (no HuggingFace needed) ─────────────────────────
# Known phishing domains from OSINT / PhishTank public data +
# well-known legitimate domains. Used when HF is unavailable or for CI.

CURATED_CASES: list[dict] = [
    # ── IDN Homograph phishing (Cyrillic/Greek substitutions) ──────────────
    {"url": "https://pаypal.com/signin",         "expected": "PHISHING",   "note": "Cyrillic а (U+0430) in paypal"},
    {"url": "https://аpple.com/id",              "expected": "PHISHING",   "note": "Cyrillic а in apple"},
    {"url": "https://аmazon.com/order",          "expected": "PHISHING",   "note": "Cyrillic а in amazon"},
    {"url": "https://micrοsoft.com/login",       "expected": "PHISHING",   "note": "Greek ο (U+03BF) in microsoft"},
    {"url": "https://gοogle.com/accounts",       "expected": "PHISHING",   "note": "Greek ο in google"},
    {"url": "https://xn--pypal-4ve.com",         "expected": "PHISHING",   "note": "Punycode homograph of paypal"},
    {"url": "https://xn--80ak6aa92e.com",        "expected": "PHISHING",   "note": "Punycode — known homograph"},
    {"url": "https://facebооk.com",              "expected": "PHISHING",   "note": "Cyrillic оо in facebook"},
    {"url": "https://ẁells-fargo.com/online",    "expected": "PHISHING",   "note": "Combining grave accent lookalike"},
    {"url": "https://linkedln.com/login",        "expected": "PHISHING",   "note": "Typosquatting linkedin"},
    # ── Classic phishing domains ───────────────────────────────────────────
    {"url": "http://192.168.1.1/paypal/login",   "expected": "PHISHING",   "note": "IP-based phishing"},
    {"url": "http://paypal.com.secure-login.net/account", "expected": "PHISHING", "note": "Subdomain phishing"},
    {"url": "http://secure-bankofamerica.com/",  "expected": "PHISHING",   "note": "Brand in subdomain"},
    {"url": "http://update-your-apple-id.com",   "expected": "PHISHING",   "note": "Phishing keyword domain"},
    {"url": "http://account-verify-amazon.com",  "expected": "PHISHING",   "note": "Brand + action keyword"},
    {"url": "http://netflix-billing-update.com", "expected": "PHISHING",   "note": "Service + billing keyword"},
    {"url": "http://usbbog-edu-co.malicious.com","expected": "PHISHING",   "note": "USB domain impersonation"},
    # ── Legitimate well-known domains ─────────────────────────────────────
    {"url": "https://google.com",               "expected": "LEGITIMATE", "note": "Google main domain"},
    {"url": "https://github.com",               "expected": "LEGITIMATE", "note": "GitHub"},
    {"url": "https://microsoft.com",            "expected": "LEGITIMATE", "note": "Microsoft"},
    {"url": "https://amazon.com",               "expected": "LEGITIMATE", "note": "Amazon"},
    {"url": "https://wikipedia.org",            "expected": "LEGITIMATE", "note": "Wikipedia"},
    {"url": "https://usbbog.edu.co",            "expected": "LEGITIMATE", "note": "USB Bogota institutional"},
    {"url": "https://unal.edu.co",              "expected": "LEGITIMATE", "note": "Nacional Colombia"},
    {"url": "https://paypal.com",               "expected": "LEGITIMATE", "note": "PayPal official"},
    {"url": "https://apple.com",                "expected": "LEGITIMATE", "note": "Apple official"},
    {"url": "https://linkedin.com",             "expected": "LEGITIMATE", "note": "LinkedIn official"},
    {"url": "https://youtube.com",              "expected": "LEGITIMATE", "note": "YouTube"},
    {"url": "https://cloudflare.com",           "expected": "LEGITIMATE", "note": "Cloudflare"},
    {"url": "https://fastapi.tiangolo.com",     "expected": "LEGITIMATE", "note": "FastAPI docs"},
    # ── Suspicious / borderline ────────────────────────────────────────────
    {"url": "https://paypa1.com",               "expected": "SUSPICIOUS", "note": "Digit substitution (l→1)"},
    {"url": "https://arnazon.com",              "expected": "SUSPICIOUS", "note": "Letter swap in amazon"},
    {"url": "https://go0gle.com",               "expected": "SUSPICIOUS", "note": "Zero substitution in google"},
]

# ─── API client ────────────────────────────────────────────────────────────────

async def analyze_url(client: httpx.AsyncClient, backend: str, url: str, token: str) -> dict:
    """Call POST /api/v1/analyze and return the JSON response."""
    try:
        resp = await client.post(
            f"{backend}/api/v1/analyze",
            json={"url": url},
            headers={"Authorization": f"Bearer {token}"},
            timeout=30.0,
        )
        resp.raise_for_status()
        return resp.json()
    except httpx.TimeoutException:
        return {"error": "timeout", "verdict": "ERROR"}
    except httpx.HTTPStatusError as e:
        return {"error": f"HTTP {e.response.status_code}", "verdict": "ERROR"}
    except Exception as e:
        return {"error": str(e), "verdict": "ERROR"}


async def get_token(backend: str, username: str = "admin", password: str = "Admin1234!") -> str:
    """Obtain a JWT from the /auth/login endpoint."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{backend}/api/v1/auth/login",
            json={"username": username, "password": password},
            timeout=10.0,
        )
        if resp.status_code == 200:
            return resp.json()["access_token"]
        # Dev mode fallback — backend accepts any creds in dev
        return "dev-token"


# ─── Metrics ──────────────────────────────────────────────────────────────────

def compute_metrics(results: list[dict]) -> dict:
    """
    Compute precision, recall, F1, accuracy for binary phishing classification.
    PHISHING = positive class; LEGITIMATE/SUSPICIOUS = negative class.
    """
    tp = fp = tn = fn = errors = 0
    for r in results:
        if r["verdict"] == "ERROR":
            errors += 1
            continue
        predicted_phishing = r["verdict"] == "PHISHING"
        actual_phishing = r["expected"] == "PHISHING"
        if predicted_phishing and actual_phishing:
            tp += 1
        elif predicted_phishing and not actual_phishing:
            fp += 1
        elif not predicted_phishing and actual_phishing:
            fn += 1
        else:
            tn += 1

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0

    return {
        "total": total,
        "errors": errors,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "meets_thesis_target": precision >= 0.80 and recall >= 0.75,
    }


# ─── Dataset loader ────────────────────────────────────────────────────────────

def load_hf_cases(dataset_key: str, limit: int) -> list[dict]:
    """Load URL cases from a HuggingFace dataset."""
    if not HF_AVAILABLE:
        raise RuntimeError("datasets library not installed")

    cfg = DATASETS[dataset_key]
    print(f"  Loading {cfg['hf_id']} (config={cfg['config']}, split={cfg['split']})…")
    ds = load_dataset(
        cfg["hf_id"],
        cfg["config"],
        split=cfg["split"],
        trust_remote_code=False,
    )
    # Sample evenly: half phishing, half legitimate for balanced evaluation
    phishing_val = cfg["phishing_value"]
    url_col = cfg["url_col"]
    label_col = cfg["label_col"]

    phishing = [r for r in ds if r[label_col] == phishing_val][:limit // 2]
    legitimate = [r for r in ds if r[label_col] != phishing_val][:limit // 2]

    cases = []
    for r in phishing:
        cases.append({
            "url": r[url_col],
            "expected": "PHISHING",
            "source": cfg["hf_id"],
        })
    for r in legitimate:
        cases.append({
            "url": r[url_col],
            "expected": "LEGITIMATE",
            "source": cfg["hf_id"],
        })
    return cases


# ─── Main evaluation loop ──────────────────────────────────────────────────────

async def run_evaluation(
    backend: str,
    dataset_key: str,
    limit: int,
    concurrency: int,
    output_dir: Path,
) -> dict:
    """Run full evaluation for one dataset and return metrics."""

    # Choose cases source
    if dataset_key == "curated":
        cases = CURATED_CASES.copy()
        source_label = "curated-offline"
    else:
        try:
            cases = load_hf_cases(dataset_key, limit)
            source_label = DATASETS[dataset_key]["hf_id"]
        except Exception as e:
            print(f"  Could not load HuggingFace dataset: {e}")
            print("  Falling back to curated offline cases.")
            cases = CURATED_CASES.copy()
            source_label = "curated-offline (fallback)"

    print(f"  {len(cases)} cases loaded from {source_label}")
    print(f"  Calling {backend}/api/v1/analyze …")

    token = await get_token(backend)
    results = []
    sem = asyncio.Semaphore(concurrency)
    start = time.perf_counter()

    async def analyze_with_sem(case: dict) -> dict:
        async with sem:
            resp = await analyze_url(client, backend, case["url"], token)
            return {
                "url": case["url"],
                "expected": case.get("expected", "UNKNOWN"),
                "verdict": resp.get("verdict", "ERROR"),
                "s_risk": resp.get("s_risk"),
                "note": case.get("note", ""),
                "error": resp.get("error"),
            }

    async with httpx.AsyncClient() as client:
        tasks = [analyze_with_sem(c) for c in cases]
        results = await asyncio.gather(*tasks)

    elapsed = time.perf_counter() - start
    metrics = compute_metrics(list(results))
    metrics["elapsed_s"] = round(elapsed, 2)
    metrics["avg_latency_ms"] = round(elapsed * 1000 / len(cases), 1) if cases else 0
    metrics["dataset"] = source_label
    metrics["timestamp"] = datetime.utcnow().isoformat()

    # Save detailed results
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_file = output_dir / f"eval_{dataset_key}_{ts}.json"
    out_file.write_text(json.dumps({"metrics": metrics, "results": list(results)}, indent=2))
    print(f"  Detailed results → {out_file}")

    return metrics


def print_report(all_metrics: list[dict]) -> None:
    """Print a human-readable summary table."""
    print("\n" + "=" * 72)
    print(f"{'EVALUATION SUMMARY':^72}")
    print("=" * 72)
    header = f"{'Dataset':<28} {'Prec':>6} {'Rec':>6} {'F1':>6} {'Acc':>6} {'✓Thesis':>8}"
    print(header)
    print("-" * 72)
    for m in all_metrics:
        name = m["dataset"][:27]
        target = "✅" if m["meets_thesis_target"] else "❌"
        print(
            f"{name:<28} {m['precision']:>6.3f} {m['recall']:>6.3f} "
            f"{m['f1']:>6.3f} {m['accuracy']:>6.3f} {target:>8}"
        )
    print("=" * 72)
    print("Thesis targets: Precision ≥ 0.80 | Recall ≥ 0.75")
    print()


# ─── CLI ──────────────────────────────────────────────────────────────────────

async def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate backendTesis phishing detector")
    parser.add_argument("--backend", default="http://localhost:8000", help="Backend base URL")
    parser.add_argument(
        "--dataset",
        default="curated",
        choices=["curated", "ealvaradob", "pirocheto", "imanoop7", "phishnchips", "naren1704", "all"],
        help="Dataset to evaluate (default: curated offline set)",
    )
    parser.add_argument("--limit", type=int, default=200, help="Max URLs per class (HF datasets)")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrent API requests")
    parser.add_argument("--output", default="reports", help="Output directory for JSON reports")
    args = parser.parse_args()

    output_dir = Path(args.output)

    # Health check
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{args.backend}/health", timeout=5.0)
            r.raise_for_status()
        print(f"✅ Backend is reachable at {args.backend}")
    except Exception as e:
        print(f"❌ Backend not reachable at {args.backend}: {e}")
        print("   Start it with: uvicorn main:app --port 8000")
        return

    keys = list(DATASETS.keys()) if args.dataset == "all" else [args.dataset]
    all_metrics = []

    for key in keys:
        label = DATASETS[key]["description"] if key != "curated" else "Hand-curated IDN + brand phishing"
        print(f"\n{'─'*72}")
        print(f"Dataset: {key.upper()}")
        print(f"  {label}")
        metrics = await run_evaluation(
            backend=args.backend,
            dataset_key=key,
            limit=args.limit,
            concurrency=args.concurrency,
            output_dir=output_dir,
        )
        print(f"  Precision={metrics['precision']:.3f}  Recall={metrics['recall']:.3f}  "
              f"F1={metrics['f1']:.3f}  Latency={metrics['avg_latency_ms']:.0f}ms/req")
        all_metrics.append(metrics)

    print_report(all_metrics)

    # Write summary
    summary_path = output_dir / "eval_summary.txt"
    lines = [
        f"Evaluation Summary — {datetime.utcnow().isoformat()}",
        f"Backend: {args.backend}",
        f"Thesis targets: Precision ≥ 0.80 | Recall ≥ 0.75",
        "",
    ]
    for m in all_metrics:
        status = "PASS" if m["meets_thesis_target"] else "FAIL"
        lines.append(
            f"[{status}] {m['dataset'][:40]:<40} "
            f"P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f}"
        )
    summary_path.write_text("\n".join(lines))
    print(f"Summary written → {summary_path}")


if __name__ == "__main__":
    asyncio.run(main())
