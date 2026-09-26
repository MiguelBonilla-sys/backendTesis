"""Captura evidencia TI/probe/RAG real, una sola vez, para EVALUATION_MODE.

Corre en modo normal (EVALUATION_MODE=false) dentro del backend con sus stores:

    head -n 20 data/idn_synth.jsonl > /tmp/demo_phish.jsonl
    head -n 20 data/legit_sample.jsonl > /tmp/demo_legit.jsonl
    python -m scripts.capture_eval_snapshot --jsonl /tmp/demo_phish.jsonl \
        --legit-jsonl /tmp/demo_legit.jsonl --output /tmp/eval_snapshot_demo.json

--limit solo aplica a --dataset (HF); los JSONL se cargan completos. Cada caso
gasta una consulta real a VirusTotal/URLScan/GSB (URLScan: 100 scans/día).

El JSON resultante es el que lee core/evaluation.py (version=1, cases por URL
normalizada). El LLM no se congela: se sigue llamando en vivo al evaluar.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from agents.idn_agent import idn_agent
from agents.llm_agent import llm_agent
from agents.web_probe_agent import web_probe_agent
from data_pipeline.threat_intel import threat_intel_service
from models.chromadb_client import init_chromadb
from models.redis_client import init_redis
from scripts.eval_baseline_vs_pipeline import collect_cases
from utils.url_parser import extract_effective_domain, normalize_url


def _idn_summary(idn_result) -> str:
    # ponytail: copia del formato de services.analysis.run_pipeline_core; si cambia allá,
    # la query RAG capturada deja de coincidir con la que haría el pipeline en vivo.
    confusables = (
        ", ".join(repr(c) for c in idn_result.confusable_chars[:5])
        if idn_result.confusable_chars
        else "none"
    )
    return (
        f"domain_unicode={idn_result.domain_unicode!r}, "
        f"s_idn_local={idn_result.s_idn_local:.2f}, "
        f"homograph_ratio={idn_result.homograph_ratio:.2f}, "
        f"visual_similarity={idn_result.visual_similarity:.2f}, "
        f"mixed_script={idn_result.is_mixed_script}, "
        f"confusable_chars=[{confusables}], "
        f"suspicious={idn_result.is_suspicious}"
    )


async def capture_one(url: str) -> tuple[str, dict]:
    url = url.strip()
    domain = extract_effective_domain(url)
    idn_result, ti_result, probe_result = await asyncio.gather(
        idn_agent.analyze(url),
        threat_intel_service.analyze(url, domain),
        web_probe_agent.analyze(url),
    )
    rag = await llm_agent._retrieve_rag_context(
        url=url, domain=domain, idn_summary=_idn_summary(idn_result)
    )
    return normalize_url(url), {
        "ti_result": ti_result.model_dump(mode="json"),
        "probe_result": probe_result.model_dump(mode="json"),
        "rag_context": list(rag),
    }


async def main() -> None:
    parser = argparse.ArgumentParser(description="Captura snapshot para EVALUATION_MODE")
    parser.add_argument("--jsonl")
    parser.add_argument("--legit-jsonl")
    parser.add_argument("--dataset")
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    await init_redis()
    await init_chromadb()
    await idn_agent.initialize()

    cases = collect_cases(args)
    sem = asyncio.Semaphore(args.concurrency)

    async def guarded(url: str):
        async with sem:
            return await capture_one(url)

    pairs = await asyncio.gather(*(guarded(c["url"]) for c in cases))
    snapshot = {"version": 1, "cases": dict(pairs)}
    Path(args.output).write_text(json.dumps(snapshot, ensure_ascii=False, indent=1, sort_keys=True))
    print(f"{len(pairs)} casos capturados -> {args.output}")


if __name__ == "__main__":
    asyncio.run(main())
