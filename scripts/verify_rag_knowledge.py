"""Real retrieval smoke test or ad-hoc search; never calls the generative LLM.

This checks reference retrieval, not phishing classification accuracy.
Run: python -m scripts.verify_rag_knowledge [--query 'SPF DKIM DMARC']
"""
from __future__ import annotations

import argparse
import asyncio
import json
import time
from datetime import UTC, datetime
from pathlib import Path

from agents.llm_agent import LLMAgent
from core.config import settings
from core.constants import COLLECTION_KNOWLEDGE
from data_pipeline.hybrid_retrieval import hybrid_retriever
from models.chromadb_client import get_or_create_collection, init_chromadb, query_collection

CASES = [
    ("¿Cómo detectar homógrafos IDN que mezclan letras cirílicas y latinas confusables?",
     ["https://www.unicode.org/reports/tr39/"]),
    ("Why can SPF fail when legitimate mail is forwarded? How does DKIM help?",
     ["https://learn.microsoft.com/en-us/defender-office-365/email-authentication-about",
      "https://learn.microsoft.com/es-es/defender-office-365/email-authentication-about"]),
    ("¿Cómo se relaciona la alineación DMARC con el remitente visible From, SPF y DKIM?",
     ["https://learn.microsoft.com/es-es/defender-office-365/email-authentication-about",
      "https://learn.microsoft.com/en-us/defender-office-365/email-authentication-about"]),
    ("Spearphishing attachment T1566.001 malicious email attachments",
     ["https://attack.mitre.org/techniques/T1566/001/"]),
    ("Spearphishing link T1566.002 OAuth device code phishing",
     ["https://attack.mitre.org/techniques/T1566/002/"]),
    ("Adversary in the middle AiTM phishing session cookie theft bypass MFA",
     ["https://learn.microsoft.com/en-us/defender-xdr/session-cookie-theft-alert"]),
    ("¿Qué señales ayudan a reconocer un correo que pide datos personales con urgencia?",
     ["https://www.incibe.es/incibe/protegete-conoce-a-fondo-phishing",
      "https://www.cisa.gov/secure-our-world/recognize-and-report-phishing"]),
    ("How should employees verify suspicious email links through an independent channel?",
     ["https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/teach-employees-avoid-phishing",
      "https://www.cisa.gov/secure-our-world/recognize-and-report-phishing",
      "https://www.incibe.es/incibe/protegete-conoce-a-fondo-phishing"]),
]


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--query")
    parser.add_argument("--cases", type=Path,
                        help="JSON list of [query, expected_source_urls] for retrieval smoke tests")
    parser.add_argument("--sources", type=Path, default=Path("data/knowledge_sources.json"),
                        help="Reviewed source manifest to replay with --verify-idempotency")
    parser.add_argument("--verify-idempotency", action="store_true",
                        help="Replay the reviewed snapshots and compare stored document IDs")
    parser.add_argument("--output", type=Path,
                        default=Path("../.firecrawl/knowledge/retrieval-check.json"))
    args = parser.parse_args()
    await init_chromadb()
    collection = await get_or_create_collection(COLLECTION_KNOWLEDGE)
    idempotency = None
    if args.verify_idempotency:
        from data_pipeline.reference_ingest import ingest_references, prepare_references

        spec = json.loads(args.sources.read_text(encoding="utf-8"))
        records, _ = prepare_references(
            spec["sources"], Path("../.firecrawl"), spec["retrieved_at"]
        )
        before = set((await collection.get(include=["metadatas"]))["ids"])
        await ingest_references(records)
        after = set((await collection.get(include=["metadatas"]))["ids"])
        idempotency = {"unchanged_ids": before == after,
                       "count_before": len(before), "count_after": len(after)}
        if before != after:
            raise RuntimeError("Ingestion replay changed the set of IDs")
    results = []
    cases = json.loads(args.cases.read_text(encoding="utf-8")) if args.cases else CASES
    for query, expected in [(args.query, [])] if args.query else cases:
        entry = {"query": query, "expected_sources": expected}
        for mode in ("dense", "hybrid"):
            start = time.perf_counter()
            candidates = (await query_collection(COLLECTION_KNOWLEDGE, [query], 6)
                          if mode == "dense" else
                          await hybrid_retriever.search(COLLECTION_KNOWLEDGE, query, 6))
            selected = LLMAgent._rerank_by_source(candidates)
            entry[mode] = {
                "elapsed_ms": round((time.perf_counter() - start) * 1000, 1),
                "hit_at_3": any(
                    r["metadata"].get("source_url") in expected for r in selected
                ),
                "results": [{"id": r["id"], "title": r["metadata"].get("title"),
                             "source_url": r["metadata"].get("source_url"),
                             "excerpt": r["document"][:250]} for r in selected],
            }
        results.append(entry)
    report = {
        "scope": "Reference retrieval smoke test; not a phishing classification benchmark",
        "checked_at": datetime.now(UTC).isoformat(), "collection": COLLECTION_KNOWLEDGE,
        "collection_count": await collection.count(), "embedding_model": settings.EMBED_MODEL,
        "cases": results,
    }
    agent = LLMAgent()
    context = await agent._retrieve_rag_context(
        "https://example.org", "example.org", "SPF DKIM DMARC email authentication"
    )
    prompt = agent._build_prompt("https://example.org", "example.org", None, context, None)
    report["llm_prompt_has_public_reference"] = (
        "Security reference" in prompt and "source=official_reference" in prompt
    )
    if not report["llm_prompt_has_public_reference"]:
        raise RuntimeError("LLMAgent did not include public references in its prompt")
    if idempotency is not None:
        report["idempotency"] = idempotency
    if not args.query:
        report["hit_at_3"] = {mode: sum(r[mode]["hit_at_3"] for r in results) / len(results)
                              for mode in ("dense", "hybrid")}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report if args.query else {k: v for k, v in report.items() if k != "cases"},
                     ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(main())
