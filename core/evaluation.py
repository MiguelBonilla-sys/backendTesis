"""Explicit, process-frozen evidence for reproducible offline detector evaluation.

The JSON maps normalized URLs to captured TI/probe results and retrieved RAG
chunks. Missing evidence is an error, never an implicit live lookup. A new
snapshot requires a process restart. No credentials are included in manifests.
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path

from core.config import settings
from utils.url_parser import normalize_url


@lru_cache(maxsize=1)
def _load_snapshot(path: str) -> tuple[dict, str]:
    if not path:
        raise ValueError("EVALUATION_MODE requires EVALUATION_SNAPSHOT_PATH")
    raw = Path(path).read_bytes()
    data = json.loads(raw)
    if data.get("version") != 1 or not isinstance(data.get("cases"), dict):
        raise ValueError("Evaluation snapshot requires version=1 and cases mapping")
    return data, hashlib.sha256(raw).hexdigest()


def evidence_for(url: str) -> dict:
    data, _ = _load_snapshot(settings.EVALUATION_SNAPSHOT_PATH)
    value = data["cases"].get(normalize_url(url))
    if not isinstance(value, dict) or not all(
        key in value for key in ("ti_result", "probe_result", "rag_context")
    ):
        raise ValueError("URL has no complete frozen evaluation evidence")
    if not isinstance(value["rag_context"], list) or not all(
        isinstance(c, str) for c in value["rag_context"]
    ):
        raise ValueError("Frozen RAG context must be a list of strings")
    return value


def evaluation_manifest() -> dict:
    if not settings.EVALUATION_MODE:
        return {"frozen": False}
    from core import constants

    _, snapshot_hash = _load_snapshot(settings.EVALUATION_SNAPSHOT_PATH)
    config = {
        "constants": {
            name: sorted(value) if isinstance(value, frozenset) else value
            for name, value in vars(constants).items()
            if name.isupper()
        },
        "hf_model": settings.HF_URL_MODEL,
        "hf_revision": settings.HF_URL_MODEL_REVISION,
        "hf_local_sha256": _file_hash(settings.HF_URL_ONNX_PATH)
        if settings.HF_URL_ONNX_PATH
        else None,
        "llm_model": settings.LLM_MODEL,
        "llm_fallback": settings.LLM_MODEL_FALLBACK,
        "llm_provider": settings.LLM_PROVIDER,
        "llm_max_tokens": settings.LLM_MAX_TOKENS,
        "top1m_limit": settings.TOP1M_LIMIT,
        "idn_dominance": settings.IDN_DOMINANCE_ENABLED,
        "redaction": settings.LLM_REDACT_PROMPT,
        "context_chars": settings.RAG_CONTEXT_MAX_CHARS,
        "chunk_chars": settings.RAG_CHUNK_MAX_CHARS,
    }
    for key, path in (
        ("top1m_sha256", settings.TOP1M_PATH),
        ("confusables_sha256", settings.CONFUSABLES_PATH),
    ):
        config[key] = _file_hash(path)
    digest = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    return {
        "frozen": True,
        "learning": False,
        "calibration": False,
        "conductor": False,
        "snapshot_sha256": snapshot_hash,
        "config_sha256": digest,
        "config": config,
    }


@lru_cache(maxsize=8)
def _file_hash(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
