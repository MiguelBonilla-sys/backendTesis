"""Pure corpus and evidence contracts for the evaluation scripts."""

from __future__ import annotations

import hashlib
import json
import math
from urllib.parse import urlsplit

import httpx

from utils.url_parser import extract_registrable_domain


def canonical_url(url: str) -> str:
    parsed = httpx.URL(url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.host:
        raise ValueError("Corpus contains an invalid HTTP(S) URL")
    return str(parsed.copy_with(fragment=None))


def unique_cases(cases: list[dict]) -> list[dict]:
    by_url: dict[str, dict] = {}
    for case in cases:
        url = canonical_url(case["url"])
        if case.get("expected") not in ("PHISHING", "LEGITIMATE"):
            raise ValueError("Each evaluation case needs a binary ground truth label")
        if url in by_url and by_url[url]["expected"] != case["expected"]:
            raise ValueError("Conflicting ground truth labels for the same URL")
        by_url.setdefault(url, {**case, "url": url})
    return [by_url[url] for url in sorted(by_url)]


def split_cases(
    cases: list[dict], calibration_fraction: float = 0.3, seed: str = "tesis-eval-v2"
) -> list[dict]:
    """No URL, registrable domain, campaign or synthetic base crosses splits."""
    cases = unique_cases(cases)
    parents: dict[str, str] = {}

    def root(key):
        parents.setdefault(key, key)
        while parents[key] != key:
            key = parents[key]
        return key

    def domain(value):
        host = urlsplit(value if "://" in value else "https://" + value).hostname or value
        return "domain:" + extract_registrable_domain(host)

    keys = []
    for case in cases:
        group = domain(case["url"])
        related = [group]
        if case.get("base"):
            related.append(domain(case["base"]))
        if case.get("campaign"):
            related.append("campaign:" + str(case["campaign"]))
        for other in related:
            a, b = sorted((root(group), root(other)))
            parents[b] = a
        keys.append(group)
    groups = {root(key) for key in keys}
    if len(groups) < 2 or not 0 < calibration_fraction < 1:
        raise ValueError("Separate calibration/test require at least two independent groups")
    ordered = sorted(groups, key=lambda g: hashlib.sha256(f"{seed}:{g}".encode()).hexdigest())
    n_calibration = min(len(groups) - 1, max(1, round(len(groups) * calibration_fraction)))
    calibration = set(ordered[:n_calibration])
    return [
        {**c, "group": root(k), "split": "calibration" if root(k) in calibration else "test"}
        for c, k in zip(cases, keys, strict=True)
    ]


def corpus_hash(cases: list[dict]) -> str:
    return hashlib.sha256(
        json.dumps(cases, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()


def validate_manifest(manifest: dict) -> None:
    if (
        manifest.get("frozen") is not True
        or manifest.get("learning") is not False
        or manifest.get("calibration") is not False
        or manifest.get("conductor") is not False
    ):
        raise ValueError(
            "Backend must enable frozen evaluation with learning/calibration/conductor off"
        )
    if not all(
        isinstance(manifest.get(k), str) and len(manifest[k]) == 64
        for k in ("snapshot_sha256", "config_sha256")
    ):
        raise ValueError("Evaluation requires snapshot and configuration SHA256")


def valid_prediction(row: dict) -> bool:
    """0.5 is valid only when actual inference succeeded; old reports are unknown."""
    statuses = row.get("agent_status") or {}
    for key in ("hf_url", "llm"):
        if statuses.get(key, {}).get("status") != "ok":
            return False
    if not statuses["hf_url"].get("model") or not statuses["hf_url"].get("revision"):
        return False
    return row.get("pipeline_verdict") in ("PHISHING", "LEGITIMATE", "SUSPICIOUS") and all(
        isinstance(row.get(k), (int, float)) and math.isfinite(row[k]) and 0 <= row[k] <= 1
        for k in ("s_hf", "s_risk")
    )
