"""Detector regression evidence: availability, safe theta and frozen evaluation."""

from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agents.fusion_agent import FusionAgent
from agents.hf_agent import HFAgent
from agents.llm_agent import LLMAgent
from core import calibration, evaluation
from core.agent_signal import SignalScore, telemetry_of
from core.config import settings
from schemas.analyze import AgentTelemetry, IDNResult, TIResult, WebProbeResult
from scripts.eval_protocol import (
    corpus_hash,
    split_cases,
    unique_cases,
    valid_prediction,
    validate_manifest,
)
from services.analysis import run_pipeline_core, schedule_autoingest


def idn():
    return IDNResult(
        domain_unicode="example",
        confusable_chars=[],
        homograph_ratio=0,
        visual_similarity=0,
        s_idn_local=0,
        is_mixed_script=False,
        is_suspicious=False,
    )


def ti():
    return TIResult(s_vt=0, s_urlscan=0, s_gsb=0, s_ti=0)


async def test_exactly_half_is_distinguished_from_unavailable(monkeypatch):
    from importlib import import_module

    hf_module = import_module("agents.hf_agent")
    session = MagicMock()
    session.run.return_value = [None, [[0.5, 0.5]]]
    monkeypatch.setattr(hf_module, "_get_url_onnx", lambda: session)
    actual = await HFAgent()._classify_url("https://example.com")
    monkeypatch.setattr(settings, "HUGGINGFACE_API_KEY", "")
    missing = await HFAgent()._classify_content("message")
    assert actual == missing == 0.5
    assert telemetry_of(actual).status == "ok"
    assert telemetry_of(actual).revision == settings.HF_URL_MODEL_REVISION
    assert telemetry_of(missing).status == "unavailable"
    assert telemetry_of(0.5).status == "unknown"


@pytest.mark.parametrize(
    "payload", [[], {"error": "loading"}, [{"label": "phishing", "score": float("nan")}]]
)
def test_invalid_hf_output_is_explicit(payload):
    result = HFAgent()._extract_phishing_score(payload)
    assert result == 0.5
    assert telemetry_of(result).status == "error"


async def test_llm_parse_failure_is_not_reported_as_success():
    agent = LLMAgent()
    with (
        patch.object(agent, "_retrieve_rag_context", AsyncMock(return_value=[])),
        patch.object(agent, "_call_llm", AsyncMock(return_value="No parseable score")),
    ):
        score, _ = await agent.analyze("https://example.com", "example.com")
    assert score == 0.5
    assert telemetry_of(score).status == "error"


def test_theta_guard_survives_old_unsafe_values():
    try:
        calibration.set_effective_theta(0.20)
        assert calibration.get_effective_theta() > 0.25
        result = calibration.choose_theta([(0.22, True)] * 20, min_samples=1, drift_max=1.0)
        assert result.new_theta >= calibration.minimum_safe_theta()
        with pytest.raises(ValueError):
            calibration.set_effective_theta(float("nan"))
    finally:
        calibration.reset_effective_theta()


@pytest.mark.parametrize(
    "strong,trusted,expected",
    [
        (True, False, "PHISHING"),
        (False, False, "LEGITIMATE"),
        (True, True, "LEGITIMATE"),
    ],
)
async def test_probe_can_detect_below_base_gate_but_login_alone_cannot(strong, trusted, expected):
    result = await FusionAgent().fuse(
        url="https://example.com",
        domain="example.com",
        idn_result=idn(),
        ti_result=ti(),
        s_llm=0.5,
        s_hf=0.5,
        llm_reason="neutral",
        start_time=time.perf_counter(),
        probe_result=WebProbeResult(
            s_probe=0.4,
            has_password_field=True,
            brand_impersonation="Example" if strong else None,
            external_form_action=strong,
        ),
        probe_domain_trusted=trusted,
    )
    assert result.verdict == expected
    contributions = result.shap_explanation.feature_contributions
    assert sum(
        contributions[k] for k in ("s_idn_local", "s_ti", "s_llm", "s_hf", "s_email", "s_probe")
    ) == pytest.approx(result.s_risk, abs=0.001)


@pytest.fixture
def snapshot(tmp_path, monkeypatch):
    path = tmp_path / "evidence.json"
    data = {
        "version": 1,
        "cases": {
            "https://example.com/": {
                "ti_result": ti().model_dump(),
                "probe_result": WebProbeResult().model_dump(),
                "rag_context": ["Frozen reference with provenance"],
            }
        },
    }
    path.write_text(json.dumps(data))
    for key, value in (
        ("EVALUATION_MODE", True),
        ("EVALUATION_SNAPSHOT_PATH", str(path)),
        ("TOP1M_PATH", str(path)),
        ("CONFUSABLES_PATH", str(path)),
    ):
        monkeypatch.setattr(settings, key, value)
    evaluation._load_snapshot.cache_clear()
    evaluation._file_hash.cache_clear()
    yield path
    evaluation._load_snapshot.cache_clear()
    evaluation._file_hash.cache_clear()


async def test_frozen_pipeline_never_queries_live_ti_probe_rag_or_learns(snapshot):
    ok = AgentTelemetry(status="ok", model="test", revision="fixed")
    hf = SignalScore(0.5, ok, {"hf_url": ok})
    with (
        patch("services.analysis.idn_agent.analyze", AsyncMock(return_value=idn())),
        patch("services.analysis.hf_agent.analyze", AsyncMock(return_value=hf)),
        patch(
            "services.analysis.llm_agent.analyze",
            AsyncMock(return_value=(SignalScore(0.5, ok), "neutral")),
        ),
        patch(
            "services.analysis.threat_intel_service.analyze",
            AsyncMock(side_effect=AssertionError("live TI")),
        ) as live_ti,
        patch(
            "services.analysis.web_probe_agent.analyze",
            AsyncMock(side_effect=AssertionError("live probe")),
        ) as live_probe,
        patch(
            "data_pipeline.hybrid_retrieval.hybrid_retriever.search",
            AsyncMock(side_effect=AssertionError("live RAG")),
        ) as live_rag,
        patch(
            "data_pipeline.knowledge_updater.knowledge_updater.ingest_from_analysis", AsyncMock()
        ) as ingest,
    ):
        response = await run_pipeline_core(
            "https://example.com/", "example.com", t_start=time.perf_counter()
        )
        context = await LLMAgent()._retrieve_rag_context("https://example.com/", "example.com")
        schedule_autoingest(response)
    assert context == ["Frozen reference with provenance"]
    validate_manifest(response.evaluation)
    live_ti.assert_not_awaited()
    live_probe.assert_not_awaited()
    live_rag.assert_not_awaited()
    ingest.assert_not_awaited()
    assert response.agent_status["hf_url"].status == "ok"


def test_snapshot_is_frozen_and_missing_urls_are_rejected(snapshot):
    first = evaluation.evaluation_manifest()
    snapshot.write_text('{"version":1,"cases":{}}')
    assert evaluation.evaluation_manifest() == first
    assert evaluation.evidence_for("https://example.com/")["rag_context"]
    with pytest.raises(ValueError, match="no complete"):
        evaluation.evidence_for("https://missing.example/")


def test_corpus_deduplicates_and_groups_domains_campaigns_and_synthetic_bases():
    cases = [
        {"url": "https://example.com/a#track", "expected": "LEGITIMATE"},
        {"url": "https://example.com/a", "expected": "LEGITIMATE"},
        {"url": "https://login.example.com/b", "expected": "PHISHING", "campaign": "campaign-1"},
        {"url": "https://attacker.org", "expected": "PHISHING", "campaign": "campaign-1"},
        {"url": "https://xn--spoof.net", "expected": "PHISHING", "base": "example.com"},
        {"url": "https://independent.edu", "expected": "LEGITIMATE"},
    ]
    result = split_cases(cases)
    assert len(result) == 5
    assert {row["split"] for row in result} == {"calibration", "test"}
    related = [row for row in result if "independent" not in row["url"]]
    assert len({row["group"] for row in related}) == len({row["split"] for row in related}) == 1
    assert corpus_hash(result) == corpus_hash(split_cases(list(reversed(cases))))
    with pytest.raises(ValueError, match="Conflicting"):
        unique_cases([cases[0], {**cases[1], "expected": "PHISHING"}])


def test_evaluation_refuses_legacy_or_fallback_rows():
    row = {"pipeline_verdict": "LEGITIMATE", "s_hf": 0.5, "s_risk": 0.25}
    assert not valid_prediction(row)
    row["agent_status"] = {
        "hf_url": {"status": "ok", "model": "url", "revision": "pinned"},
        "llm": {"status": "ok", "model": "llm"},
    }
    assert valid_prediction(row)
    row["agent_status"]["hf_url"]["status"] = "unavailable"
    assert not valid_prediction(row)
    with pytest.raises(ValueError):
        validate_manifest({"frozen": False})


async def test_ti_cache_separates_paths_and_tenants(monkeypatch):
    from data_pipeline.threat_intel import ThreatIntelService

    service = ThreatIntelService()
    cache = {}

    async def get(key):
        return cache.get(key)

    async def put(key, value, **kwargs):
        cache[key] = value

    for key in (
        "VIRUSTOTAL_API_KEY",
        "URLSCAN_API_KEY",
        "GOOGLE_SAFE_BROWSING_API_KEY",
        "WHOISXML_API_KEY",
    ):
        monkeypatch.setattr(settings, key, "fixture-key")
    monkeypatch.setattr("data_pipeline.threat_intel.get_ti_cache", get)
    monkeypatch.setattr("data_pipeline.threat_intel.set_ti_cache", put)
    vt = AsyncMock(side_effect=lambda url, domain: 0.9 if domain.startswith("evil.") else 0.0)
    gsb = AsyncMock(side_effect=lambda url: 1.0 if url.endswith("/bad") else 0.0)
    whois = AsyncMock(return_value=(0.0, 500))
    monkeypatch.setattr(service, "_query_virustotal", vt)
    monkeypatch.setattr(service, "_query_urlscan", AsyncMock(return_value=0.0))
    monkeypatch.setattr(service, "_query_gsb", gsb)
    monkeypatch.setattr(service, "_query_whoisxml", whois)
    clean = await service.analyze("https://host.example.com/good", "host.example.com")
    bad = await service.analyze("https://host.example.com/bad", "host.example.com")
    evil = await service.analyze("https://evil.example.com/", "evil.example.com")
    other = await service.analyze("https://other.example.com/", "other.example.com")
    # An IDN hint extracted from a CDN filename cannot change network reputation.
    again = await service.analyze("https://host.example.com/good", "forged-filename.org")
    assert (clean.s_gsb, bad.s_gsb, evil.s_vt, other.s_vt) == (0.0, 1.0, 0.9, 0.0)
    assert again == clean
    assert vt.await_count == 3 and gsb.await_count == 4 and whois.await_count == 1


def test_calibration_does_not_select_threshold_on_test_rows():
    from scripts.run_t5_t6 import run_t6_analysis

    available = {
        "hf_url": {"status": "ok", "model": "test", "revision": "fixed"},
        "llm": {"status": "ok", "model": "test"},
    }
    rows = [
        {"split": "calibration", "group": "cal", "s_risk": 0.35, "expected": "PHISHING"},
        {"split": "calibration", "group": "cal", "s_risk": 0.1, "expected": "LEGITIMATE"},
        {"split": "test", "group": "holdout", "s_risk": 0.6, "expected": "PHISHING"},
        {"split": "test", "group": "holdout", "s_risk": 0.2, "expected": "LEGITIMATE"},
    ]
    for row in rows:
        row.update(agent_status=available, s_hf=0.5, pipeline_verdict="LEGITIMATE")
    first = run_t6_analysis(rows)
    rows[2]["expected"], rows[3]["expected"] = "LEGITIMATE", "PHISHING"
    second = run_t6_analysis(rows)
    assert first["theta_recalibrado"] == second["theta_recalibrado"]
    assert first["test_metrics"] != second["test_metrics"]
    rows[-1]["group"] = "cal"
    with pytest.raises(ValueError, match="disjoint"):
        run_t6_analysis(rows)
