"""Regressions: missing evidence cannot produce a successful clean verdict."""

from importlib import import_module
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from core.agent_signal import SignalScore
from main import app
from schemas.analyze import AgentTelemetry, EmailSignals
from services.email_analysis import analyze_email_content
from tests.auth_helpers import create_access_token
from tests.unit.test_persist_helpers import _make_response
from utils.email_parser import _extract_email_domain, parse_eml

eml_router = import_module("routers.eml_router")


@pytest.fixture
def api(auth_store):
    client = TestClient(app)
    client.headers["Authorization"] = "Bearer " + create_access_token(
        {"sub": "admin", "role": "admin"}
    )
    yield client
    client.close()


def eml(text):
    return (
        "From: sender@usbbog.edu.co\nSubject: Notice\n"
        "Authentication-Results: fake; spf=pass; dkim=pass\n\n" + text
    ).encode()


def test_display_name_and_uploaded_authentication_are_not_trusted():
    spoofed = '"contact@usbbog.edu.co" <attacker@outside.example>'
    assert _extract_email_domain(spoofed) == "outside.example"
    assert _extract_email_domain("a@usbbog.edu.co, b@outside.example") == ""
    from services.analysis import _sender_domain

    assert _sender_domain(spoofed) == "outside.example"
    parsed = parse_eml(eml("Hello"))
    assert parsed.spf_pass and parsed.dkim_pass
    assert parsed.authentication_verified is False
    from data_pipeline.knowledge_updater import is_usb_baseline_candidate

    assert not is_usb_baseline_candidate(
        sender_domain=parsed.sender_domain,
        spf_pass=True,
        dkim_pass=True,
        verdict="LEGITIMATE",
        s_risk=0.01,
    )


@pytest.mark.parametrize("partial", [False, True])
def test_eml_failed_links_return_incomplete_not_legitimate(api, monkeypatch, partial):
    results = [
        _make_response(verdict="LEGITIMATE", s_risk=0.05) if partial else RuntimeError("down"),
        RuntimeError("down"),
    ]
    monkeypatch.setattr(eml_router, "_analyze_single_url_for_email", AsyncMock(side_effect=results))
    persist = AsyncMock()
    monkeypatch.setattr(eml_router, "_persist_eml_incident", persist)
    response = api.post(
        "/api/v1/analyze_eml",
        files={"file": ("sample.eml", eml("https://a.example https://b.example"))},
    )
    assert response.status_code == 503
    assert response.json()["detail"]["analysis_status"] == (
        "partial" if partial else "indeterminate"
    )
    persist.assert_not_awaited()


def test_linkless_eml_analyzes_content_and_cannot_seed_uploaded_headers(api, monkeypatch):
    assessment = _make_response(verdict="SUSPICIOUS", s_risk=0.25)
    content = AsyncMock(return_value=(assessment, "indeterminate"))
    persist, baseline = AsyncMock(), AsyncMock()
    monkeypatch.setattr(eml_router, "analyze_email_content", content)
    monkeypatch.setattr(eml_router, "_persist_eml_incident", persist)
    monkeypatch.setattr(eml_router.knowledge_updater, "ingest_legit_baseline", baseline)
    response = api.post(
        "/api/v1/analyze_eml", files={"file": ("sample.eml", eml("Transfer funds now"))}
    )
    assert response.status_code == 200
    assert response.json()["email_verdict"] == "SUSPICIOUS"
    assert response.json()["analysis_status"] == "indeterminate"
    assert response.json()["content_analysis"]["request_id"] == assessment.request_id
    content.assert_awaited_once()
    persist.assert_awaited_once()
    baseline.assert_not_awaited()


@pytest.mark.parametrize(
    "llm_ok,hf_ok,status",
    [(False, False, "indeterminate"), (True, False, "partial"), (True, True, "complete")],
)
async def test_content_availability_controls_clean_verdict(monkeypatch, llm_ok, hf_ok, status):
    score = SignalScore(
        0.05 if llm_ok else 0.5, AgentTelemetry(status="ok" if llm_ok else "unavailable")
    )
    monkeypatch.setattr(
        "services.email_analysis.llm_agent.analyze",
        AsyncMock(return_value=(score, "content evidence")),
    )
    monkeypatch.setattr(
        "services.email_analysis.hf_agent.analyze_content_with_status",
        AsyncMock(
            return_value=(
                0.05 if hf_ok else 0.5,
                AgentTelemetry(status="ok" if hf_ok else "timeout"),
            )
        ),
    )
    result, actual = await analyze_email_content(EmailSignals(), "Hello", "hash")
    assert actual == status
    assert result.verdict == ("LEGITIMATE" if status == "complete" else "SUSPICIOUS")


def test_success_is_not_acknowledged_when_storage_fails(api, monkeypatch):
    persist = AsyncMock(side_effect=RuntimeError("private database detail"))
    monkeypatch.setattr("models.database.execute", persist)
    response = api.post(
        "/api/v1/report", json={"url": "https://example.com", "reported_verdict": "PHISHING"}
    )
    assert response.status_code == 503
    assert "private database detail" not in response.text
    assert response.headers["retry-after"] == "5"


def test_eml_link_limit_rejects_instead_of_ignoring_unchecked_links(api):
    response = api.post(
        "/api/v1/analyze_eml",
        files={"file": ("sample.eml", eml(" ".join(f"https://a{i}.example" for i in range(11))))},
    )
    assert response.status_code == 422
