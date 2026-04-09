"""Tests for schemas/incident_schemas.py — Pydantic model instantiation."""

import uuid
from datetime import datetime, timezone

from schemas.incident_schemas import (
    AgentResultDetail,
    IncidentDetailResponse,
    IncidentListItem,
    IncidentListResponse,
    XAIReportDetail,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def test_incident_list_item_fields():
    item = IncidentListItem(
        id=uuid.uuid4(),
        trace_id=uuid.uuid4(),
        domain="evil.com",
        verdict="PHISHING",
        s_risk=0.92,
        reviewed=False,
        created_at=_now(),
    )
    assert item.domain == "evil.com"
    assert item.verdict == "PHISHING"
    assert item.s_risk == 0.92
    assert item.reviewed is False


def test_incident_list_item_safe_verdict():
    item = IncidentListItem(
        id=uuid.uuid4(),
        trace_id=uuid.uuid4(),
        domain="google.com",
        verdict="SAFE",
        s_risk=0.05,
        reviewed=True,
        created_at=_now(),
    )
    assert item.verdict == "SAFE"
    assert item.reviewed is True


def test_incident_list_response_structure():
    items = [
        IncidentListItem(
            id=uuid.uuid4(),
            trace_id=uuid.uuid4(),
            domain="phish.com",
            verdict="PHISHING",
            s_risk=0.95,
            reviewed=False,
            created_at=_now(),
        )
    ]
    response = IncidentListResponse(items=items, total=1, page=1, size=10, pages=1)
    assert response.total == 1
    assert response.page == 1
    assert response.size == 10
    assert response.pages == 1
    assert len(response.items) == 1


def test_incident_list_response_empty():
    response = IncidentListResponse(items=[], total=0, page=1, size=10, pages=0)
    assert response.items == []
    assert response.total == 0


def test_agent_result_detail():
    detail = AgentResultDetail(
        agent_name="IDNAgent",
        score=0.85,
        raw_output={"ratio_h": 0.5, "sim_v": 0.9},
        duration_ms=42,
    )
    assert detail.agent_name == "IDNAgent"
    assert detail.score == 0.85
    assert detail.duration_ms == 42


def test_agent_result_detail_no_duration():
    detail = AgentResultDetail(
        agent_name="LLMAgent",
        score=0.3,
        raw_output={},
        duration_ms=None,
    )
    assert detail.duration_ms is None


def test_xai_report_detail():
    report = XAIReportDetail(
        shap_values={"idn_contribution": 0.4, "llm_contribution": 0.3},
        lime_values={"feature_1": 0.2},
        top_features=["idn_contribution", "llm_contribution"],
    )
    assert "idn_contribution" in report.shap_values
    assert report.top_features[0] == "idn_contribution"


def test_incident_detail_response_with_xai():
    xai = XAIReportDetail(
        shap_values={"idn_contribution": 0.5},
        lime_values={},
        top_features=["idn_contribution"],
    )
    agent_results = [
        AgentResultDetail(agent_name="IDNAgent", score=0.7, raw_output={}, duration_ms=10)
    ]
    response = IncidentDetailResponse(
        id=uuid.uuid4(),
        trace_id=uuid.uuid4(),
        url="https://phish.example.com",
        domain="phish.example.com",
        verdict="SUSPICIOUS",
        s_risk=0.65,
        s_idn=0.7,
        s_llm=0.4,
        s_ti=0.1,
        reviewed=False,
        agent_results=agent_results,
        xai_report=xai,
        created_at=_now(),
    )
    assert response.verdict == "SUSPICIOUS"
    assert response.xai_report is not None
    assert response.s_idn == 0.7


def test_incident_detail_response_no_xai():
    response = IncidentDetailResponse(
        id=uuid.uuid4(),
        trace_id=uuid.uuid4(),
        url="https://safe.example.com",
        domain="safe.example.com",
        verdict="SAFE",
        s_risk=0.1,
        s_idn=0.05,
        s_llm=0.1,
        s_ti=0.0,
        reviewed=True,
        agent_results=[],
        xai_report=None,
        created_at=_now(),
    )
    assert response.xai_report is None
    assert response.agent_results == []
