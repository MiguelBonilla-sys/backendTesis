"""Tests for routers/incidents_router.py — read-only admin dashboard endpoints."""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from auth.auth import require_auth as _require_auth
from main import app
from models.database import get_session

_MOCK_USER = {"sub": "admin", "role": "admin"}
_TRACE_ID = uuid.uuid4()
_ANALYSIS_ID = uuid.uuid4()
_NOW = datetime(2026, 4, 12, 10, 0, 0, tzinfo=timezone.utc)


# ── Mock builders ─────────────────────────────────────────────────────────────

def _mock_analysis(
    *,
    trace_id: uuid.UUID = _TRACE_ID,
    verdict: str = "PHISHING",
    s_risk: float = 0.85,
) -> MagicMock:
    a = MagicMock()
    a.id = _ANALYSIS_ID
    a.trace_id = trace_id
    a.url = "https://аpple.com/login"
    a.domain = "аpple.com"
    a.verdict = verdict
    a.s_risk = s_risk
    a.s_idn = 0.8
    a.s_llm = 0.7
    a.s_ti = 0.9
    a.created_at = _NOW
    return a


def _mock_agent_row(name: str, score: float) -> MagicMock:
    r = MagicMock()
    r.agent_name = name
    r.score = score
    r.raw_output = {}
    r.duration_ms = None
    return r


def _mock_xai_row() -> MagicMock:
    x = MagicMock()
    x.shap_values = {"idn_contribution": 0.3, "baseline": 0.5}
    x.lime_values = {}
    x.top_features = ["idn_contribution"]
    return x


def _scalar_one(value) -> MagicMock:
    r = MagicMock()
    r.scalar_one.return_value = value
    return r


def _scalars_all(items: list) -> MagicMock:
    r = MagicMock()
    r.scalars.return_value.all.return_value = items
    return r


def _scalar_one_or_none(value) -> MagicMock:
    r = MagicMock()
    r.scalar_one_or_none.return_value = value
    return r


def _make_list_session(analyses: list, total: int = None) -> AsyncMock:
    """Session mock for list_incidents: count then data query."""
    if total is None:
        total = len(analyses)
    session = AsyncMock()
    session.execute.side_effect = [_scalar_one(total), _scalars_all(analyses)]
    return session


def _make_detail_session(analysis, agent_rows=None, xai_row=None) -> AsyncMock:
    """Session mock for get_incident: analysis, agent_results, xai_report queries."""
    if agent_rows is None:
        agent_rows = [
            _mock_agent_row("idn_agent", 0.8),
            _mock_agent_row("llm_agent", 0.7),
            _mock_agent_row("fusion_agent", 0.85),
        ]
    session = AsyncMock()
    session.execute.side_effect = [
        _scalar_one_or_none(analysis),
        _scalars_all(agent_rows),
        _scalar_one_or_none(xai_row),
    ]
    return session


def _session_override(session: AsyncMock):
    """Returns an async generator FUNCTION (not object) for use as dependency override."""
    async def _gen():
        yield session
    return _gen


# ── Auth guard tests ──────────────────────────────────────────────────────────

async def test_incidents_list_without_token_returns_401():
    """GET /api/v1/incidents without auth → 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/api/v1/incidents")
    assert resp.status_code == 401


async def test_incidents_detail_without_token_returns_401():
    """GET /api/v1/incidents/{trace_id} without auth → 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get(f"/api/v1/incidents/{_TRACE_ID}")
    assert resp.status_code == 401


# ── List endpoint ─────────────────────────────────────────────────────────────

@pytest.fixture
def _auth_override():
    """Inject a pre-validated admin user and restore on teardown."""
    app.dependency_overrides[_require_auth] = lambda: _MOCK_USER
    yield
    app.dependency_overrides.pop(_require_auth, None)
    app.dependency_overrides.pop(get_session, None)


async def test_incidents_list_returns_200(_auth_override):
    session = _make_list_session([_mock_analysis()])
    app.dependency_overrides[get_session] = _session_override(session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/api/v1/incidents")

    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data
    assert "size" in data
    assert "pages" in data


async def test_incidents_list_empty_returns_zero_items(_auth_override):
    session = _make_list_session([], total=0)
    app.dependency_overrides[get_session] = _session_override(session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/api/v1/incidents")

    data = resp.json()
    assert data["total"] == 0
    assert data["items"] == []
    assert data["pages"] == 0


async def test_incidents_list_pagination_fields(_auth_override):
    """page/size fields from query params are reflected in response."""
    analyses = [_mock_analysis(trace_id=uuid.uuid4()) for _ in range(3)]
    session = _make_list_session(analyses, total=50)
    app.dependency_overrides[get_session] = _session_override(session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/api/v1/incidents?page=2&size=3")

    data = resp.json()
    assert data["page"] == 2
    assert data["size"] == 3
    assert data["total"] == 50
    assert data["pages"] == 17  # ceil(50/3)


async def test_incidents_list_item_fields(_auth_override):
    """Each item in the list has the required IncidentListItem fields."""
    session = _make_list_session([_mock_analysis(verdict="PHISHING")])
    app.dependency_overrides[get_session] = _session_override(session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/api/v1/incidents")

    item = resp.json()["items"][0]
    assert "id" in item
    assert "trace_id" in item
    assert "domain" in item
    assert "verdict" in item
    assert "s_risk" in item
    assert "reviewed" in item
    assert "created_at" in item
    assert item["verdict"] == "PHISHING"


async def test_incidents_list_verdict_filter_forwarded_to_query(_auth_override):
    """verdict= query param is accepted without error (SQL filtering is in the ORM layer)."""
    session = _make_list_session([_mock_analysis(verdict="PHISHING")])
    app.dependency_overrides[get_session] = _session_override(session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/api/v1/incidents?verdict=PHISHING")

    assert resp.status_code == 200


async def test_incidents_list_since_filter_accepted(_auth_override):
    """since= ISO datetime query param is accepted without error."""
    session = _make_list_session([])
    app.dependency_overrides[get_session] = _session_override(session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/api/v1/incidents?since=2026-01-01T00:00:00Z")

    assert resp.status_code == 200


# ── Detail endpoint ───────────────────────────────────────────────────────────

async def test_incidents_detail_returns_200_for_known_trace_id(_auth_override):
    session = _make_detail_session(_mock_analysis(), xai_row=_mock_xai_row())
    app.dependency_overrides[get_session] = _session_override(session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get(f"/api/v1/incidents/{_TRACE_ID}")

    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "PHISHING"
    assert "agent_results" in data
    assert "xai_report" in data


async def test_incidents_detail_returns_404_for_unknown_trace_id(_auth_override):
    session = _make_detail_session(None)
    # Only one execute call needed (the analysis lookup fails → raise 404)
    session.execute.side_effect = [_scalar_one_or_none(None)]
    app.dependency_overrides[get_session] = _session_override(session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get(f"/api/v1/incidents/{uuid.uuid4()}")

    assert resp.status_code == 404
    assert resp.json()["detail"] == "Analysis not found"


async def test_incidents_detail_includes_three_agent_results(_auth_override):
    session = _make_detail_session(_mock_analysis(), xai_row=_mock_xai_row())
    app.dependency_overrides[get_session] = _session_override(session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get(f"/api/v1/incidents/{_TRACE_ID}")

    agent_results = resp.json()["agent_results"]
    assert len(agent_results) == 3
    agent_names = {r["agent_name"] for r in agent_results}
    assert agent_names == {"idn_agent", "llm_agent", "fusion_agent"}


async def test_incidents_detail_xai_report_none_when_absent(_auth_override):
    """xai_report is null in response when the XAI row does not exist."""
    session = _make_detail_session(_mock_analysis(), xai_row=None)
    app.dependency_overrides[get_session] = _session_override(session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get(f"/api/v1/incidents/{_TRACE_ID}")

    assert resp.status_code == 200
    assert resp.json()["xai_report"] is None


async def test_incidents_detail_xai_report_has_shap_and_top_features(_auth_override):
    """When xai_report exists, it includes shap_values and top_features."""
    session = _make_detail_session(_mock_analysis(), xai_row=_mock_xai_row())
    app.dependency_overrides[get_session] = _session_override(session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get(f"/api/v1/incidents/{_TRACE_ID}")

    xai = resp.json()["xai_report"]
    assert "shap_values" in xai
    assert "top_features" in xai
    assert "lime_values" in xai


async def test_incidents_detail_all_score_fields_present(_auth_override):
    """Detail response includes s_risk, s_idn, s_llm, s_ti."""
    session = _make_detail_session(_mock_analysis(), xai_row=None)
    app.dependency_overrides[get_session] = _session_override(session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get(f"/api/v1/incidents/{_TRACE_ID}")

    data = resp.json()
    for field in ("s_risk", "s_idn", "s_llm", "s_ti"):
        assert field in data, f"Missing field: {field}"
