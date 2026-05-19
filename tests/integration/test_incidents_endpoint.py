"""Integration tests for GET /api/v1/incidents endpoints."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from auth.jwt import create_access_token
from main import app


def _auth_headers() -> dict:
    token = create_access_token({"sub": "test-user", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}


def _make_row(incident_id: str = None, verdict: str = "PHISHING") -> dict:
    return {
        "id": incident_id or str(uuid.uuid4()),
        "email_hash": "abc123",
        "url": "https://рaypal.com/login",
        "domain": "рaypal.com",
        "verdict": verdict,
        "s_risk": 0.85,
        "s_idn": 0.90,
        "s_llm": 0.80,
        "s_ti": 0.89,
        "llm_reason": "Suspicious domain",
        "shap_contributions": json.dumps({"s_idn_local": 0.27}),
        "created_at": datetime.now(timezone.utc),
    }


@pytest.fixture
def client():
    with patch("main.init_db", new_callable=AsyncMock), \
         patch("main.close_db", new_callable=AsyncMock), \
         patch("main.init_redis", new_callable=AsyncMock), \
         patch("main.close_redis", new_callable=AsyncMock):
        with TestClient(app) as c:
            yield c


class TestListIncidents:
    def test_requires_auth(self, client):
        resp = client.get("/api/v1/incidents")
        assert resp.status_code in {401, 403}

    def test_returns_200_with_auth(self, client):
        count_row = MagicMock()
        count_row.__getitem__ = MagicMock(return_value=0)

        with patch("routers.incidents_router.fetchrow", new_callable=AsyncMock) as mock_fetchrow, \
             patch("routers.incidents_router.fetch", new_callable=AsyncMock) as mock_fetch:
            mock_fetchrow.return_value = count_row
            mock_fetch.return_value = []
            resp = client.get("/api/v1/incidents", headers=_auth_headers())
        assert resp.status_code == 200

    def test_returns_list_response_structure(self, client):
        count_row = MagicMock()
        count_row.__getitem__ = MagicMock(return_value=0)

        with patch("routers.incidents_router.fetchrow", new_callable=AsyncMock) as mock_fetchrow, \
             patch("routers.incidents_router.fetch", new_callable=AsyncMock) as mock_fetch:
            mock_fetchrow.return_value = count_row
            mock_fetch.return_value = []
            resp = client.get("/api/v1/incidents", headers=_auth_headers())
        data = resp.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "page_size" in data

    def test_empty_list_returned_when_no_incidents(self, client):
        count_row = MagicMock()
        count_row.__getitem__ = MagicMock(return_value=0)

        with patch("routers.incidents_router.fetchrow", new_callable=AsyncMock) as mock_fetchrow, \
             patch("routers.incidents_router.fetch", new_callable=AsyncMock) as mock_fetch:
            mock_fetchrow.return_value = count_row
            mock_fetch.return_value = []
            resp = client.get("/api/v1/incidents", headers=_auth_headers())
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0

    def test_verdict_filter_accepted(self, client):
        count_row = MagicMock()
        count_row.__getitem__ = MagicMock(return_value=0)

        with patch("routers.incidents_router.fetchrow", new_callable=AsyncMock) as mock_fetchrow, \
             patch("routers.incidents_router.fetch", new_callable=AsyncMock) as mock_fetch:
            mock_fetchrow.return_value = count_row
            mock_fetch.return_value = []
            resp = client.get(
                "/api/v1/incidents?verdict=PHISHING",
                headers=_auth_headers(),
            )
        assert resp.status_code == 200

    def test_invalid_verdict_filter_returns_422(self, client):
        resp = client.get(
            "/api/v1/incidents?verdict=INVALID",
            headers=_auth_headers(),
        )
        assert resp.status_code == 422

    def test_database_error_returns_500(self, client):
        from core.exceptions import DatabaseError
        with patch("routers.incidents_router.fetchrow",
                   new_callable=AsyncMock,
                   side_effect=DatabaseError("DB failed")):
            resp = client.get("/api/v1/incidents", headers=_auth_headers())
        assert resp.status_code == 500


class TestGetIncident:
    def test_requires_auth(self, client):
        resp = client.get(f"/api/v1/incidents/{uuid.uuid4()}")
        assert resp.status_code in {401, 403}

    def test_returns_404_when_not_found(self, client):
        with patch("routers.incidents_router.fetchrow",
                   new_callable=AsyncMock, return_value=None):
            incident_id = str(uuid.uuid4())
            resp = client.get(
                f"/api/v1/incidents/{incident_id}",
                headers=_auth_headers(),
            )
        assert resp.status_code == 404

    def test_returns_incident_when_found(self, client):
        row = _make_row()
        mock_row = MagicMock()
        for k, v in row.items():
            mock_row.__getitem__ = MagicMock(side_effect=lambda key, _r=row: _r[key])
        mock_row.get = MagicMock(side_effect=lambda key, default=None, _r=row: _r.get(key, default))

        # Use a dict-like mock
        class DictRow(dict):
            pass

        dict_row = DictRow(row)

        with patch("routers.incidents_router.fetchrow",
                   new_callable=AsyncMock, return_value=dict_row):
            resp = client.get(
                f"/api/v1/incidents/{row['id']}",
                headers=_auth_headers(),
            )
        assert resp.status_code == 200

    def test_database_error_returns_500(self, client):
        from core.exceptions import DatabaseError
        with patch("routers.incidents_router.fetchrow",
                   new_callable=AsyncMock,
                   side_effect=DatabaseError("DB failed")):
            resp = client.get(
                f"/api/v1/incidents/{uuid.uuid4()}",
                headers=_auth_headers(),
            )
        assert resp.status_code == 500


class TestRowToRecord:
    def test_parses_json_shap_contributions(self):
        from routers.incidents_router import _row_to_record
        row = {
            "id": str(uuid.uuid4()),
            "email_hash": "hash",
            "url": "https://paypal.com",
            "domain": "paypal.com",
            "verdict": "PHISHING",
            "s_risk": 0.85,
            "s_idn": 0.90,
            "s_llm": 0.80,
            "s_ti": 0.89,
            "llm_reason": "Test",
            "shap_contributions": '{"s_idn_local": 0.27}',
            "created_at": datetime.now(timezone.utc),
        }
        record = _row_to_record(row)
        assert record.shap_contributions["s_idn_local"] == 0.27

    def test_handles_dict_shap_contributions(self):
        from routers.incidents_router import _row_to_record
        row = {
            "id": str(uuid.uuid4()),
            "email_hash": "hash",
            "url": "https://paypal.com",
            "domain": "paypal.com",
            "verdict": "PHISHING",
            "s_risk": 0.85,
            "s_idn": 0.90,
            "s_llm": 0.80,
            "s_ti": 0.89,
            "llm_reason": "Test",
            "shap_contributions": {"s_idn_local": 0.27},
            "created_at": datetime.now(timezone.utc),
        }
        record = _row_to_record(row)
        assert record.shap_contributions["s_idn_local"] == 0.27

    def test_handles_none_shap_contributions(self):
        from routers.incidents_router import _row_to_record
        row = {
            "id": str(uuid.uuid4()),
            "email_hash": "",
            "url": "https://paypal.com",
            "domain": "paypal.com",
            "verdict": "PHISHING",
            "s_risk": 0.85,
            "s_idn": 0.90,
            "s_llm": 0.80,
            "s_ti": 0.89,
            "llm_reason": "Test",
            "shap_contributions": None,
            "created_at": datetime.now(timezone.utc),
        }
        record = _row_to_record(row)
        assert record.shap_contributions == {}

    def test_handles_null_email_hash(self):
        from routers.incidents_router import _row_to_record
        row = {
            "id": str(uuid.uuid4()),
            "email_hash": None,
            "url": "https://paypal.com",
            "domain": "paypal.com",
            "verdict": "LEGITIMATE",
            "s_risk": 0.05,
            "s_idn": 0.0,
            "s_llm": 0.1,
            "s_ti": 0.0,
            "llm_reason": "Clean",
            "shap_contributions": "{}",
            "created_at": datetime.now(timezone.utc),
        }
        record = _row_to_record(row)
        assert record.email_hash == ""
