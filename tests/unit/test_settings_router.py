"""Tests for GET /api/v1/settings."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from auth.jwt import create_access_token
from main import app


@pytest.fixture
def client():
    with patch("main.init_db", new_callable=AsyncMock), \
         patch("main.close_db", new_callable=AsyncMock), \
         patch("main.init_redis", new_callable=AsyncMock), \
         patch("main.close_redis", new_callable=AsyncMock):
        with TestClient(app) as c:
            yield c


def _auth_headers(role: str = "admin") -> dict:
    token = create_access_token({"sub": "testuser", "role": role})
    return {"Authorization": f"Bearer {token}"}


class TestGetSettings:
    def test_returns_200_with_valid_token(self, client):
        resp = client.get("/api/v1/settings", headers=_auth_headers())
        assert resp.status_code == 200

    def test_returns_401_without_token(self, client):
        resp = client.get("/api/v1/settings")
        assert resp.status_code in {401, 403}

    def test_viewer_can_read_settings(self, client):
        resp = client.get("/api/v1/settings", headers=_auth_headers(role="viewer"))
        assert resp.status_code == 200

    def test_response_contains_all_keys(self, client):
        data = client.get("/api/v1/settings", headers=_auth_headers()).json()
        expected = {"alpha", "beta", "gamma", "theta", "lambda", "ti_vt_weight", "ti_urlscan_weight", "ti_gsb_weight"}
        assert expected == set(data.keys())

    def test_default_alpha(self, client):
        data = client.get("/api/v1/settings", headers=_auth_headers()).json()
        assert data["alpha"] == pytest.approx(0.60)

    def test_default_beta(self, client):
        data = client.get("/api/v1/settings", headers=_auth_headers()).json()
        assert data["beta"] == pytest.approx(0.40)

    def test_default_gamma(self, client):
        data = client.get("/api/v1/settings", headers=_auth_headers()).json()
        assert data["gamma"] == pytest.approx(0.50)

    def test_default_theta(self, client):
        data = client.get("/api/v1/settings", headers=_auth_headers()).json()
        assert data["theta"] == pytest.approx(0.70)

    def test_default_lambda(self, client):
        data = client.get("/api/v1/settings", headers=_auth_headers()).json()
        assert data["lambda"] == pytest.approx(0.30)

    def test_ti_weights_sum_to_one(self, client):
        data = client.get("/api/v1/settings", headers=_auth_headers()).json()
        total = data["ti_vt_weight"] + data["ti_urlscan_weight"] + data["ti_gsb_weight"]
        assert total == pytest.approx(1.0)
