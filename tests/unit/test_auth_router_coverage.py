"""Coverage tests for auth_router.py — GET /auth/me and _authenticate_user helper."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch
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


def _admin_headers() -> dict:
    token = create_access_token({"sub": "admin", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}


# ─── GET /auth/me ─────────────────────────────────────────────────────────────

class TestGetCurrentUserInfo:
    """Tests for GET /api/v1/auth/me (line 63 in auth_router.py)."""

    def test_get_me_returns_200_with_valid_token(self, client):
        resp = client.get("/api/v1/auth/me", headers=_admin_headers())
        assert resp.status_code == 200

    def test_get_me_returns_username_and_role(self, client):
        resp = client.get("/api/v1/auth/me", headers=_admin_headers())
        data = resp.json()
        assert data["username"] == "admin"
        assert data["role"] == "admin"

    def test_get_me_without_token_returns_401(self, client):
        resp = client.get("/api/v1/auth/me")
        assert resp.status_code in {401, 403}

    def test_get_me_with_viewer_role(self, client):
        token = create_access_token({"sub": "viewer1", "role": "viewer"})
        resp = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["role"] == "viewer"


# ─── _authenticate_user helper ────────────────────────────────────────────────

class TestAuthenticateUserHelper:
    """Direct unit tests for _authenticate_user (lines 79-95 in auth_router.py)."""

    @pytest.mark.asyncio
    async def test_wrong_username_returns_none(self):
        from routers.auth_router import _authenticate_user
        from core.config import settings
        with patch.object(settings, "ADMIN_USERNAME", "admin"):
            result = await _authenticate_user("wrong_user", "any_password")
        assert result is None

    @pytest.mark.asyncio
    async def test_dev_mode_no_hash_returns_user(self):
        """When ADMIN_PASSWORD_HASH is empty and ENVIRONMENT != production, accept any password."""
        from routers.auth_router import _authenticate_user
        from core.config import settings
        with patch.object(settings, "ADMIN_USERNAME", "admin"), \
             patch.object(settings, "ADMIN_PASSWORD_HASH", ""), \
             patch.dict("os.environ", {"ENVIRONMENT": "development"}):
            result = await _authenticate_user("admin", "any_password")
        assert result is not None
        assert result.username == "admin"
        assert result.role == "admin"

    @pytest.mark.asyncio
    async def test_production_mode_no_hash_returns_none(self):
        """In production, an unconfigured password hash means no login."""
        from routers.auth_router import _authenticate_user
        from core.config import settings
        with patch.object(settings, "ADMIN_USERNAME", "admin"), \
             patch.object(settings, "ADMIN_PASSWORD_HASH", ""), \
             patch.dict("os.environ", {"ENVIRONMENT": "production"}):
            result = await _authenticate_user("admin", "any_password")
        assert result is None

    @pytest.mark.asyncio
    async def test_wrong_password_with_hash_returns_none(self):
        """Incorrect password with configured hash → None."""
        from routers.auth_router import _authenticate_user
        from core.config import settings
        with patch.object(settings, "ADMIN_USERNAME", "admin"), \
             patch.object(settings, "ADMIN_PASSWORD_HASH", "$2b$12$fakehash"), \
             patch("core.security.verify_password", return_value=False):
            result = await _authenticate_user("admin", "wrong_password")
        assert result is None

    @pytest.mark.asyncio
    async def test_correct_password_with_hash_returns_user(self):
        """Correct password with configured hash → UserInfo."""
        from routers.auth_router import _authenticate_user
        from core.config import settings
        with patch.object(settings, "ADMIN_USERNAME", "admin"), \
             patch.object(settings, "ADMIN_PASSWORD_HASH", "$2b$12$fakehash"), \
             patch("core.security.verify_password", return_value=True):
            result = await _authenticate_user("admin", "correct_password")
        assert result is not None
        assert result.username == "admin"
        assert result.role == "admin"
