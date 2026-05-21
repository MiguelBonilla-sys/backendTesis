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
    """Direct unit tests for _authenticate_user (DB-based implementation)."""

    @pytest.mark.asyncio
    async def test_wrong_username_returns_none(self):
        from routers.auth_router import _authenticate_user
        with patch("models.database.fetchrow", new_callable=AsyncMock, return_value=None):
            result = await _authenticate_user("wrong_user", "any_password")
        assert result is None

    @pytest.mark.asyncio
    async def test_inactive_user_returns_none(self):
        row = {"email": "admin@usbbog.edu.co", "password_hash": "$2b$12$h", "role": "admin", "is_active": False}
        with patch("models.database.fetchrow", new_callable=AsyncMock, return_value=row):
            from routers.auth_router import _authenticate_user
            result = await _authenticate_user("admin@usbbog.edu.co", "any_password")
        assert result is None

    @pytest.mark.asyncio
    async def test_wrong_password_with_hash_returns_none(self):
        """Incorrect password → None."""
        row = {"email": "admin@usbbog.edu.co", "password_hash": "$2b$12$fakehash", "role": "admin", "is_active": True}
        with patch("models.database.fetchrow", new_callable=AsyncMock, return_value=row), \
             patch("core.security.verify_password", return_value=False):
            from routers.auth_router import _authenticate_user
            result = await _authenticate_user("admin@usbbog.edu.co", "wrong_password")
        assert result is None

    @pytest.mark.asyncio
    async def test_correct_password_with_hash_returns_user(self):
        """Correct password → UserInfo with matching username and role."""
        row = {"email": "admin@usbbog.edu.co", "password_hash": "$2b$12$fakehash", "role": "admin", "is_active": True}
        with patch("models.database.fetchrow", new_callable=AsyncMock, return_value=row), \
             patch("core.security.verify_password", return_value=True):
            from routers.auth_router import _authenticate_user
            result = await _authenticate_user("admin@usbbog.edu.co", "correct_password")
        assert result is not None
        assert result.username == "admin@usbbog.edu.co"
        assert result.role == "admin"

    @pytest.mark.asyncio
    async def test_student_role_returned_correctly(self):
        """Role from DB row is preserved in UserInfo."""
        row = {"email": "student@usbbog.edu.co", "password_hash": "$2b$12$h", "role": "student", "is_active": True}
        with patch("models.database.fetchrow", new_callable=AsyncMock, return_value=row), \
             patch("core.security.verify_password", return_value=True):
            from routers.auth_router import _authenticate_user
            result = await _authenticate_user("student@usbbog.edu.co", "pass")
        assert result is not None
        assert result.role == "student"
