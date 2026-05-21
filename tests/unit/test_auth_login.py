"""Tests for routers/auth_router.py and auth/dependencies.py"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
from fastapi import HTTPException


class TestLoginEndpoint:
    @pytest.fixture
    def client(self):
        with patch("main.init_db", new_callable=AsyncMock), \
             patch("main.close_db", new_callable=AsyncMock), \
             patch("main.init_redis", new_callable=AsyncMock), \
             patch("main.close_redis", new_callable=AsyncMock):
            from main import app
            with TestClient(app) as c:
                yield c

    def test_login_missing_body_returns_422(self, client):
        resp = client.post("/api/v1/auth/login", json={})
        assert resp.status_code == 422

    def test_login_short_password_returns_422(self, client):
        resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": ""})
        assert resp.status_code == 422

    def test_login_dev_mode_success(self, client):
        """En dev mode (sin ADMIN_PASSWORD_HASH), cualquier password funciona."""
        with patch("routers.auth_router._authenticate_user") as mock_auth:
            from schemas.auth import UserInfo
            mock_auth.return_value = UserInfo(username="admin", role="admin")
            resp = client.post(
                "/api/v1/auth/login",
                json={"username": "admin", "password": "anypassword"}
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 900  # 15 min * 60

    def test_login_invalid_credentials_returns_401(self, client):
        with patch("routers.auth_router._authenticate_user", return_value=None):
            resp = client.post(
                "/api/v1/auth/login",
                json={"username": "wrong", "password": "wrongpassword"}
            )
        assert resp.status_code == 401

    def test_jwt_expire_is_15_minutes(self):
        """Verificar que JWT_EXPIRE_MINUTES = 15 (requisito R03)."""
        from core.config import settings
        assert settings.JWT_EXPIRE_MINUTES == 15, (
            f"JWT debe expirar en 15 min (R03 Crítico), actualmente: {settings.JWT_EXPIRE_MINUTES}"
        )


class TestRequireAdmin:
    @pytest.mark.asyncio
    async def test_admin_role_passes(self):
        """require_admin called directly with a dict (no FastAPI DI)."""
        from auth import dependencies

        # Bypass the Depends(require_auth) default by calling the inner logic directly
        payload = {"sub": "admin", "role": "admin"}
        # Patch require_auth so require_admin dependency receives our payload
        with patch("auth.dependencies.require_auth", return_value=payload):
            result = await dependencies.require_admin(current_user=payload)
        assert result == payload

    @pytest.mark.asyncio
    async def test_viewer_role_rejected(self):
        from auth import dependencies

        payload = {"sub": "user", "role": "viewer"}
        with pytest.raises(HTTPException) as exc_info:
            await dependencies.require_admin(current_user=payload)
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_student_role_rejected(self):
        from auth import dependencies

        payload = {"sub": "student", "role": "student"}
        with pytest.raises(HTTPException) as exc_info:
            await dependencies.require_admin(current_user=payload)
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_missing_role_rejected(self):
        from auth import dependencies

        payload = {"sub": "user"}  # sin 'role'
        with pytest.raises(HTTPException) as exc_info:
            await dependencies.require_admin(current_user=payload)
        assert exc_info.value.status_code == 403


class TestRequireRole:
    @pytest.mark.asyncio
    async def test_require_role_factory_allows_matching_role(self):
        from auth.dependencies import require_role

        checker = require_role("admin", "viewer")
        result = await checker(current_user={"sub": "user", "role": "viewer"})
        assert result["role"] == "viewer"

    @pytest.mark.asyncio
    async def test_require_role_factory_blocks_non_matching(self):
        from auth.dependencies import require_role

        checker = require_role("admin")
        with pytest.raises(HTTPException) as exc_info:
            await checker(current_user={"sub": "user", "role": "student"})
        assert exc_info.value.status_code == 403
