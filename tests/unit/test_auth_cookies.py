"""Cookie-based auth (dashboard) — login/refresh/logout set/read httpOnly cookies,
sin romper el flujo Bearer que sigue usando la extensión."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

from auth.jwt import create_access_token, create_refresh_token
from core.config import settings
from core.constants import ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE


@pytest.fixture
def client():
    with (
        patch("main.init_db", new_callable=AsyncMock),
        patch("main.close_db", new_callable=AsyncMock),
        patch("main.init_redis", new_callable=AsyncMock),
        patch("main.close_redis", new_callable=AsyncMock),
    ):
        from main import app

        with TestClient(app) as c:
            yield c


def test_login_sets_httponly_cookies(client):
    with patch("routers.auth_router._authenticate_user") as mock_auth:
        from schemas.auth import UserInfo

        mock_auth.return_value = UserInfo(username="admin", role="admin")
        resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "x"})
    assert resp.status_code == 200
    assert resp.cookies.get(ACCESS_TOKEN_COOKIE)
    assert resp.cookies.get(REFRESH_TOKEN_COOKIE)
    set_cookie = resp.headers.get("set-cookie", "")
    assert "HttpOnly" in set_cookie
    # body sigue trayendo el token — la extensión lo necesita
    assert resp.json()["access_token"]


def test_me_authenticates_via_cookie_only(client):
    token = create_access_token({"sub": "admin", "role": "admin"})
    client.cookies.set(ACCESS_TOKEN_COOKIE, token)
    resp = client.get("/api/v1/auth/me")
    assert resp.status_code == 200
    assert resp.json()["username"] == "admin"


def test_refresh_via_cookie_without_body(client):
    refresh = create_refresh_token({"sub": "admin", "role": "admin"})
    client.cookies.set(REFRESH_TOKEN_COOKIE, refresh)
    resp = client.post("/api/v1/auth/refresh")
    assert resp.status_code == 200
    assert resp.json()["access_token"]


def test_refresh_via_body_still_works_for_extension(client):
    """La extensión no tiene cookies — sigue mandando el refresh token en el body."""
    refresh = create_refresh_token({"sub": "admin", "role": "admin"})
    resp = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert resp.status_code == 200
    assert resp.json()["access_token"]


def test_refresh_without_cookie_or_body_returns_401(client):
    resp = client.post("/api/v1/auth/refresh")
    assert resp.status_code == 401


def test_logout_clears_cookies(client):
    resp = client.post("/api/v1/auth/logout")
    assert resp.status_code == 204
    set_cookie = resp.headers.get("set-cookie", "")
    assert f'{ACCESS_TOKEN_COOKIE}=""' in set_cookie or "Max-Age=0" in set_cookie


def test_dev_cookies_skip_secure_so_http_localhost_works(client):
    """APP_ENV=development (default local) → sin Secure, SameSite=Lax."""
    assert settings.APP_ENV == "development"
    with patch("routers.auth_router._authenticate_user") as mock_auth:
        from schemas.auth import UserInfo

        mock_auth.return_value = UserInfo(username="admin", role="admin")
        resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "x"})
    set_cookie = resp.headers.get("set-cookie", "").lower()
    assert "secure" not in set_cookie
    assert "samesite=lax" in set_cookie


def test_prod_cookies_are_secure_and_shared_across_the_dpdns_domain(client):
    """APP_ENV=production + AUTH_COOKIE_DOMAIN → Secure, SameSite=None, Domain
    compartido entre Coolify (back-tesi.) y Render (render.) para el failover."""
    with (
        patch.object(settings, "APP_ENV", "production"),
        patch.object(settings, "AUTH_COOKIE_DOMAIN", "mangel.dpdns.org"),
        patch("routers.auth_router._authenticate_user") as mock_auth,
    ):
        from schemas.auth import UserInfo

        mock_auth.return_value = UserInfo(username="admin", role="admin")
        resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "x"})
    set_cookie = resp.headers.get("set-cookie", "")
    assert "Secure" in set_cookie
    assert "samesite=none" in set_cookie.lower()
    assert "domain=mangel.dpdns.org" in set_cookie.lower()
