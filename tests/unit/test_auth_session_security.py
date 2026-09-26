"""Session lifecycle and browser-boundary regressions (H01, H02, H16)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import jwt
import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient
from starlette.requests import Request

from auth.dependencies import require_admin, require_auth
from auth.jwt import create_access_token, decode_token
from auth.sessions import issue_session, rotate_session
from core.config import settings
from core.constants import ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE
from core.exceptions import AuthenticationError
from core.rate_limiter import get_client_ip
from routers.auth_router import router

GOOD_ORIGIN = "https://dashdect.mangel.dpdns.org"
BAD_ORIGIN = "https://untrusted.vercel.app"


@pytest.fixture
def client(auth_store):
    app = FastAPI()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(router, prefix="/api/v1")

    @app.post("/write")
    async def write(current=Depends(require_auth)):
        return current

    @app.get("/admin")
    async def admin(current=Depends(require_admin)):
        return current

    with TestClient(app) as client:
        yield client


def pair(auth_store):
    return auth_store.issue({"sub": "admin", "role": "admin"})


def test_refresh_cannot_authenticate_as_access(client, auth_store):
    _, refresh = pair(auth_store)
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {refresh}"})
    assert response.status_code == 401


def test_access_cannot_refresh(client, auth_store):
    access, _ = pair(auth_store)
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": access}).status_code == 401


def test_signed_token_without_persisted_session_is_rejected(client):
    token = create_access_token({"sub": "admin", "role": "admin"})
    assert (
        client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code
        == 401
    )


@pytest.mark.parametrize("missing", ["exp", "iat", "sub", "role", "type", "sid", "jti"])
def test_missing_mandatory_claim_rejected(missing):
    payload = decode_token(create_access_token({"sub": "admin", "role": "admin"}))
    payload.pop(missing)
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    with pytest.raises(AuthenticationError):
        decode_token(token)


@pytest.mark.parametrize(
    "changes", [{"sub": ""}, {"type": "unknown"}, {"role": "superuser"}, {"sid": ""}, {"jti": ""}]
)
def test_invalid_mandatory_claim_rejected(changes):
    payload = decode_token(create_access_token({"sub": "admin", "role": "admin"}))
    payload.update(changes)
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    with pytest.raises(AuthenticationError):
        decode_token(token)


def test_refresh_rotates_and_rejects_previous_token(client, auth_store):
    _, refresh = pair(auth_store)
    response = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert response.status_code == 200
    replacement = response.json()["refresh_token"]
    assert replacement != refresh
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": refresh}).status_code == 401
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": replacement}).status_code == 200
    )


@pytest.mark.asyncio
async def test_concurrent_refresh_allows_only_one_rotation(auth_store):
    _, refresh = pair(auth_store)
    payload = decode_token(refresh)
    responses = await asyncio.gather(
        rotate_session(payload), rotate_session(payload), return_exceptions=True
    )
    assert sum(isinstance(result, tuple) for result in responses) == 1
    failures = [result for result in responses if isinstance(result, HTTPException)]
    assert len(failures) == 1 and failures[0].status_code == 401


@pytest.mark.parametrize("change", ["inactive", "deleted", "password"])
def test_account_changes_invalidate_access_and_refresh(client, auth_store, change):
    access, refresh = pair(auth_store)
    if change == "inactive":
        auth_store.accounts["admin"]["is_active"] = False
    elif change == "deleted":
        del auth_store.accounts["admin"]
    else:
        auth_store.accounts["admin"]["password_hash"] = "new-hash"
    assert (
        client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access}"}).status_code
        == 401
    )
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": refresh}).status_code == 401


def test_role_demotion_immediately_applies_to_access_and_refresh(client, auth_store):
    access, refresh = pair(auth_store)
    auth_store.accounts["admin"]["role"] = "student"
    header = {"Authorization": f"Bearer {access}"}
    assert client.get("/admin", headers=header).status_code == 403
    assert client.get("/api/v1/auth/me", headers=header).json()["role"] == "student"
    response = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert response.status_code == 200
    assert decode_token(response.json()["access_token"])["role"] == "student"


def test_cookie_logout_revokes_access_and_refresh(client, auth_store):
    access, refresh = pair(auth_store)
    client.cookies.set(ACCESS_TOKEN_COOKIE, access)
    client.cookies.set(REFRESH_TOKEN_COOKIE, refresh)
    assert client.post("/api/v1/auth/logout", headers={"Origin": GOOD_ORIGIN}).status_code == 204
    assert (
        client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access}"}).status_code
        == 401
    )
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": refresh}).status_code == 401


def test_bearer_logout_revokes_extension_session(client, auth_store):
    access, refresh = pair(auth_store)
    assert (
        client.post(
            "/api/v1/auth/logout", headers={"Authorization": f"Bearer {access}"}
        ).status_code
        == 204
    )
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": refresh}).status_code == 401


@pytest.mark.parametrize("origin", [BAD_ORIGIN, "https://untrusted.onrender.com", "null"])
def test_third_party_cookie_refresh_denied_and_unreadable(client, auth_store, origin):
    _, refresh = pair(auth_store)
    client.cookies.set(REFRESH_TOKEN_COOKIE, refresh)
    response = client.post("/api/v1/auth/refresh", headers={"Origin": origin})
    assert response.status_code == 403
    assert "access-control-allow-origin" not in response.headers
    assert "access_token" not in response.json()


def test_product_cookie_refresh_allowed_and_readable(client, auth_store):
    _, refresh = pair(auth_store)
    client.cookies.set(REFRESH_TOKEN_COOKIE, refresh)
    response = client.post("/api/v1/auth/refresh", headers={"Origin": GOOD_ORIGIN})
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == GOOD_ORIGIN
    assert response.headers["access-control-allow-credentials"] == "true"


@pytest.mark.parametrize("endpoint", ["/api/v1/auth/refresh", "/api/v1/auth/logout", "/write"])
def test_cookie_write_requires_origin(client, auth_store, endpoint):
    access, refresh = pair(auth_store)
    client.cookies.set(ACCESS_TOKEN_COOKIE, access)
    client.cookies.set(REFRESH_TOKEN_COOKIE, refresh)
    assert client.post(endpoint).status_code == 403


def test_cookie_write_allowed_for_product_and_bearer_supported(client, auth_store):
    access, _ = pair(auth_store)
    client.cookies.set(ACCESS_TOKEN_COOKIE, access)
    response = client.post("/write", headers={"Origin": GOOD_ORIGIN})
    assert response.status_code == 200
    assert response.json()["id"] == auth_store.accounts["admin"]["id"]
    client.cookies.clear()
    assert client.post("/write", headers={"Authorization": f"Bearer {access}"}).status_code == 200


@pytest.mark.parametrize(
    "endpoint,body",
    [
        ("login", {"username": "admin", "password": "x"}),
        ("register", {"email": "student@usbbog.edu.co", "password": "secretpass"}),
        ("logout", None),
    ],
)
def test_cross_origin_auth_writes_denied(client, endpoint, body):
    assert (
        client.post(
            f"/api/v1/auth/{endpoint}", json=body, headers={"Origin": BAD_ORIGIN}
        ).status_code
        == 403
    )


def test_known_extension_origin_allowed(client, auth_store):
    _, refresh = pair(auth_store)
    response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh},
        headers={"Origin": "chrome-extension://hpcgpdffecpcljmofigneicgkdfhplhf"},
    )
    assert response.status_code == 200


def test_login_identity_is_normalized_and_limited(client, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_LOGIN_IDENTITY", 2)
    with patch(
        "routers.auth_router._authenticate_user", new_callable=AsyncMock, return_value=None
    ) as auth:
        for username in (" ADMIN ", "admin"):
            assert (
                client.post(
                    "/api/v1/auth/login", json={"username": username, "password": "x"}
                ).status_code
                == 401
            )
        response = client.post("/api/v1/auth/login", json={"username": "Admin", "password": "x"})
    assert response.status_code == 429
    assert "Retry-After" in response.headers
    assert auth.await_count == 2
    assert all(call.args[0] == "admin" for call in auth.await_args_list)


def test_login_ip_cannot_be_rotated_with_external_forwarded_headers(client, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_LOGIN_IP", 2)
    with patch("routers.auth_router._authenticate_user", new_callable=AsyncMock, return_value=None):
        responses = [
            client.post(
                "/api/v1/auth/login",
                json={"username": f"user{n}", "password": "x"},
                headers={"X-Forwarded-For": f"192.0.2.{n}"},
            ).status_code
            for n in range(3)
        ]
    assert responses == [401, 401, 429]


def test_auth_fails_closed_without_session_store(client, auth_store):
    access, refresh = pair(auth_store)
    with patch("auth.sessions.get_redis", side_effect=RuntimeError("unavailable")):
        assert (
            client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access}"}).status_code
            == 503
        )
        assert (
            client.post("/api/v1/auth/refresh", json={"refresh_token": refresh}).status_code == 503
        )
    with patch("core.rate_limiter.get_redis", side_effect=RuntimeError("unavailable")):
        assert (
            client.post(
                "/api/v1/auth/login", json={"username": "admin", "password": "x"}
            ).status_code
            == 503
        )


def test_auth_fails_closed_without_database(client, auth_store):
    access, _ = pair(auth_store)
    with patch("auth.sessions.fetchrow", side_effect=RuntimeError("unavailable")):
        assert (
            client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access}"}).status_code
            == 503
        )


@pytest.mark.asyncio
async def test_failed_session_write_never_issues_tokens(auth_store):
    with patch.object(auth_store, "set", new_callable=AsyncMock, return_value=False):
        with pytest.raises(HTTPException) as failure:
            await issue_session("admin")
    assert failure.value.status_code == 503


@pytest.mark.parametrize(
    "forwarded,expected",
    [
        ("192.0.2.4, 10.0.0.3", "192.0.2.4"),
        ("192.0.2.99, 198.51.100.7", "198.51.100.7"),
        ("invalid", "10.0.0.2"),
    ],
)
def test_only_explicit_trusted_proxy_chain_is_used(monkeypatch, forwarded, expected):
    monkeypatch.setattr(settings, "TRUSTED_PROXY_CIDRS", ["10.0.0.0/24"])
    request = Request(
        {
            "type": "http",
            "client": ("10.0.0.2", 1234),
            "headers": [(b"x-forwarded-for", forwarded.encode())],
        }
    )
    assert get_client_ip(request) == expected


@pytest.mark.asyncio
async def test_password_verification_runs_in_worker_thread():
    import threading

    from core.security import verify_password_async

    event_loop_thread = threading.get_ident()
    worker_threads = []

    def verify(plain, hashed):
        worker_threads.append(threading.get_ident())
        return True

    with patch("core.security.verify_password", side_effect=verify):
        assert await verify_password_async("x", "hash") is True
    assert worker_threads and worker_threads[0] != event_loop_thread


@pytest.mark.parametrize(
    "origin",
    [
        "*",
        "chrome-extension://*",
        "https://*.vercel.app",
        "https://user:pass@example.com",
        "https://example.com/path",
    ],
)
def test_cors_configuration_rejects_non_exact_origins(origin):
    from pydantic import ValidationError

    from core.config import Settings

    with pytest.raises(ValidationError, match="exact origins"):
        Settings(_env_file=None, CORS_ORIGINS=[origin])


def test_explicit_invalid_logout_token_cannot_revoke_ambient_cookie(client, auth_store):
    access, _ = pair(auth_store)
    client.cookies.set(ACCESS_TOKEN_COOKIE, access)
    assert client.post("/api/v1/auth/logout", json={"refresh_token": "invalid"}).status_code == 204
    assert (
        client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access}"}).status_code
        == 200
    )
