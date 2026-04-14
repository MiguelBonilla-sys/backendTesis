"""Tests for routers/auth_router.py — login and register endpoints."""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from main import app
from models.database import get_session
from models.orm_models import User

# ── Helpers ───────────────────────────────────────────────────────────────────

_STUDENT_EMAIL = "student@academia.usbbog.edu.co"
_ADMIN_EMAIL = "admin@usbbog.edu.co"
_PASSWORD = "securePass1"
_HASHED = "$2b$12$hashedpasswordplaceholder123456"


def _make_user(
    *,
    email: str = _STUDENT_EMAIL,
    role: str = "student",
    is_active: bool = True,
) -> MagicMock:
    user = MagicMock(spec=User)
    user.id = uuid.uuid4()
    user.email = email
    user.password_hash = _HASHED
    user.role = role
    user.is_active = is_active
    return user


def _session_override(session: AsyncMock):
    """Returns an async generator function for use as dependency override."""
    async def _gen():
        yield session

    return _gen


def _make_session() -> AsyncMock:
    session = AsyncMock()
    return session


# ── Login tests ───────────────────────────────────────────────────────────────

async def test_login_success():
    """Valid credentials for an active user return 200 + TokenResponse fields."""
    user = _make_user(role="student")
    session = _make_session()
    app.dependency_overrides[get_session] = _session_override(session)

    with (
        patch("routers.auth_router.get_user_by_email", new=AsyncMock(return_value=user)),
        patch("routers.auth_router.verify_password", return_value=True),
    ):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
            resp = await client.post(
                "/api/v1/auth/login",
                json={"email": _STUDENT_EMAIL, "password": _PASSWORD},
            )

    app.dependency_overrides.pop(get_session, None)
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert "expires_in" in data
    assert data["role"] == "student"


async def test_login_invalid_credentials_wrong_password():
    """Wrong password returns 401 — never reveals which field is wrong."""
    user = _make_user()
    session = _make_session()
    app.dependency_overrides[get_session] = _session_override(session)

    with (
        patch("routers.auth_router.get_user_by_email", new=AsyncMock(return_value=user)),
        patch("routers.auth_router.verify_password", return_value=False),
    ):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
            resp = await client.post(
                "/api/v1/auth/login",
                json={"email": _STUDENT_EMAIL, "password": "wrongpassword"},
            )

    app.dependency_overrides.pop(get_session, None)
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid credentials"


async def test_login_nonexistent_user():
    """Unknown email returns 401 — same message as wrong password (no enumeration)."""
    session = _make_session()
    app.dependency_overrides[get_session] = _session_override(session)

    with patch("routers.auth_router.get_user_by_email", new=AsyncMock(return_value=None)):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
            resp = await client.post(
                "/api/v1/auth/login",
                json={"email": "ghost@usbbog.edu.co", "password": _PASSWORD},
            )

    app.dependency_overrides.pop(get_session, None)
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid credentials"


async def test_login_disabled_account_returns_403():
    """Inactive user returns 403 after successful password verification."""
    user = _make_user(is_active=False)
    session = _make_session()
    app.dependency_overrides[get_session] = _session_override(session)

    with (
        patch("routers.auth_router.get_user_by_email", new=AsyncMock(return_value=user)),
        patch("routers.auth_router.verify_password", return_value=True),
    ):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
            resp = await client.post(
                "/api/v1/auth/login",
                json={"email": _STUDENT_EMAIL, "password": _PASSWORD},
            )

    app.dependency_overrides.pop(get_session, None)
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Account disabled"


# ── Register tests ────────────────────────────────────────────────────────────

async def test_register_success_usbbog_domain():
    """@usbbog.edu.co email registers successfully and returns 201 + TokenResponse."""
    user = _make_user(email="newuser@usbbog.edu.co", role="student")
    session = _make_session()
    app.dependency_overrides[get_session] = _session_override(session)

    with (
        patch("routers.auth_router.get_user_by_email", new=AsyncMock(return_value=None)),
        patch("routers.auth_router.create_student_user", new=AsyncMock(return_value=user)),
    ):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
            resp = await client.post(
                "/api/v1/auth/register",
                json={
                    "email": "newuser@usbbog.edu.co",
                    "password": _PASSWORD,
                    "confirm_password": _PASSWORD,
                },
            )

    app.dependency_overrides.pop(get_session, None)
    assert resp.status_code == 201
    data = resp.json()
    assert "access_token" in data
    assert data["role"] == "student"


async def test_register_success_academia_domain():
    """@academia.usbbog.edu.co email registers successfully and returns 201."""
    user = _make_user(email="student@academia.usbbog.edu.co", role="student")
    session = _make_session()
    app.dependency_overrides[get_session] = _session_override(session)

    with (
        patch("routers.auth_router.get_user_by_email", new=AsyncMock(return_value=None)),
        patch("routers.auth_router.create_student_user", new=AsyncMock(return_value=user)),
    ):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
            resp = await client.post(
                "/api/v1/auth/register",
                json={
                    "email": "student@academia.usbbog.edu.co",
                    "password": _PASSWORD,
                    "confirm_password": _PASSWORD,
                },
            )

    app.dependency_overrides.pop(get_session, None)
    assert resp.status_code == 201


async def test_register_invalid_domain_returns_422():
    """Non-USB domain (@gmail.com) is rejected by Pydantic validation → 422."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "user@gmail.com",
                "password": _PASSWORD,
                "confirm_password": _PASSWORD,
            },
        )
    assert resp.status_code == 422


async def test_register_password_mismatch_returns_422():
    """Mismatched passwords are rejected by model_validator → 422."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": _STUDENT_EMAIL,
                "password": _PASSWORD,
                "confirm_password": "different_password",
            },
        )
    assert resp.status_code == 422


async def test_register_duplicate_email_returns_409():
    """Registering with an already-registered email returns 409 Conflict."""
    existing_user = _make_user()
    session = _make_session()
    app.dependency_overrides[get_session] = _session_override(session)

    with patch("routers.auth_router.get_user_by_email", new=AsyncMock(return_value=existing_user)):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
            resp = await client.post(
                "/api/v1/auth/register",
                json={
                    "email": _STUDENT_EMAIL,
                    "password": _PASSWORD,
                    "confirm_password": _PASSWORD,
                },
            )

    app.dependency_overrides.pop(get_session, None)
    assert resp.status_code == 409
    assert resp.json()["detail"] == "Email already registered"


async def test_register_short_password_returns_422():
    """Password shorter than 8 characters is rejected by Pydantic Field → 422."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": _STUDENT_EMAIL,
                "password": "short",
                "confirm_password": "short",
            },
        )
    assert resp.status_code == 422


async def test_login_admin_role_returned():
    """Admin user login returns role='admin' in TokenResponse."""
    user = _make_user(email=_ADMIN_EMAIL, role="admin")
    session = _make_session()
    app.dependency_overrides[get_session] = _session_override(session)

    with (
        patch("routers.auth_router.get_user_by_email", new=AsyncMock(return_value=user)),
        patch("routers.auth_router.verify_password", return_value=True),
    ):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
            resp = await client.post(
                "/api/v1/auth/login",
                json={"email": _ADMIN_EMAIL, "password": _PASSWORD},
            )

    app.dependency_overrides.pop(get_session, None)
    assert resp.status_code == 200
    assert resp.json()["role"] == "admin"
