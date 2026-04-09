"""Tests for auth/auth.py — JWT create, decode, require_auth dependency."""

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from auth.auth import create_access_token, decode_token, require_auth
from core.exceptions import AuthError


def test_create_access_token_returns_string():
    token = create_access_token("user123")
    assert isinstance(token, str)
    assert len(token) > 20


def test_create_access_token_default_role():
    token = create_access_token("user123")
    payload = decode_token(token)
    assert payload["role"] == "user"


def test_create_access_token_custom_role():
    token = create_access_token("admin_user", role="admin")
    payload = decode_token(token)
    assert payload["sub"] == "admin_user"
    assert payload["role"] == "admin"


def test_decode_token_valid():
    token = create_access_token("alice")
    payload = decode_token(token)
    assert payload["sub"] == "alice"
    assert "exp" in payload


def test_decode_token_invalid_raises_auth_error():
    with pytest.raises(AuthError, match="Invalid or expired token"):
        decode_token("this.is.not.a.valid.jwt")


def test_decode_token_tampered_raises_auth_error():
    token = create_access_token("bob")
    tampered = token[:-5] + "XXXXX"
    with pytest.raises(AuthError):
        decode_token(tampered)


def test_require_auth_no_credentials_raises_401():
    with pytest.raises(HTTPException) as exc_info:
        require_auth(None)
    assert exc_info.value.status_code == 401
    assert "Not authenticated" in exc_info.value.detail


def test_require_auth_valid_token_returns_payload():
    token = create_access_token("charlie", role="analyst")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    payload = require_auth(creds)
    assert payload["sub"] == "charlie"
    assert payload["role"] == "analyst"


def test_require_auth_invalid_token_raises_401():
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="bad.token.value")
    with pytest.raises(HTTPException) as exc_info:
        require_auth(creds)
    assert exc_info.value.status_code == 401
