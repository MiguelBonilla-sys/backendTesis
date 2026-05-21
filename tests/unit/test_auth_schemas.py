"""Tests for schemas/auth.py — auth request/response schemas."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from schemas.auth import LoginRequest, TokenResponse, UserInfo


class TestLoginRequest:
    def test_valid_login(self):
        req = LoginRequest(username="admin", password="password123")
        assert req.username == "admin"
        assert req.password == "password123"

    def test_username_too_short_raises(self):
        with pytest.raises(ValidationError):
            LoginRequest(username="", password="password123")

    def test_password_too_short_raises(self):
        with pytest.raises(ValidationError):
            LoginRequest(username="admin", password="")

    def test_min_username_length(self):
        req = LoginRequest(username="a", password="password123")
        assert req.username == "a"

    def test_min_password_length(self):
        req = LoginRequest(username="admin", password="p")
        assert req.password == "p"


class TestTokenResponse:
    def test_valid_token_response(self):
        token = TokenResponse(access_token="jwt.token.here", expires_in=3600, role="admin")
        assert token.access_token == "jwt.token.here"
        assert token.token_type == "bearer"
        assert token.expires_in == 3600

    def test_token_type_defaults_to_bearer(self):
        token = TokenResponse(access_token="token", expires_in=1800, role="admin")
        assert token.token_type == "bearer"


class TestUserInfo:
    def test_valid_user_info(self):
        user = UserInfo(username="admin", role="admin")
        assert user.username == "admin"
        assert user.role == "admin"

    def test_role_stored(self):
        user = UserInfo(username="viewer", role="viewer")
        assert user.role == "viewer"
