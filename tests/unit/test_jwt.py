"""Tests for auth/jwt.py — JWT creation and validation."""
from __future__ import annotations

import time

import pytest
from jose import jwt

from auth.jwt import create_access_token, decode_token
from core.config import settings
from core.exceptions import AuthenticationError


class TestCreateAccessToken:
    def test_returns_non_empty_string(self):
        token = create_access_token({"sub": "user1"})
        assert isinstance(token, str)
        assert len(token) > 0

    def test_token_has_three_parts(self):
        token = create_access_token({"sub": "user1"})
        parts = token.split(".")
        assert len(parts) == 3

    def test_payload_embedded_in_token(self):
        token = create_access_token({"sub": "testuser", "role": "admin"})
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        assert payload["sub"] == "testuser"
        assert payload["role"] == "admin"

    def test_exp_claim_added(self):
        token = create_access_token({"sub": "user1"})
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        assert "exp" in payload

    def test_exp_in_future(self):
        token = create_access_token({"sub": "user1"})
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        assert payload["exp"] > time.time()

    def test_different_payloads_produce_different_tokens(self):
        t1 = create_access_token({"sub": "user1"})
        t2 = create_access_token({"sub": "user2"})
        assert t1 != t2

    def test_empty_payload_token_created(self):
        token = create_access_token({})
        assert len(token) > 0


class TestDecodeToken:
    def test_valid_token_decoded(self):
        token = create_access_token({"sub": "user1"})
        payload = decode_token(token)
        assert payload["sub"] == "user1"

    def test_invalid_token_raises_authentication_error(self):
        with pytest.raises(AuthenticationError):
            decode_token("not.a.valid.token")

    def test_tampered_token_raises_authentication_error(self):
        token = create_access_token({"sub": "user1"})
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(AuthenticationError):
            decode_token(tampered)

    def test_wrong_secret_raises_authentication_error(self):
        # Encode with different secret
        token = jwt.encode(
            {"sub": "user1"}, "wrong-secret", algorithm=settings.JWT_ALGORITHM
        )
        with pytest.raises(AuthenticationError):
            decode_token(token)

    def test_decoded_payload_is_dict(self):
        token = create_access_token({"sub": "user1"})
        payload = decode_token(token)
        assert isinstance(payload, dict)

    def test_authentication_error_has_message(self):
        with pytest.raises(AuthenticationError) as exc_info:
            decode_token("bad.token.here")
        assert exc_info.value.message != ""

    def test_round_trip_all_claims(self):
        data = {"sub": "user1", "role": "admin", "custom": "value"}
        token = create_access_token(data)
        payload = decode_token(token)
        assert payload["sub"] == "user1"
        assert payload["role"] == "admin"
        assert payload["custom"] == "value"
