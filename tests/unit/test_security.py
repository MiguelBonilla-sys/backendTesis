"""Tests for core/security.py — password and email hashing."""
from __future__ import annotations

import hashlib

import pytest
from unittest.mock import patch, MagicMock

from core.security import hash_email


class TestHashPassword:
    def test_returns_non_empty_string(self):
        with patch("core.security.pwd_context") as mock_ctx:
            mock_ctx.hash.return_value = "$2b$12$mockedhashvalue"
            from core.security import hash_password
            result = hash_password("mypassword123")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_delegates_to_pwd_context(self):
        with patch("core.security.pwd_context") as mock_ctx:
            mock_ctx.hash.return_value = "$2b$12$test"
            from core.security import hash_password
            hash_password("password")
            mock_ctx.hash.assert_called_once_with("password")

    def test_bcrypt_hash_format(self):
        with patch("core.security.pwd_context") as mock_ctx:
            mock_ctx.hash.return_value = "$2b$12$mockedhashvalue"
            from core.security import hash_password
            result = hash_password("mypassword123")
        assert result.startswith("$2")


class TestVerifyPassword:
    def test_correct_password_returns_true(self):
        with patch("core.security.pwd_context") as mock_ctx:
            mock_ctx.verify.return_value = True
            from core.security import verify_password
            result = verify_password("correct", "$2b$12$hash")
        assert result is True

    def test_wrong_password_returns_false(self):
        with patch("core.security.pwd_context") as mock_ctx:
            mock_ctx.verify.return_value = False
            from core.security import verify_password
            result = verify_password("wrong", "$2b$12$hash")
        assert result is False

    def test_delegates_to_pwd_context(self):
        with patch("core.security.pwd_context") as mock_ctx:
            mock_ctx.verify.return_value = True
            from core.security import verify_password
            verify_password("plain", "hashed")
            mock_ctx.verify.assert_called_once_with("plain", "hashed")

    def test_verify_returns_bool(self):
        with patch("core.security.pwd_context") as mock_ctx:
            mock_ctx.verify.return_value = True
            from core.security import verify_password
            result = verify_password("password", "hash")
        assert isinstance(result, bool)


class TestHashEmail:
    def test_returns_64_char_hex_string(self):
        result = hash_email("user@example.com")
        assert isinstance(result, str)
        assert len(result) == 64

    def test_deterministic_same_email(self):
        h1 = hash_email("user@example.com")
        h2 = hash_email("user@example.com")
        assert h1 == h2

    def test_different_emails_produce_different_hashes(self):
        h1 = hash_email("user1@example.com")
        h2 = hash_email("user2@example.com")
        assert h1 != h2

    def test_strips_whitespace(self):
        h1 = hash_email("user@example.com")
        h2 = hash_email("  user@example.com  ")
        assert h1 == h2

    def test_lowercases_before_hashing(self):
        h1 = hash_email("User@Example.COM")
        h2 = hash_email("user@example.com")
        assert h1 == h2

    def test_matches_manual_sha256(self):
        email = "user@example.com"
        expected = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()
        assert hash_email(email) == expected

    def test_result_is_hex(self):
        result = hash_email("test@test.com")
        int(result, 16)  # must not raise
