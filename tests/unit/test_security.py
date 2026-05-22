"""Tests for core/security.py — password and email hashing."""
from __future__ import annotations

import hashlib

from core.security import hash_email, hash_password, verify_password


class TestHashPassword:
    def test_returns_non_empty_string(self):
        result = hash_password("mypassword123")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_bcrypt_hash_format(self):
        result = hash_password("mypassword123")
        assert result.startswith("$2")

    def test_distinct_salts_produce_distinct_hashes(self):
        # bcrypt uses a random salt — hashing the same password twice differs
        assert hash_password("samepassword") != hash_password("samepassword")

    def test_handles_password_over_72_bytes(self):
        # bcrypt only uses the first 72 bytes — must not raise ValueError
        result = hash_password("x" * 200)
        assert result.startswith("$2")


class TestVerifyPassword:
    def test_correct_password_returns_true(self):
        hashed = hash_password("correct-horse-battery")
        assert verify_password("correct-horse-battery", hashed) is True

    def test_wrong_password_returns_false(self):
        hashed = hash_password("correct-horse-battery")
        assert verify_password("wrong-password", hashed) is False

    def test_verify_returns_bool(self):
        hashed = hash_password("password")
        assert isinstance(verify_password("password", hashed), bool)

    def test_roundtrip_over_72_bytes(self):
        long_password = "y" * 120
        hashed = hash_password(long_password)
        assert verify_password(long_password, hashed) is True


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
