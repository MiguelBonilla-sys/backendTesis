"""Tests for auth/auth_service.py — password hashing and user DB operations."""

import pytest

from auth.auth_service import hash_password, verify_password


# ── Password hashing ──────────────────────────────────────────────────────────

def test_hash_password_returns_bcrypt_hash():
    """hash_password() returns a bcrypt hash prefixed with $2b$."""
    hashed = hash_password("mysecretpassword")
    assert hashed.startswith("$2b$")


def test_hash_password_embeds_cost_factor_12():
    """bcrypt hash encodes the cost factor (rounds=12) in the prefix."""
    hashed = hash_password("testpassword1")
    # bcrypt format: $2b$<cost>$<22-char salt><31-char hash>
    assert hashed.startswith("$2b$12$")


def test_verify_password_correct_returns_true():
    """verify_password() returns True when plain matches the stored hash."""
    plain = "correct_password_123"
    hashed = hash_password(plain)
    assert verify_password(plain, hashed) is True


def test_verify_password_wrong_returns_false():
    """verify_password() returns False when plain does not match the hash."""
    hashed = hash_password("original_password")
    assert verify_password("wrong_password", hashed) is False


def test_hash_password_different_salts_per_call():
    """Two calls with the same plaintext produce different hashes (bcrypt salting)."""
    plain = "samepassword"
    hash1 = hash_password(plain)
    hash2 = hash_password(plain)
    assert hash1 != hash2


def test_verify_password_both_hashes_verify_correctly():
    """Both independently-salted hashes verify the same plaintext correctly."""
    plain = "samepassword"
    hash1 = hash_password(plain)
    hash2 = hash_password(plain)
    assert verify_password(plain, hash1) is True
    assert verify_password(plain, hash2) is True


def test_verify_password_empty_string_does_not_match_non_empty():
    """Empty plaintext does not match a hash of a non-empty password."""
    hashed = hash_password("nonempty")
    assert verify_password("", hashed) is False


def test_hash_password_length_within_bcrypt_limit():
    """Output hash length is the standard 60-character bcrypt string."""
    hashed = hash_password("anypassword")
    assert len(hashed) == 60
