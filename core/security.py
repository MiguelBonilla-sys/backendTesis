"""Password hashing and privacy-compliant email hashing utilities."""

import hashlib

import bcrypt


def hash_password(password: str) -> str:
    """Return a bcrypt hash of *password*."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if *plain* matches the bcrypt *hashed* value."""
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def hash_email(email: str) -> str:
    """Return the SHA-256 hex digest of *email* for privacy compliance.

    Complies with Ley 1581/2012 — the original email address is never stored;
    only its deterministic hash is persisted in the database.
    """
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()
