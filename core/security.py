"""Password hashing and privacy-compliant email hashing utilities."""

import hashlib

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Return a bcrypt hash of *password*."""
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if *plain* matches the bcrypt *hashed* value."""
    return pwd_context.verify(plain, hashed)


def hash_email(email: str) -> str:
    """Return the SHA-256 hex digest of *email* for privacy compliance.

    Complies with Ley 1581/2012 — the original email address is never stored;
    only its deterministic hash is persisted in the database.
    """
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()
