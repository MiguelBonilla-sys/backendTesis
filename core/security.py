"""Password hashing and privacy-compliant email hashing utilities."""

import hashlib

import anyio
import bcrypt

from core.config import settings

_hash_limiter = anyio.CapacityLimiter(max(1, settings.AUTH_HASH_CONCURRENCY))

# bcrypt only considers the first 72 bytes of a password. bcrypt 4.x+ raises
# ValueError for longer inputs instead of truncating silently, so truncate
# here to keep behaviour stable and avoid 500 errors on long passwords.
_BCRYPT_MAX_BYTES = 72


def _to_bcrypt_bytes(password: str) -> bytes:
    """Encode *password* to UTF-8 bytes, capped at bcrypt's 72-byte limit."""
    return password.encode("utf-8")[:_BCRYPT_MAX_BYTES]


def hash_password(password: str) -> str:
    """Return a bcrypt hash of *password*."""
    return bcrypt.hashpw(_to_bcrypt_bytes(password), bcrypt.gensalt(rounds=12)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if *plain* matches the bcrypt *hashed* value."""
    return bcrypt.checkpw(_to_bcrypt_bytes(plain), hashed.encode())


def hash_email(email: str) -> str:
    """Return the SHA-256 hex digest of *email* for privacy compliance.

    Complies with Ley 1581/2012 — the original email address is never stored;
    only its deterministic hash is persisted in the database.
    """
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()


async def hash_password_async(password: str) -> str:
    """Bound expensive password work without blocking the application loop."""
    return await anyio.to_thread.run_sync(hash_password, password, limiter=_hash_limiter)


async def verify_password_async(plain: str, hashed: str) -> bool:
    return await anyio.to_thread.run_sync(verify_password, plain, hashed, limiter=_hash_limiter)
