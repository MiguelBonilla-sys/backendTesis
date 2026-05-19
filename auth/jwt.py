"""JWT creation and validation using python-jose (HS256)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt

from core.config import settings
from core.exceptions import AuthenticationError


def create_access_token(data: dict) -> str:
    """Encode *data* into a signed JWT with an expiry claim.

    The token is signed with ``settings.JWT_SECRET_KEY`` using
    ``settings.JWT_ALGORITHM`` (default HS256).

    Args:
        data: Arbitrary claims to embed.  A fresh ``exp`` claim is always
              added, overriding any existing value in *data*.

    Returns:
        A compact serialised JWT string.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    to_encode["exp"] = expire
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token.

    Args:
        token: The compact serialised JWT string.

    Returns:
        The decoded payload as a plain dict.

    Raises:
        AuthenticationError: If the token is expired, has an invalid signature,
                             or is otherwise malformed.
    """
    try:
        payload: dict = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        return payload
    except JWTError as exc:
        raise AuthenticationError(
            message="Invalid or expired token",
            detail=str(exc),
        ) from exc
