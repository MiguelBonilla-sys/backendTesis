"""Signed tokens with explicit purpose and mandatory session claims."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
from jwt import PyJWTError

from core.config import settings
from core.exceptions import AuthenticationError


def _create_token(data: dict, kind: str, minutes: int) -> str:
    payload = data.copy()
    now = datetime.now(UTC)
    payload.update(type=kind, iat=now, exp=now + timedelta(minutes=minutes))
    payload.setdefault("sid", str(uuid4()))
    payload.setdefault("jti", str(uuid4()))
    payload.setdefault("role", "viewer")
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_access_token(data: dict) -> str:
    return _create_token(data, "access", settings.JWT_EXPIRE_MINUTES)


def create_refresh_token(data: dict) -> str:
    return _create_token(data, "refresh", settings.JWT_REFRESH_EXPIRE_MINUTES)


def decode_token(token: str, expected_type: str | None = None) -> dict:
    """Validate signature, time, mandatory identity/session claims and purpose."""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["sub", "role", "exp", "iat", "type", "sid", "jti"]},
        )
        if any(
            not isinstance(payload.get(key), str) or not payload[key].strip()
            for key in ("sub", "role", "type", "sid", "jti")
        ):
            raise ValueError("Invalid identity or session claims")
        if payload["role"] not in {"admin", "student", "viewer"}:
            raise ValueError("Invalid role")
        if payload["type"] not in {"access", "refresh"}:
            raise ValueError("Invalid token type")
        if expected_type is not None and payload["type"] != expected_type:
            raise ValueError("Incorrect token type")
        return payload
    except (PyJWTError, ValueError) as exc:
        raise AuthenticationError(message="Invalid or expired token", detail=str(exc)) from exc
