"""Redis-backed sessions, atomic refresh rotation and current account checks.

Sessions fail closed when DB/Redis is unavailable. Independent Redis instances
require reauthentication after failover; cookie sharing alone is insufficient.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from uuid import uuid4

from fastapi import HTTPException

from auth.jwt import create_access_token, create_refresh_token
from core.config import settings
from models.database import fetchrow
from models.redis_client import get_redis

# Compare and rotate in one Redis command, preventing concurrent replay.
ROTATE_SCRIPT = """
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local session = cjson.decode(raw)
if session.refresh_jti ~= ARGV[1] then return 0 end
session.refresh_jti = ARGV[2]
redis.call('SET', KEYS[1], cjson.encode(session), 'EX', ARGV[3])
return 1
"""


def credential_version(password_hash: str) -> str:
    return hmac.new(
        settings.JWT_SECRET_KEY.encode(), password_hash.encode(), hashlib.sha256
    ).hexdigest()


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=401, detail="Session invalid or expired", headers={"WWW-Authenticate": "Bearer"}
    )


def _unavailable() -> HTTPException:
    return HTTPException(status_code=503, detail="Authentication service unavailable")


async def current_account(subject: str) -> dict:
    try:
        row = await fetchrow(
            "SELECT id, email, password_hash, role, is_active FROM users WHERE email = $1",
            subject,
        )
    except Exception as exc:
        raise _unavailable() from exc
    if not row or not row["is_active"] or row["role"] not in {"admin", "student", "viewer"}:
        raise _unauthorized()
    return dict(row)


def _tokens(subject: str, role: str, sid: str, refresh_jti: str) -> tuple[str, str, str]:
    claims = {"sub": subject, "role": role, "sid": sid}
    return (
        create_access_token(claims),
        create_refresh_token({**claims, "jti": refresh_jti}),
        role,
    )


async def issue_session(subject: str) -> tuple[str, str, str]:
    account = await current_account(subject)
    sid, refresh_jti = str(uuid4()), str(uuid4())
    value = json.dumps(
        {
            "sub": account["email"],
            "refresh_jti": refresh_jti,
            "credential_version": credential_version(account["password_hash"]),
        }
    )
    try:
        stored = await get_redis().set(
            f"auth:session:{sid}", value, ex=settings.JWT_REFRESH_EXPIRE_MINUTES * 60, nx=True
        )
    except Exception as exc:
        raise _unavailable() from exc
    if not stored:
        raise _unavailable()
    return _tokens(account["email"], account["role"], sid, refresh_jti)


async def validate_session(payload: dict) -> dict:
    """Check revocation, active account and credentials; always use its live role."""
    try:
        raw = await get_redis().get(f"auth:session:{payload['sid']}")
    except Exception as exc:
        raise _unavailable() from exc
    if not raw:
        raise _unauthorized()
    try:
        session = json.loads(raw)
        if session["sub"] != payload["sub"]:
            raise _unauthorized()
        account = await current_account(payload["sub"])
        if not hmac.compare_digest(
            session["credential_version"], credential_version(account["password_hash"])
        ):
            raise _unauthorized()
    except (KeyError, ValueError, TypeError) as exc:
        raise _unauthorized() from exc
    return {**payload, "role": account["role"], "id": str(account["id"])}


async def rotate_session(payload: dict) -> tuple[str, str, str]:
    current = await validate_session(payload)
    new_jti = str(uuid4())
    try:
        rotated = await get_redis().eval(
            ROTATE_SCRIPT,
            1,
            f"auth:session:{payload['sid']}",
            payload["jti"],
            new_jti,
            settings.JWT_REFRESH_EXPIRE_MINUTES * 60,
        )
    except Exception as exc:
        raise _unavailable() from exc
    if rotated != 1:
        raise _unauthorized()
    return _tokens(payload["sub"], current["role"], payload["sid"], new_jti)


async def revoke_session(payload: dict) -> None:
    try:
        await get_redis().delete(f"auth:session:{payload['sid']}")
    except Exception as exc:
        raise _unavailable() from exc
