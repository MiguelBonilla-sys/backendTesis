"""Second factor for admin accounts: one-time code sent by email (RFS-01).

The code never leaves the process in clear except inside the email: Redis keeps
an HMAC of it in ``mfa:{challenge_id}`` with a TTL, an attempt counter and the
subject. Verification deletes the key, so a code works once; ``DEL`` returning 1
also makes two concurrent verifications of the same code accept only one.
Recovery codes are stored as HMACs in ``users.mfa_recovery`` and consumed with a
single conditional UPDATE.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime
from html import escape

from core.config import settings
from core.logger import get_logger
from core.security import hash_email

logger = get_logger(__name__)

RECOVERY_CODES = 8


class MfaError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _digest(value: str) -> str:
    return hmac.new(settings.JWT_SECRET_KEY.encode(), value.encode(), hashlib.sha256).hexdigest()


def requires_mfa(role: str) -> bool:
    return settings.MFA_ENABLED and role == "admin"


def _redis():
    from models.redis_client import get_redis

    return get_redis()


async def _send_code(email: str, code: str) -> bool:
    from services.mailer import send_email

    redis = _redis()
    day_key = f"mail:otp:{datetime.now(UTC):%Y%m%d}"
    if await redis.incr(day_key) > settings.OTP_DAILY_CAP:
        logger.warning("mfa_otp_daily_cap_reached")
        return False
    await redis.expire(day_key, 172800)
    minutes = settings.MFA_OTP_TTL_SECONDS // 60
    text = (f"Tu código de acceso al dashboard es {code}. Vence en {minutes} minutos.\n"
            "Si no intentaste iniciar sesión, cambia tu contraseña.")
    html = (f"<p>Tu código de acceso al dashboard es <strong>{escape(code)}</strong>.</p>"
            f"<p>Vence en {minutes} minutos. Si no intentaste iniciar sesión, "
            "cambia tu contraseña.</p>")
    return await send_email([email], "Código de acceso — IDN Phishing Detector", text, html,
                            kind="otp")


async def _within_send_budget(email: str) -> bool:
    """At most MFA_CODES_PER_WINDOW codes per 15 minutes per account."""
    key = f"mfa:sends:{hash_email(email)}"
    redis = _redis()
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, 900)
    return count <= settings.MFA_CODES_PER_WINDOW


async def start_challenge(email: str) -> tuple[str, bool]:
    """Create a challenge and email its code. Returns (challenge_id, email_sent)."""
    challenge_id = secrets.token_urlsafe(24)
    code = f"{secrets.randbelow(1_000_000):06d}"
    redis = _redis()
    key = f"mfa:{challenge_id}"
    await redis.hset(key, mapping={"sub": email, "digest": _digest(code), "attempts": 0})
    await redis.expire(key, settings.MFA_OTP_TTL_SECONDS)
    await redis.set(f"mfa:cooldown:{challenge_id}", "1", ex=settings.MFA_RESEND_COOLDOWN_SECONDS)
    sent = await _within_send_budget(email) and await _send_code(email, code)
    return challenge_id, sent


async def resend_code(challenge_id: str) -> bool:
    """New code for a live challenge after the cooldown; the old code stops working."""
    redis = _redis()
    key = f"mfa:{challenge_id}"
    email = await redis.hget(key, "sub")
    if not email:
        raise MfaError("expired")
    if not await redis.set(f"mfa:cooldown:{challenge_id}", "1", nx=True,
                           ex=settings.MFA_RESEND_COOLDOWN_SECONDS):
        raise MfaError("cooldown")
    if not await _within_send_budget(email):
        raise MfaError("too_many_codes")
    code = f"{secrets.randbelow(1_000_000):06d}"
    await redis.hset(key, mapping={"digest": _digest(code), "attempts": 0})
    return await _send_code(email, code)


async def _consume_recovery(email: str, code: str) -> bool:
    from models.database import fetchrow

    row = await fetchrow(
        "UPDATE users SET mfa_recovery = mfa_recovery - $2 "
        "WHERE email = $1 AND mfa_recovery ? $2 RETURNING email",
        email, _digest(code.lower()),
    )
    return row is not None


# One atomic step per verification: a challenge that was consumed or never existed
# is not recreated by the attempt counter, so concurrent verifications of the same
# code cannot both succeed (found by the T33 MFA pentest with 8 parallel requests).
VERIFY_SCRIPT = """
local sub = redis.call('HGET', KEYS[1], 'sub')
if not sub then return {'expired', ''} end
local attempts = redis.call('HINCRBY', KEYS[1], 'attempts', 1)
if attempts > tonumber(ARGV[2]) then
  redis.call('DEL', KEYS[1])
  return {'too_many_attempts', ''}
end
if ARGV[1] == '' then return {'recovery', sub} end
if redis.call('HGET', KEYS[1], 'digest') ~= ARGV[1] then return {'invalid_code', ''} end
redis.call('DEL', KEYS[1])
return {'ok', sub}
"""


async def verify_challenge(challenge_id: str, code: str) -> str:
    """Return the subject when the code (or a recovery code) is valid."""
    redis = _redis()
    key = f"mfa:{challenge_id}"
    recovery = "-" in code
    outcome, email = await redis.eval(
        VERIFY_SCRIPT, 1, key, "" if recovery else _digest(code), settings.MFA_MAX_ATTEMPTS)
    if outcome == "ok":
        return email
    if outcome != "recovery":
        raise MfaError(outcome)
    # Recovery codes are consumed by one conditional UPDATE: also single use under races.
    if await _consume_recovery(email, code):
        await redis.delete(key)
        return email
    raise MfaError("invalid_code")


async def new_recovery_codes(email: str) -> list[str]:
    """Replace the account's recovery codes; plain codes are returned only once."""
    from models.database import execute

    codes = [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(RECOVERY_CODES)]
    await execute("UPDATE users SET mfa_recovery = $2::jsonb WHERE email = $1",
                  email, json.dumps([_digest(c) for c in codes]))
    return codes
