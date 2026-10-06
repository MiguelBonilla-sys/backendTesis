import asyncio
import re
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from auth import mfa
from core.config import settings

ORIGIN = {"Origin": "https://dashdect.mangel.dpdns.org"}


class FakeRedis:
    def __init__(self):
        self.data: dict[str, object] = {}

    async def hset(self, key, mapping):
        self.data.setdefault(key, {}).update({k: str(v) for k, v in mapping.items()})

    async def hget(self, key, field):
        return self.data.get(key, {}).get(field)

    async def hgetall(self, key):
        return dict(self.data.get(key, {}))

    async def hincrby(self, key, field, amount):
        bucket = self.data.setdefault(key, {})
        bucket[field] = str(int(bucket.get(field, 0)) + amount)
        return int(bucket[field])

    async def expire(self, key, ttl):
        return True

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.data:
            return None
        self.data[key] = value
        return True

    async def incr(self, key):
        self.data[key] = int(self.data.get(key, 0)) + 1
        return self.data[key]

    async def delete(self, key):
        return 1 if self.data.pop(key, None) is not None else 0

    async def eval(self, script, numkeys, key, digest, max_attempts):
        """Same semantics as mfa.VERIFY_SCRIPT, atomic like Redis EVAL."""
        bucket = self.data.get(key)
        if not bucket or not bucket.get("sub"):
            return ["expired", ""]
        bucket["attempts"] = str(int(bucket.get("attempts", 0)) + 1)
        if int(bucket["attempts"]) > int(max_attempts):
            self.data.pop(key, None)
            return ["too_many_attempts", ""]
        if digest == "":
            return ["recovery", bucket["sub"]]
        if bucket.get("digest") != digest:
            return ["invalid_code", ""]
        self.data.pop(key, None)
        return ["ok", bucket["sub"]]


@pytest.fixture
def mfa_env(monkeypatch):
    redis = FakeRedis()
    sent: list[str] = []

    async def fake_send(to, subject, text, html, *, kind):
        sent.append(text)
        return True

    monkeypatch.setattr(settings, "MFA_ENABLED", True)
    monkeypatch.setattr(mfa, "_redis", lambda: redis)
    monkeypatch.setattr("services.mailer.send_email", fake_send)
    return redis, sent


def _code(sent):
    return re.search(r"\b(\d{6})\b", sent[-1]).group(1)


class TestChallenge:
    async def test_valid_code_once(self, mfa_env):
        _, sent = mfa_env
        cid, ok = await mfa.start_challenge("boss@usb.edu.co")
        assert ok
        assert await mfa.verify_challenge(cid, _code(sent)) == "boss@usb.edu.co"
        with pytest.raises(mfa.MfaError) as exc:
            await mfa.verify_challenge(cid, _code(sent))
        assert exc.value.reason == "expired"

    async def test_wrong_code_then_lockout(self, mfa_env):
        _, sent = mfa_env
        cid, _ = await mfa.start_challenge("boss@usb.edu.co")
        for _ in range(settings.MFA_MAX_ATTEMPTS):
            with pytest.raises(mfa.MfaError):
                await mfa.verify_challenge(cid, "000000" if _code(sent) != "000000" else "111111")
        with pytest.raises(mfa.MfaError) as exc:
            await mfa.verify_challenge(cid, _code(sent))
        assert exc.value.reason == "too_many_attempts"

    async def test_unknown_challenge(self, mfa_env):
        with pytest.raises(mfa.MfaError) as exc:
            await mfa.verify_challenge("nope" * 5, "123456")
        assert exc.value.reason == "expired"

    async def test_concurrent_verification_accepts_one(self, mfa_env):
        _, sent = mfa_env
        cid, _ = await mfa.start_challenge("boss@usb.edu.co")
        code = _code(sent)
        results = await asyncio.gather(mfa.verify_challenge(cid, code),
                                       mfa.verify_challenge(cid, code), return_exceptions=True)
        assert sum(r == "boss@usb.edu.co" for r in results) == 1

    async def test_resend_respects_cooldown_and_replaces_code(self, mfa_env):
        redis, sent = mfa_env
        cid, _ = await mfa.start_challenge("boss@usb.edu.co")
        first = _code(sent)
        with pytest.raises(mfa.MfaError) as exc:
            await mfa.resend_code(cid)
        assert exc.value.reason == "cooldown"
        redis.data.pop(f"mfa:cooldown:{cid}")
        assert await mfa.resend_code(cid)
        second = _code(sent)
        if first != second:
            with pytest.raises(mfa.MfaError):
                await mfa.verify_challenge(cid, first)
        assert await mfa.verify_challenge(cid, second) == "boss@usb.edu.co"

    async def test_resend_unknown_and_budget(self, mfa_env):
        redis, _ = mfa_env
        with pytest.raises(mfa.MfaError):
            await mfa.resend_code("x" * 20)
        cid, _ = await mfa.start_challenge("boss@usb.edu.co")
        for _ in range(settings.MFA_CODES_PER_WINDOW - 1):
            redis.data.pop(f"mfa:cooldown:{cid}", None)
            await mfa.resend_code(cid)
        redis.data.pop(f"mfa:cooldown:{cid}", None)
        with pytest.raises(mfa.MfaError) as exc:
            await mfa.resend_code(cid)
        assert exc.value.reason == "too_many_codes"

    async def test_daily_otp_cap(self, mfa_env, monkeypatch):
        _, sent = mfa_env
        monkeypatch.setattr(settings, "OTP_DAILY_CAP", 1)
        assert (await mfa.start_challenge("a@usb.edu.co"))[1]
        assert not (await mfa.start_challenge("b@usb.edu.co"))[1]
        assert len(sent) == 1

    async def test_recovery_code_single_use(self, mfa_env):
        stored: dict[str, list[str]] = {}

        async def fake_execute(query, email, payload):
            import json
            stored[email] = json.loads(payload)

        async def fake_fetchrow(query, email, digest):
            if digest in stored.get(email, []):
                stored[email].remove(digest)
                return {"email": email}
            return None

        with patch("models.database.execute", fake_execute), \
             patch("models.database.fetchrow", fake_fetchrow):
            codes = await mfa.new_recovery_codes("boss@usb.edu.co")
            assert len(codes) == mfa.RECOVERY_CODES and len(set(codes)) == mfa.RECOVERY_CODES
            cid, _ = await mfa.start_challenge("boss@usb.edu.co")
            assert await mfa.verify_challenge(cid, codes[0].upper()) == "boss@usb.edu.co"
            cid, _ = await mfa.start_challenge("boss@usb.edu.co")
            with pytest.raises(mfa.MfaError):
                await mfa.verify_challenge(cid, codes[0])

    def test_requires_mfa_only_for_admin(self, monkeypatch):
        monkeypatch.setattr(settings, "MFA_ENABLED", True)
        assert mfa.requires_mfa("admin") and not mfa.requires_mfa("student")
        monkeypatch.setattr(settings, "MFA_ENABLED", False)
        assert not mfa.requires_mfa("admin")


@pytest.fixture
def client(auth_store, mfa_env):
    from main import app

    with patch("main.init_db", new_callable=AsyncMock), \
         patch("main.close_db", new_callable=AsyncMock), \
         patch("main.init_redis", new_callable=AsyncMock), \
         patch("main.close_redis", new_callable=AsyncMock), \
         patch("routers.auth_router.log_audit_event", new_callable=AsyncMock), \
         patch("routers.auth_router._authenticate_user") as auth:
        from schemas.auth import UserInfo

        auth.side_effect = AsyncMock(side_effect=lambda u, p: UserInfo(
            username=u, role="admin" if u.startswith("boss") else "student"))
        auth_store.add_account("boss@usb.edu.co", "admin")
        auth_store.add_account("ana@usb.edu.co", "student")
        with TestClient(app) as c:
            yield c


class TestHttpFlow:
    def test_admin_gets_challenge_then_tokens(self, client, mfa_env):
        _, sent = mfa_env
        resp = client.post("/api/v1/auth/login", headers=ORIGIN,
                           json={"username": "boss@usb.edu.co", "password": "x"})
        body = resp.json()
        assert resp.status_code == 200 and body["mfa_required"] is True
        assert "access_token" not in body
        resp = client.post("/api/v1/auth/mfa/verify", headers=ORIGIN,
                           json={"challenge_id": body["challenge_id"], "code": _code(sent)})
        assert resp.status_code == 200 and resp.json()["access_token"]

    def test_student_skips_mfa(self, client):
        resp = client.post("/api/v1/auth/login", headers=ORIGIN,
                           json={"username": "ana@usb.edu.co", "password": "x"})
        assert resp.status_code == 200 and resp.json()["access_token"]

    def test_wrong_code_is_401_and_resend_cooldown_429(self, client):
        body = client.post("/api/v1/auth/login", headers=ORIGIN,
                           json={"username": "boss@usb.edu.co", "password": "x"}).json()
        resp = client.post("/api/v1/auth/mfa/verify", headers=ORIGIN,
                           json={"challenge_id": body["challenge_id"], "code": "12345a"})
        assert resp.status_code == 422
        resp = client.post("/api/v1/auth/mfa/verify", headers=ORIGIN,
                           json={"challenge_id": "y" * 20, "code": "123456"})
        assert resp.status_code == 401
        resp = client.post("/api/v1/auth/mfa/resend", headers=ORIGIN,
                           json={"challenge_id": body["challenge_id"]})
        assert resp.status_code == 429

    def test_recovery_codes_endpoint_admin_only(self, client):
        from tests.auth_helpers import create_access_token

        student = create_access_token({"sub": "ana@usb.edu.co", "role": "student"})
        resp = client.post("/api/v1/auth/mfa/recovery-codes", headers={
            **ORIGIN, "Authorization": f"Bearer {student}"})
        assert resp.status_code == 403
        admin = create_access_token({"sub": "boss@usb.edu.co", "role": "admin"})
        with patch("routers.auth_router.new_recovery_codes",
                   AsyncMock(return_value=["abcd-1234"])):
            resp = client.post("/api/v1/auth/mfa/recovery-codes", headers={
                **ORIGIN, "Authorization": f"Bearer {admin}"})
        assert resp.status_code == 200 and resp.json()["codes"] == ["abcd-1234"]

pytestmark = [pytest.mark.acceptance]
