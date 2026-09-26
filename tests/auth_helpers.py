"""Explicit in-memory storage doubles for real auth/session endpoint tests.

Only Redis/database I/O is replaced. Signing, token validation, account checks,
rotation, rate limiting and Origin validation execute the production code.
"""

from __future__ import annotations

import json
import time
from uuid import uuid4

from auth.jwt import create_access_token as sign_access
from auth.jwt import create_refresh_token as sign_refresh
from auth.sessions import credential_version

_active_store = None


class MemoryPipeline:
    def __init__(self, store):
        self.store = store
        self.operations = []

    async def zremrangebyscore(self, *args):
        self.operations.append(("remove", args))

    async def zcard(self, *args):
        self.operations.append(("count", args))

    async def zadd(self, *args):
        self.operations.append(("add", args))

    async def expire(self, *args):
        self.operations.append(("expire", args))

    async def execute(self):
        results = []
        # No await inside: same atomic ordering as a Redis transaction.
        for operation, args in self.operations:
            entries = self.store.windows.setdefault(args[0], {})
            if operation == "remove":
                expired = [key for key, score in entries.items() if args[1] <= score <= args[2]]
                for key in expired:
                    del entries[key]
                results.append(len(expired))
            elif operation == "count":
                results.append(len(entries))
            elif operation == "add":
                entries.update(args[1])
                results.append(len(args[1]))
            else:
                results.append(True)
        return results


class AuthStore:
    def __init__(self):
        self.sessions = {}
        self.expires = {}
        self.windows = {}
        self.accounts = {}
        for username, role in (
            ("admin", "admin"),
            ("test-user", "admin"),
            ("viewer1", "viewer"),
            ("nuevo.user@academia.usbbog.edu.co", "student"),
        ):
            self.add_account(username, role)

    def add_account(self, username, role="student", password_hash="test-password-hash"):
        account = {
            "id": str(uuid4()),
            "email": username,
            "role": role,
            "is_active": True,
            "password_hash": password_hash,
        }
        self.accounts[username] = account
        return account

    async def fetchrow(self, query, username):
        return self.accounts.get(username)

    async def set(self, key, value, ex=None, nx=False):
        if nx and key in self.sessions:
            return None
        self.sessions[key] = value
        self.expires[key] = time.time() + ex if ex else float("inf")
        return True

    async def get(self, key):
        if self.expires.get(key, 0) <= time.time():
            self.sessions.pop(key, None)
        return self.sessions.get(key)

    async def delete(self, key):
        return int(self.sessions.pop(key, None) is not None)

    async def eval(self, script, count, key, previous, new, ttl):
        raw = await self.get(key)
        if not raw:
            return 0
        value = json.loads(raw)
        if value["refresh_jti"] != previous:
            return 0
        value["refresh_jti"] = new
        await self.set(key, json.dumps(value), ex=int(ttl))
        return 1

    def pipeline(self):
        return MemoryPipeline(self)

    def issue(self, data):
        """Seed a session for a pre-existing account and sign real JWTs."""
        account = self.accounts[data["sub"]]
        sid, refresh_jti = str(uuid4()), str(uuid4())
        self.sessions[f"auth:session:{sid}"] = json.dumps(
            {
                "sub": account["email"],
                "refresh_jti": refresh_jti,
                "credential_version": credential_version(account["password_hash"]),
            }
        )
        self.expires[f"auth:session:{sid}"] = time.time() + 86400
        claims = {**data, "sid": sid}
        return sign_access(claims), sign_refresh({**claims, "jti": refresh_jti})


def create_access_token(data):
    if _active_store is None:
        raise RuntimeError("Request the auth_store fixture before issuing a test session")
    return _active_store.issue(data)[0]


def create_refresh_token(data):
    if _active_store is None:
        raise RuntimeError("Request the auth_store fixture before issuing a test session")
    return _active_store.issue(data)[1]
