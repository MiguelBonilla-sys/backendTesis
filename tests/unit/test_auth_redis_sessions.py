"""Exercise production refresh Lua against an isolated local Redis process."""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
import redis
import redis.asyncio as async_redis
from fastapi import HTTPException

from auth.jwt import decode_token
from auth.sessions import issue_session, revoke_session, rotate_session, validate_session
from tests.support.local_process import spawn


@pytest.fixture
def isolated_redis_socket():
    executable = shutil.which("redis-server")
    if executable is None:
        pytest.skip("redis-server required for isolated session integration")
    with tempfile.TemporaryDirectory(prefix="auth-redis-", dir="/tmp") as directory:
        socket = str(Path(directory) / "redis.sock")
        process = spawn(
            [
                executable,
                "--port",
                "0",
                "--unixsocket",
                socket,
                "--unixsocketperm",
                "700",
                "--save",
                "",
                "--appendonly",
                "no",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        probe = redis.Redis(unix_socket_path=socket)
        try:
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                try:
                    if probe.ping():
                        break
                except redis.ConnectionError:
                    time.sleep(0.01)
            else:
                pytest.fail("Isolated Redis did not become ready")
            yield socket
        finally:
            probe.close()
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


@pytest.mark.asyncio
async def test_real_redis_rotation_replay_and_revocation(
    auth_store, isolated_redis_socket, monkeypatch
):
    client = async_redis.Redis(unix_socket_path=isolated_redis_socket, decode_responses=True)
    monkeypatch.setattr("auth.sessions.get_redis", lambda: client)
    try:
        access, refresh, role = await issue_session("admin")
        payload = decode_token(refresh)
        assert await client.ttl(f"auth:session:{payload['sid']}") > 0
        attempts = await asyncio.gather(
            *(rotate_session(payload) for _ in range(5)),
            return_exceptions=True,
        )
        issued = [result for result in attempts if isinstance(result, tuple)]
        denied = [result for result in attempts if isinstance(result, HTTPException)]
        assert len(issued) == 1
        assert len(denied) == 4 and all(result.status_code == 401 for result in denied)
        assert (await validate_session(decode_token(access)))["role"] == role
        replacement = issued[0][1]
        assert (await rotate_session(decode_token(replacement)))[1] != replacement
        await revoke_session(payload)
        with pytest.raises(HTTPException) as error:
            await validate_session(decode_token(access))
        assert error.value.status_code == 401
    finally:
        await client.aclose()
