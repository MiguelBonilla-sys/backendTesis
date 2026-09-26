"""Exercise HTTPX/httpcore through the actual hardened transport."""

import asyncio
import socket
from unittest.mock import AsyncMock

import httpcore
import httpx
import pytest

from core.probe_transport import PublicNetworkBackend, PublicProbeTransport


def addresses(*ips):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in ips]


@pytest.mark.parametrize(
    "ips",
    [
        [],
        ["127.0.0.1"],
        ["169.254.169.254"],
        ["::ffff:127.0.0.1"],
        ["8.8.8.8", "10.0.0.1"],
        ["224.0.0.1"],
    ],
)
async def test_no_socket_opens_for_private_or_mixed_dns(monkeypatch, ips):
    backend = PublicNetworkBackend()
    connect = AsyncMock()
    monkeypatch.setattr(backend._backend, "connect_tcp", connect)
    monkeypatch.setattr(
        asyncio.get_running_loop(), "getaddrinfo", AsyncMock(return_value=addresses(*ips))
    )
    with pytest.raises(httpcore.ConnectError):
        await backend.connect_tcp("rebind.example", 443)
    connect.assert_not_awaited()


async def test_connection_dns_is_revalidated_and_pinned(monkeypatch):
    backend = PublicNetworkBackend()
    connect = AsyncMock()
    monkeypatch.setattr(backend._backend, "connect_tcp", connect)
    dns = AsyncMock(side_effect=[addresses("8.8.8.8"), addresses("127.0.0.1")])
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", dns)
    await backend.connect_tcp("rebind.example", 443)
    assert connect.await_args.args == ("8.8.8.8", 443)
    with pytest.raises(httpcore.ConnectError):
        await backend.connect_tcp("rebind.example", 443)
    assert connect.await_count == 1


async def test_dns_deadline_is_enforced(monkeypatch):
    async def slow(*args, **kwargs):
        await asyncio.sleep(10)

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", slow)
    with pytest.raises(httpcore.ConnectTimeout):
        await PublicNetworkBackend().connect_tcp("slow.example", 443, timeout=0.01)


async def test_real_transport_preserves_host_and_sni_with_numeric_socket(monkeypatch):
    class Stream(httpcore.AsyncNetworkStream):
        data = b""
        server_hostname = None

        async def read(self, max_bytes, timeout=None):
            return b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"

        async def write(self, buffer, timeout=None):
            self.data += buffer

        async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
            self.server_hostname = server_hostname
            return self

        async def aclose(self):
            pass

        def get_extra_info(self, info):
            return None

    stream = Stream()
    connect = AsyncMock(return_value=stream)
    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", connect)
    monkeypatch.setattr(
        asyncio.get_running_loop(), "getaddrinfo", AsyncMock(return_value=addresses("8.8.8.8"))
    )
    async with httpx.AsyncClient(transport=PublicProbeTransport(), trust_env=False) as client:
        response = await client.get("https://target.example/path")
    assert response.text == "OK"
    assert connect.await_args.args == ("8.8.8.8", 443)
    assert stream.server_hostname == "target.example"
    assert b"Host: target.example\r\n" in stream.data


async def test_retries_only_validated_addresses_and_denies_unix(monkeypatch):
    backend = PublicNetworkBackend()
    connect = AsyncMock(side_effect=[httpcore.ConnectError("down"), object()])
    monkeypatch.setattr(backend._backend, "connect_tcp", connect)
    monkeypatch.setattr(
        asyncio.get_running_loop(),
        "getaddrinfo",
        AsyncMock(return_value=addresses("8.8.8.8", "1.1.1.1")),
    )
    await backend.connect_tcp("multi.example", 443)
    assert [call.args[0] for call in connect.await_args_list] == ["8.8.8.8", "1.1.1.1"]
    with pytest.raises(httpcore.ConnectError):
        await backend.connect_unix_socket("/tmp/unsafe.sock")
