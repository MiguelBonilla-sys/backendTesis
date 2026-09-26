"""Probe sockets connect only to the public addresses they just validated.

The HTTP origin is unchanged, preserving Host and TLS SNI. DNS runs off the
event loop, and proxies cannot bypass destination validation.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl

import httpcore
import httpx


def is_blocked_address(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return not ip.is_global or ip.is_multicast


class PublicNetworkBackend(httpcore.AsyncNetworkBackend):
    def __init__(self):
        self._backend = httpcore.AnyIOBackend()

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        try:
            async with asyncio.timeout(timeout):
                addresses = await asyncio.get_running_loop().getaddrinfo(
                    host,
                    port,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                )
                ips = list(dict.fromkeys(address[4][0] for address in addresses))
                if not ips or any(is_blocked_address(ip) for ip in ips):
                    raise httpcore.ConnectError("Probe destination is not public")
                for i, ip in enumerate(ips):
                    try:
                        # Numeric destination: no second hostname lookup by the connector.
                        return await self._backend.connect_tcp(
                            ip,
                            port,
                            timeout=timeout,
                            local_address=local_address,
                            socket_options=socket_options,
                        )
                    except httpcore.ConnectError:
                        if i == len(ips) - 1:
                            raise
        except TimeoutError as exc:
            raise httpcore.ConnectTimeout("Probe connection deadline exceeded") from exc
        except (OSError, ValueError) as exc:
            raise httpcore.ConnectError("Probe destination resolution failed") from exc

    async def connect_unix_socket(self, *args, **kwargs):
        raise httpcore.ConnectError("Unix sockets are not probe destinations")

    async def sleep(self, seconds):
        await asyncio.sleep(seconds)


class PublicProbeTransport(httpx.AsyncHTTPTransport):
    def __init__(self):
        # HTTPX's transport adapter owns this pool. Its pinned API is covered
        # by a request-level regression including Host/SNI and socket address.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # nosec: inspect invalid-cert phishing sites
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=context,
            network_backend=PublicNetworkBackend(),
            max_connections=2,
            max_keepalive_connections=0,
        )
