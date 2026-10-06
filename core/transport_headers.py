"""HSTS at the application boundary, including TLS terminated by the proxy.

Policy: ``Strict-Transport-Security: max-age=31536000`` (one year). Deliberately
no ``includeSubDomains`` (no sibling domains served by this host) and no
``preload`` (out of scope).

Placement: this middleware must wrap the whole application, outside FastAPI's
middleware stack (``app = TransportHeadersMiddleware(app)``). Starlette's
``ServerErrorMiddleware`` sends its 500 responses through the outermost ``send``,
so any middleware registered with ``add_middleware`` never sees them. Wrapped
outermost, unhandled-exception responses carry HSTS too.

Browsers only honor HSTS received over HTTPS. Emit it also on the private HTTP
hop so that TLS termination at Cloudflare retains the policy.
"""

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class TransportHeadersMiddleware:
    """No forwarded-header trust is implied.

    Non-HTTP scopes (lifespan, websocket) pass through untouched.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Strict-Transport-Security"] = "max-age=31536000"
            await send(message)

        await self.app(scope, receive, send_headers)
