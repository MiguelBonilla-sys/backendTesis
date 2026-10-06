"""HSTS middleware: política, cobertura en respuestas de error y passthrough."""

from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.responses import PlainTextResponse

from core.transport_headers import TransportHeadersMiddleware

HSTS = "Strict-Transport-Security"
POLICY = "max-age=31536000"


def _wrap(inner: FastAPI) -> TransportHeadersMiddleware:
    """Misma integración que main.py: el middleware envuelve toda la app."""
    return TransportHeadersMiddleware(inner)


def test_ok_response_carries_hsts():
    inner = FastAPI()

    @inner.get("/ok")
    def ok() -> dict:
        return {"ok": True}

    response = TestClient(_wrap(inner)).get("/ok")
    assert response.status_code == 200
    assert response.headers[HSTS] == POLICY


def test_policy_has_no_include_subdomains_nor_preload():
    inner = FastAPI()

    @inner.get("/ok")
    def ok() -> dict:
        return {"ok": True}

    response = TestClient(_wrap(inner)).get("/ok")
    assert "includeSubDomains" not in response.headers[HSTS]
    assert "preload" not in response.headers[HSTS]


def test_handled_error_response_carries_hsts():
    inner = FastAPI()

    @inner.get("/boom")
    def boom() -> None:
        raise ValueError("boom")

    response = TestClient(_wrap(inner), raise_server_exceptions=False).get("/boom")
    assert response.status_code == 500
    assert response.headers[HSTS] == POLICY


def test_unhandled_error_through_server_error_middleware_carries_hsts():
    """Un 500 generado por ServerErrorMiddleware (fuera de ExceptionMiddleware)
    solo lleva HSTS si el middleware envuelve la app completa."""
    inner = FastAPI()

    @inner.get("/crash")
    def crash() -> None:
        raise ValueError("x")

    @inner.exception_handler(ValueError)
    async def failing_handler(request, exc):  # noqa: ARG001
        raise RuntimeError("handler failed")

    response = TestClient(_wrap(inner), raise_server_exceptions=False).get("/crash")
    assert response.status_code == 500
    assert response.headers[HSTS] == POLICY


def test_not_found_response_carries_hsts():
    inner = FastAPI()
    response = TestClient(_wrap(inner), raise_server_exceptions=False).get("/nope")
    assert response.status_code == 404
    assert response.headers[HSTS] == POLICY


def test_existing_response_headers_are_preserved():
    inner = FastAPI()

    @inner.get("/extra")
    def extra():
        return PlainTextResponse("x", headers={"X-Custom": "kept"})

    response = TestClient(_wrap(inner)).get("/extra")
    assert response.headers["X-Custom"] == "kept"
    assert response.headers[HSTS] == POLICY


def test_prior_sts_header_is_replaced():
    inner = FastAPI()

    @inner.get("/override")
    def override():
        return PlainTextResponse("x", headers={HSTS: "max-age=0"})

    response = TestClient(_wrap(inner)).get("/override")
    assert response.headers[HSTS] == POLICY


def test_lifespan_scope_passes_through_untouched():
    async def run_lifespan():
        inner = FastAPI()

        @inner.get("/health")
        def health() -> dict:
            return {"status": "ok"}

        app = _wrap(inner)
        with TestClient(app) as client:
            # Si el lifespan no pasara, TestClient fallaría el startup aquí.
            assert client.get("/health").status_code == 200

    import asyncio

    asyncio.run(run_lifespan())


def test_websocket_scope_passes_through_untouched():
    from starlette.websockets import WebSocket

    inner = FastAPI()

    @inner.websocket("/ws")
    async def ws(websocket: WebSocket):
        await websocket.accept()
        await websocket.send_text("ok")

    with TestClient(_wrap(inner)) as client:
        with client.websocket_connect("/ws") as websocket:
            assert websocket.receive_text() == "ok"


def test_real_main_app_emits_hsts_on_health_and_404():
    """El registro real en main.py: /health lleva HSTS sin levantar lifespan."""
    from main import app

    client = TestClient(app, raise_server_exceptions=False)
    assert client.get("/health").headers[HSTS] == POLICY
    assert client.get("/definitely-not-a-route").headers[HSTS] == POLICY
