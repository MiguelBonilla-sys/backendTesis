"""Tests for middleware/error_handler.py — exception → JSON response mapping."""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from core.exceptions import (
    AuthError,
    BackendTesisError,
    IDNAnalysisError,
    InvalidURLError,
    LLMInferenceError,
    TIFetchError,
)
from middleware.error_handler import ErrorHandlerMiddleware


# ── Build a minimal Starlette app with test routes ────────────────────────────

async def _raise_invalid_url(request: Request):
    raise InvalidURLError("bad url scheme")


async def _raise_auth_error(request: Request):
    raise AuthError("not authenticated")


async def _raise_idn_error(request: Request):
    raise IDNAnalysisError("idn analysis failed")


async def _raise_llm_error(request: Request):
    raise LLMInferenceError("llm failed")


async def _raise_ti_error(request: Request):
    raise TIFetchError("ti fetch failed")


async def _raise_backend_error(request: Request):
    raise BackendTesisError("generic backend error")


async def _raise_unhandled(request: Request):
    raise RuntimeError("completely unexpected error")


async def _ok(request: Request):
    return JSONResponse({"status": "ok"})


def _build_test_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(ErrorHandlerMiddleware)

    app.add_route("/raise-invalid-url", _raise_invalid_url)
    app.add_route("/raise-auth", _raise_auth_error)
    app.add_route("/raise-idn", _raise_idn_error)
    app.add_route("/raise-llm", _raise_llm_error)
    app.add_route("/raise-ti", _raise_ti_error)
    app.add_route("/raise-backend", _raise_backend_error)
    app.add_route("/raise-unhandled", _raise_unhandled)
    app.add_route("/ok", _ok)
    return app


_test_app = _build_test_app()


@pytest.mark.asyncio
async def test_normal_request_passes_through():
    async with AsyncClient(transport=ASGITransport(app=_test_app), base_url="http://test") as client:
        resp = await client.get("/ok")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_invalid_url_error_returns_422():
    async with AsyncClient(transport=ASGITransport(app=_test_app), base_url="http://test") as client:
        resp = await client.get("/raise-invalid-url")
    assert resp.status_code == 422
    body = resp.json()
    assert body["error"] == "InvalidURLError"
    assert "trace_id" in body
    assert "detail" in body


@pytest.mark.asyncio
async def test_auth_error_returns_401():
    async with AsyncClient(transport=ASGITransport(app=_test_app), base_url="http://test") as client:
        resp = await client.get("/raise-auth")
    assert resp.status_code == 401
    body = resp.json()
    assert body["error"] == "AuthError"
    assert "trace_id" in body


@pytest.mark.asyncio
async def test_idn_analysis_error_returns_500():
    async with AsyncClient(transport=ASGITransport(app=_test_app), base_url="http://test") as client:
        resp = await client.get("/raise-idn")
    assert resp.status_code == 500
    body = resp.json()
    assert body["error"] == "IDNAnalysisError"
    assert "trace_id" in body


@pytest.mark.asyncio
async def test_llm_inference_error_returns_500():
    async with AsyncClient(transport=ASGITransport(app=_test_app), base_url="http://test") as client:
        resp = await client.get("/raise-llm")
    assert resp.status_code == 500
    assert resp.json()["error"] == "LLMInferenceError"


@pytest.mark.asyncio
async def test_ti_fetch_error_returns_502():
    async with AsyncClient(transport=ASGITransport(app=_test_app), base_url="http://test") as client:
        resp = await client.get("/raise-ti")
    assert resp.status_code == 502
    assert resp.json()["error"] == "TIFetchError"


@pytest.mark.asyncio
async def test_generic_backend_error_returns_500():
    async with AsyncClient(transport=ASGITransport(app=_test_app), base_url="http://test") as client:
        resp = await client.get("/raise-backend")
    assert resp.status_code == 500
    assert resp.json()["error"] == "BackendTesisError"


@pytest.mark.asyncio
async def test_unhandled_exception_returns_500_with_trace_id():
    async with AsyncClient(transport=ASGITransport(app=_test_app), base_url="http://test") as client:
        resp = await client.get("/raise-unhandled")
    assert resp.status_code == 500
    body = resp.json()
    assert body["error"] == "internal_error"
    assert "trace_id" in body
    assert "unexpected error" in body["detail"]
