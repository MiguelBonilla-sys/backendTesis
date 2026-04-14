"""Tests for GET /health endpoint — Phase 1 acceptance criteria."""

import pytest
from httpx import ASGITransport, AsyncClient
from unittest.mock import AsyncMock, patch

from main import app


@pytest.mark.asyncio
async def test_health_returns_200():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_health_response_structure():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/health")
    data = resp.json()
    assert "status" in data
    assert "version" in data
    assert "components" in data


@pytest.mark.asyncio
async def test_readiness_returns_200():
    """Readiness probe returns 200 + ready:true when DB is reachable."""
    from models.database import get_session
    from unittest.mock import AsyncMock

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock()

    async def _override():
        yield mock_session

    app.dependency_overrides[get_session] = _override
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
            resp = await client.get("/ready")
    finally:
        app.dependency_overrides.pop(get_session, None)

    assert resp.status_code == 200
    assert resp.json()["ready"] is True


@pytest.mark.asyncio
async def test_health_components_keys():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/health")
    components = resp.json()["components"]
    assert "api" in components
    assert "database" in components
    assert "redis" in components
    assert "chromadb" in components
