import pytest
import os

# Force 127.0.0.1 for windows stability against ::1/localhost ambiguity
os.environ["DATABASE_URL"] = "postgresql+asyncpg://postgres:postgres@127.0.0.1:5432/phishing_detector"
os.environ["REDIS_URL"] = "redis://127.0.0.1:6379/0"

from httpx import AsyncClient, ASGITransport
from main import app
from core.config import settings
from models.database import init_db, close_db
from models.redis_client import init_redis, close_redis

@pytest.fixture
def anyio_backend():
    return "asyncio"

@pytest.mark.asyncio
async def test_health_endpoint_integration():
    """Verify that /health reflects real service availability."""
    # Ensure settings are updated manually if they were already loaded
    from core.config import settings
    settings.DATABASE_URL = "postgresql+asyncpg://postgres:postgres@127.0.0.1:5432/phishing_detector"
    settings.REDIS_URL = "redis://127.0.0.1:6379/0"
    
    await init_db()
    await init_redis()
    
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.get("/health")
            assert response.status_code == 200
            data = response.json()
            
            if data["status"] != "ok":
                 print(f"Health check failed detail: {data}")
                 
            assert data["status"] == "ok"
    finally:
        await close_db()
        await close_redis()

@pytest.mark.asyncio
async def test_ready_endpoint_integration():
    """Simple integration check for overall readiness."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/ready")
        assert response.status_code == 200
        assert response.json()["ready"] is True
