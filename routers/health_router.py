from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import redis.asyncio as redis
import chromadb
from core.config import settings
from models.database import get_session
from schemas.analyze_schemas import HealthResponse
from core.logger import logger

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["health"])
async def health_check(
    db: AsyncSession = Depends(get_session),
) -> HealthResponse:
    """Verify that all components are up."""
    status_map = {
        "api": "ok",
        "database": "error",
        "redis": "error",
        "chromadb": "error",
        "llamastack": "ok", # Placeholder
    }

    # 1. DB
    try:
        await db.execute(text("SELECT 1"))
        status_map["database"] = "ok"
    except Exception as e:
        logger.error(f"Health: DB error: {e}")

    # 2. Redis
    try:
        r = redis.from_url(settings.REDIS_URL)
        await r.ping()
        status_map["redis"] = "ok"
    except Exception as e:
        logger.error(f"Health: Redis error: {e}")

    # 3. ChromaDB
    try:
        # Check heartbeat
        client = chromadb.HttpClient(host=settings.CHROMADB_HOST, port=settings.CHROMADB_PORT)
        client.heartbeat()
        status_map["chromadb"] = "ok"
    except Exception as e:
        logger.error(f"Health: Chroma error: {e}")

    overall = "ok" if all(v == "ok" for v in status_map.values()) else "error"

    return HealthResponse(
        status=overall,
        version="1.0.0",
        components=status_map,
    )


@router.get("/ready", tags=["health"])
async def readiness(db: AsyncSession = Depends(get_session)) -> dict:
    """Readiness probe."""
    try:
        await db.execute(text("SELECT 1"))
        return {"ready": True}
    except Exception:
        return {"ready": False}
