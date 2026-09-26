"""Health check router — GET /health."""

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: str
    timestamp: datetime
    version: str


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Endpoint de salud del servicio. No requiere autenticación."""
    return HealthResponse(
        status="ok",
        timestamp=datetime.now(UTC),
        version="1.0.0",
    )


@router.get("/ready")
async def readiness():
    """Essential stores/IDN gate readiness; unavailable RAG is explicit degradation."""
    import asyncio

    from fastapi.responses import JSONResponse

    from agents.idn_agent import idn_agent
    from models.chromadb_client import get_client
    from models.database import fetchrow
    from models.redis_client import get_redis

    async def check(kind: str) -> bool:
        try:
            async with asyncio.timeout(2.0):
                if kind == "postgres":
                    return await fetchrow("SELECT 1 AS ready") is not None
                if kind == "redis":
                    return bool(await get_redis().ping())
                await get_client().heartbeat()
                return True
        except Exception:
            return False

    postgres, redis, rag = await asyncio.gather(*(check(k) for k in ("postgres", "redis", "rag")))
    idn = idn_agent.ready and idn_agent.has_reference_knowledge
    ready = postgres and redis and idn
    return JSONResponse(
        status_code=200 if ready else 503,
        content={"status": "ready" if ready else "not_ready", "degraded": ready and not rag,
                 "checks": {"postgres": postgres, "redis": redis, "idn": idn, "rag": rag}},
    )
