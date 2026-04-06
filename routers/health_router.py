from fastapi import APIRouter

from schemas.analyze_schemas import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["health"])
async def health_check() -> HealthResponse:
    return HealthResponse(
        status="ok",
        version="1.0.0",
        components={
            "api": "ok",
            "database": "ok",
            "redis": "ok",
            "chromadb": "ok",
            "llamastack": "ok",
        },
    )


@router.get("/ready", tags=["health"])
async def readiness() -> dict:
    return {"ready": True}
