from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings
from core.logger import logger
from models.database import close_db, init_db
from models.redis_client import close_redis, init_redis
from routers import (
    analyze_router,
    auth_router,
    eml_router,
    health_router,
    incidents_router,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting BackendTesis...")
    await init_db()
    await init_redis()

    # θ efectivo: última recalibración adaptativa persistida (T12)
    try:
        from core.calibration import load_effective_theta_from_db

        await load_effective_theta_from_db()
    except Exception as exc:
        logger.warning(f"effective_theta_load_failed: {exc}")

    yield
    logger.info("Shutting down BackendTesis...")
    await close_db()
    await close_redis()


app = FastAPI(
    title="BackendTesis API",
    description="IDN Homograph Phishing Detector — USB Bogotá 2026",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"https://.*\.ngrok-free\.(app|dev)",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(auth_router, prefix="/api/v1", tags=["auth"])
app.include_router(analyze_router, prefix="/api/v1", tags=["analyze"])
app.include_router(eml_router, prefix="/api/v1", tags=["analyze"])
app.include_router(incidents_router, prefix="/api/v1", tags=["incidents"])


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
