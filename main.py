from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from agents.idn_agent import init_catalog, init_top1m
from core.config import settings
from core.logger import logger
from data_pipeline.top1m_loader import load_top1m
from middleware.error_handler import ErrorHandlerMiddleware
from models.chromadb_client import ensure_collections
from models.database import close_db, init_db
from models.redis_client import close_redis, init_redis
from routers import analyze_router, health_router


def _validate_startup_config() -> None:
    """Fail fast if required configuration is missing."""
    required = {
        "DATABASE_URL": settings.DATABASE_URL,
        "REDIS_URL": settings.REDIS_URL,
        "SECRET_KEY": settings.SECRET_KEY,
    }
    missing = [k for k, v in required.items() if not v or v == "changeme-use-strong-secret-in-production"]
    if "SECRET_KEY" in missing and settings.APP_ENV == "production":
        raise ValueError("SECRET_KEY must be set to a strong secret in production.")
    db_missing = [k for k in ["DATABASE_URL", "REDIS_URL"] if not required[k]]
    if db_missing:
        raise ValueError(f"Required config missing: {', '.join(db_missing)}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting BackendTesis...")
    _validate_startup_config()
    await init_db()
    await init_redis()
    try:
        ensure_collections()
    except Exception as exc:
        logger.warning(f"ChromaDB not available at startup: {exc}")
    init_catalog(settings.CONFUSABLES_PATH)
    top1m = load_top1m(settings.DOMAIN_INDEX_PATH, limit=1000)
    init_top1m(top1m)
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

app.add_middleware(ErrorHandlerMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router.router)
app.include_router(analyze_router.router, prefix="/api/v1", tags=["analyze"])


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
