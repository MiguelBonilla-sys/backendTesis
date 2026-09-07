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
    from agents.idn_agent import idn_agent
    from agents.llm_agent import llm_agent
    from core.llm_gateway import llm_gateway
    from models.chromadb_client import init_chromadb

    try:
        await init_redis()

        # El detector local necesita su catálogo y referencias antes de servir
        # solicitudes. Un fallo aquí debe impedir analizar con señales vacías.
        await idn_agent.initialize()
        if not idn_agent.ready or not idn_agent.has_reference_knowledge:
            raise RuntimeError("IDN agent did not initialize its reference knowledge")

        # ChromaDB es una dependencia recuperable: sin ella sigue disponible el
        # análisis, pero se informa expresamente que el RAG está degradado.
        try:
            await init_chromadb()
        except Exception as exc:
            logger.warning("rag_startup_degraded", error=str(exc))

        # θ + pesos efectivos: última calibración adaptativa persistida (T12).
        try:
            from core.calibration import load_effective_theta_from_db
            from core.online_calibration import load_effective_weights_from_db

            await load_effective_theta_from_db()
            await load_effective_weights_from_db()
        except Exception as exc:
            logger.warning("effective_calibration_load_failed", error=str(exc))

        # El gateway admite degradación neutral ante fallo de red.
        await llm_agent.initialize()
        yield
    finally:
        logger.info("Shutting down BackendTesis...")
        await close_db()
        await close_redis()
        await llm_gateway.aclose()


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
    allow_origin_regex=settings.CORS_ORIGIN_REGEX,
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
