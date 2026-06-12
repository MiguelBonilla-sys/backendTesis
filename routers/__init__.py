from routers.analyze_router import router as analyze_router
from routers.auth_router import router as auth_router
from routers.eml_router import router as eml_router
from routers.health_router import router as health_router
from routers.incidents_router import router as incidents_router

__all__ = [
    "analyze_router",
    "auth_router",
    "eml_router",
    "health_router",
    "incidents_router",
]
