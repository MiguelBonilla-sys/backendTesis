from routers.analyze_router import router as analyze_router
from routers.auth_router import router as auth_router
from routers.health_router import router as health_router
from routers.incidents_router import router as incidents_router
from routers.settings_router import router as settings_router

__all__ = ["analyze_router", "auth_router", "health_router", "incidents_router", "settings_router"]
