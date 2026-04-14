from functools import lru_cache
import os
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


def _running_in_container() -> bool:
    return (
        Path("/.dockerenv").exists()
        or Path("/run/.containerenv").exists()
        or os.getenv("container") == "podman"
    )


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # App
    APP_ENV: str = "development"
    DEBUG: bool = False
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "chrome-extension://*"]
    # Host-side path used by compose bind mounts (not used by app runtime logic).
    PODMAN_HOST_DATA_DIR: str = "D:/Podman/backendTesis"

    # PostgreSQL
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/phishing_detector"

    # ChromaDB
    CHROMADB_HOST: str = "localhost"
    CHROMADB_PORT: int = 8001

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_TTL: int = 3600

    # LlamaStack
    LLAMASTACK_URL: str = "http://localhost:5001"
    LLAMASTACK_MODEL: str = "ibm-granite/granite-3.3-8b-instruct-GGUF"

    # TI APIs
    VIRUSTOTAL_API_KEY: str = ""
    URLSCAN_API_KEY: str = ""
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    WHOISXML_API_KEY: str = ""

    # JWT
    SECRET_KEY: str = "changeme-use-strong-secret-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # IDN Agent data files
    CONFUSABLES_PATH: str = "data/confusables.txt"
    DOMAIN_INDEX_PATH: str = "data/top1m.txt"


def _adapt_container_hosts(settings: Settings) -> None:
    """Map localhost endpoints to compose service names when running in container.

    This keeps .env as the single source of truth for local development while
    allowing the same values to work when backend runs inside podman compose.
    """
    if not _running_in_container():
        return

    settings.DATABASE_URL = (
        settings.DATABASE_URL
        .replace("@localhost:", "@postgres:")
        .replace("@127.0.0.1:", "@postgres:")
    )
    settings.REDIS_URL = (
        settings.REDIS_URL
        .replace("redis://localhost:", "redis://redis:")
        .replace("redis://127.0.0.1:", "redis://redis:")
    )
    if settings.CHROMADB_HOST in {"localhost", "127.0.0.1"}:
        settings.CHROMADB_HOST = "chroma"
        settings.CHROMADB_PORT = 8000

    if settings.LLAMASTACK_URL.startswith("http://localhost:11434"):
        settings.LLAMASTACK_URL = settings.LLAMASTACK_URL.replace(
            "http://localhost", "http://ollama", 1
        )
    elif settings.LLAMASTACK_URL.startswith("http://127.0.0.1:11434"):
        settings.LLAMASTACK_URL = settings.LLAMASTACK_URL.replace(
            "http://127.0.0.1", "http://ollama", 1
        )
    elif settings.LLAMASTACK_URL.startswith("http://localhost:5001"):
        settings.LLAMASTACK_URL = settings.LLAMASTACK_URL.replace(
            "http://localhost", "http://llamastack", 1
        )
    elif settings.LLAMASTACK_URL.startswith("http://127.0.0.1:5001"):
        settings.LLAMASTACK_URL = settings.LLAMASTACK_URL.replace(
            "http://127.0.0.1", "http://llamastack", 1
        )


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    _adapt_container_hosts(settings)
    return settings


settings = get_settings()
