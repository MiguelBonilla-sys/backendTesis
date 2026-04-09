from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # App
    APP_ENV: str = "development"
    DEBUG: bool = False
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "chrome-extension://*"]

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
    LLAMASTACK_MODEL: str = "ollama/Llama-3.1-8B-Instruct-GGUF"

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


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
