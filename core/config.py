from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/phishing_detector"

    # Redis
    REDIS_URL: str = "redis://localhost:6379"

    # ChromaDB
    CHROMADB_HOST: str = "localhost"
    CHROMADB_PORT: int = 8001

    # JWT
    JWT_SECRET_KEY: str = "change-me-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_EXPIRE_MINUTES: int = 1440  # 24h para refresh token
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD_HASH: str = ""  # hash bcrypt del password admin — se configura por env var

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Threat Intelligence API keys (empty = disabled)
    VIRUSTOTAL_API_KEY: str = ""
    URLSCAN_API_KEY: str = ""
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    WHOISXML_API_KEY: str = ""
    DOMAIN_AGE_SUSPICIOUS_DAYS: int = 30  # dominios < 30 días = sospechoso

    # LlamaStack
    LLAMASTACK_URL: str = "http://localhost:5000"
    LLAMASTACK_MODEL: str = "Llama-3.1-8B-Instruct-GGUF"

    # Data paths
    TOP1M_PATH: str = "data/top1m.csv"
    CONFUSABLES_PATH: str = "data/confusables.txt"

    # Cache
    TI_CACHE_TTL: int = 3600

    # Logging
    LOG_LEVEL: str = "INFO"


settings = Settings()
