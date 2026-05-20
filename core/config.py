from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # App
    APP_ENV: str = "development"
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/phishing_detector"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_TTL: int = 3600

    # ChromaDB
    CHROMADB_HOST: str = "localhost"
    CHROMADB_PORT: int = 8001

    # JWT
    SECRET_KEY: str = "changeme-use-strong-secret-in-production"
    JWT_SECRET_KEY: str = "changeme-use-strong-secret-in-production"
    ALGORITHM: str = "HS256"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_EXPIRE_MINUTES: int = 1440
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD_HASH: str = ""

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Rate Limiting
    RATE_LIMIT_ANALYZE: int = 100
    RATE_LIMIT_REPORT: int = 20

    # Threat Intelligence API keys
    VIRUSTOTAL_API_KEY: str = ""
    URLSCAN_API_KEY: str = ""
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    WHOISXML_API_KEY: str = ""
    DOMAIN_AGE_SUSPICIOUS_DAYS: int = 30

    # LlamaStack
    LLAMASTACK_URL: str = "http://localhost:5001"
    LLAMASTACK_MODEL: str = "Llama-3.1-8B-Instruct-GGUF"

    # Data paths
    TOP1M_PATH: str = "data/top1m.csv"
    CONFUSABLES_PATH: str = "data/confusables.txt"

    # Cache
    TI_CACHE_TTL: int = 3600

    # Logging
    LOG_LEVEL: str = "INFO"


settings = Settings()
