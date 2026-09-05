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
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_EXPIRE_MINUTES: int = 15
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

    # LLM Gateway — inferencia generativa vía proveedor remoto OpenAI-compatible.
    # Reemplaza el modelo local (LlamaStack/Ollama): el backend ya no depende de
    # un modelo instalado. Default: OpenCode Go / DeepSeek V4 Flash Vision Exp.
    LLM_BASE_URL: str = "https://opencode.ai/zen/go/v1"
    LLM_API_KEY: str = ""
    LLM_MODEL: str = "deepseek-v4-flash-vision-exp"
    LLM_MODEL_FALLBACK: str = "deepseek-v4-flash"  # text-only, mismo proveedor/precio
    LLM_PROVIDER: str = "opencode-go"  # etiqueta para trazas
    LLM_REDACT_PROMPT: bool = True  # redactar PII del contenido antes de enviar
    LLM_MAX_TOKENS: int = 400  # holgura para el bloque REASON (150 truncaba)

    # IDN dominance (fusion): γ dinámico que silencia al LLM en ataques IDN.
    # El motivo original —"el LLM recibe Punycode y no decodifica homoglifos"—
    # es empíricamente débil con DeepSeek V4, que decodifica xn-- por sí solo y
    # recibe domain_unicode en el prompt. Se deja activable para re-calibración.
    IDN_DOMINANCE_ENABLED: bool = True

    # Conductor / orquestador — segunda pasada deliberada del LLM sobre casos
    # de la banda SUSPICIOUS (o señales en conflicto), con todas las salidas de
    # agentes + RAG. No altera s_risk (SHAP intacto): solo re-arbitra el
    # veredicto y enriquece las razones. Opt-in — el pipeline determinista sigue
    # siendo el camino primario y el baseline del eval de tesis.
    CONDUCTOR_ENABLED: bool = False

    # RAG que aprende de todo: ingesta CADA análisis a ChromaDB (no solo los de
    # s_risk alto), con tier de confianza en la metadata y una cuota de docs
    # auto-ingestados sin confirmación humana (anti-envenenamiento).
    LEARN_FROM_EVERY_ANALYSIS: bool = True
    AUTO_INGEST_QUOTA: float = 0.60  # fracción máx del corpus sin confirmar

    # Calibración online del vector de pesos de fusión {α, γ, w_hf}.
    # Kill-switch: default False — los pesos de tesis quedan congelados como
    # baseline del eval. Ver core/online_calibration.py.
    ONLINE_CALIBRATION_ENABLED: bool = False

    # HuggingFace
    # - URL model (pirocheto/…): sklearn/ONNX, se corre LOCAL vía onnxruntime.
    #   HF_URL_ONNX_PATH: ruta a un model.onnx bundleado (offline); vacío → se
    #   descarga de HF y se cachea en la primera llamada.
    # - Email model (cybersectony/…): transformers, vía Inference API (hf-inference),
    #   necesita HUGGINGFACE_API_KEY; sin key degrada a 0.5.
    HUGGINGFACE_API_KEY: str = ""
    HF_URL_MODEL: str = "pirocheto/phishing-url-detection"
    HF_URL_ONNX_PATH: str = ""
    HF_EMAIL_MODEL: str = "cybersectony/phishing-email-detection-distilbert_v2.4.1"

    # RAG embeddings (ChromaDB)
    # - "chroma"  → función por defecto de ChromaDB (ONNX all-MiniLM-L6-v2, 384d,
    #               inglés). Cero deps.
    # - "ollama"  → embedder local vía Ollama. Para el corpus español + homoglifos
    #               usar `embeddinggemma` (300M, 768d, 100+ idiomas, CPU, ~620 MB)
    #               o `paraphrase-multilingual` (278M, 384d — drop-in sin re-index).
    # OJO: ChromaDB fija la EF por colección — cambiar de provider requiere
    # colecciones nuevas o re-embeber (ver scripts/seed_chromadb.py).
    EMBED_PROVIDER: str = "chroma"
    EMBED_MODEL: str = "embeddinggemma"
    EMBED_BASE_URL: str = "http://localhost:11434"

    # Recuperación híbrida denso + BM25 léxico + RRF. Si `rank_bm25` no está o
    # la colección está vacía, cae a denso-solo sin ruido.
    RAG_HYBRID_ENABLED: bool = True

    # Rerank de los chunks recuperados con una llamada extra al LLM (DeepSeek).
    # Opt-in — suma 1 request por análisis. Sin cross-encoder local (no cabe en
    # 2 GB); el LLM-rerank alinea mejor con el razonamiento del LLM (Rao et al.).
    RAG_RERANK_ENABLED: bool = False

    # Límites de recuperación y contexto; el presupuesto se reparte entre fuentes.
    RAG_RETRIEVAL_TIMEOUT_S: float = 5.0
    RAG_CONTEXT_MAX_CHARS: int = 6000
    RAG_CHUNK_MAX_CHARS: int = 600

    # Data paths
    TOP1M_PATH: str = "data/top1m.txt"
    CONFUSABLES_PATH: str = "data/confusables.txt"

    # Cache
    TI_CACHE_TTL: int = 3600

    # Logging
    LOG_LEVEL: str = "INFO"


settings = Settings()
