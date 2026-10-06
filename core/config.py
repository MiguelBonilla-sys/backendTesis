from urllib.parse import urlsplit

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # App
    APP_ENV: str = "development"
    DEBUG: bool = False
    # Bound concurrent analysis work and total processing time per URL/email.
    ANALYSIS_CONCURRENCY: int = Field(default=8, ge=1, le=128)
    ANALYSIS_QUEUE_TIMEOUT_S: float = Field(default=10.0, gt=0, le=120)
    ANALYSIS_TIMEOUT_S: float = Field(default=45.0, gt=0, le=300)
    STORE_EMAIL_CONTENT: bool = False
    # /docs, /redoc y /openapi.json. En producción se apaga (hallazgo F32-01 de T32).
    API_DOCS_ENABLED: bool = True
    EMAIL_METADATA_RETENTION_DAYS: int = Field(default=30, ge=1, le=3650)

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/phishing_detector"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_TTL: int = 3600

    # ChromaDB — local (HTTP) o Chroma Cloud (si CHROMA_API_KEY está seteada → ssl + auth)
    CHROMADB_HOST: str = "localhost"
    CHROMADB_PORT: int = 8001
    CHROMADB_SSL: bool = False
    CHROMA_API_KEY: str = ""
    CHROMA_TENANT: str = "default_tenant"
    CHROMA_DATABASE: str = "default_database"

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

    # Cookies httpOnly del dashboard (además del token en el body, que usa la
    # extensión). SameSite=None + Secure porque el front puede servirse desde
    # un dominio *.vercel.app (cross-site real) — en dev estos dos se relajan
    # solos (ver auth_router._cookie_kwargs), no hace falta tocarlos localmente.
    # AUTH_COOKIE_DOMAIN: en prod, "mangel.dpdns.org" — Coolify (back-tesi.) y
    # Render (render.) están mapeados como subdominios de ESE dominio (ver
    # render.yaml / docker-compose.coolify.yml), así que comparten la cookie:
    # Redis debe compartirse para conservar sesiones en failover; si cambia,
    # hay que volver a iniciar sesión. Vacío = cookie
    # host-only (solo sirve para el dominio exacto que la puso).
    AUTH_COOKIE_DOMAIN: str = ""
    AUTH_COOKIE_SECURE: bool = True
    AUTH_COOKIE_SAMESITE: str = "none"

    # Registro self-service — solo correos institucionales USB
    ALLOWED_SIGNUP_DOMAINS: list[str] = ["usbbog.edu.co", "academia.usbbog.edu.co"]

    # Exact product/browser origins only. Extension IDs must be explicitly added.
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173", "http://localhost:3000",
        "https://dashdect.mangel.dpdns.org", "https://onboardingtes.mangel.dpdns.org",
        "chrome-extension://hpcgpdffecpcljmofigneicgkdfhplhf",
    ]

    @field_validator("CORS_ORIGINS")
    @classmethod
    def exact_cors_origins(cls, origins: list[str]) -> list[str]:
        for origin in origins:
            parsed = urlsplit(origin)
            if (
                "*" in origin
                or parsed.scheme not in {"https", "http", "chrome-extension", "moz-extension"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path or parsed.query or parsed.fragment
            ):
                raise ValueError("CORS_ORIGINS must contain exact origins without wildcards or paths")
            # Trigger validation of malformed ports rather than accepting inert entries.
            _ = parsed.port
        return origins

    # Rate limiting. Socket peer is authoritative unless an explicit proxy CIDR
    # is configured and the entire right-hand proxy chain is trusted.
    TRUSTED_PROXY_CIDRS: list[str] = []
    # Peticiones por IP cada 60 s. Antes RATE_LIMIT_ANALYZE/REPORT existían pero los routers
    # usaban números fijos (hallazgo de T35); ahora mandan estos valores.
    RATE_LIMIT_ANALYZE: int = 100
    RATE_LIMIT_ANALYZE_EMAIL: int = 30
    RATE_LIMIT_ANALYZE_BATCH: int = 20
    RATE_LIMIT_ANALYZE_EML: int = 10
    RATE_LIMIT_REPORT: int = 20
    RATE_LIMIT_INCIDENTS: int = 30
    RATE_LIMIT_FEEDBACK: int = 30
    RATE_LIMIT_REGISTER: int = 5  # por hora
    RATE_LIMIT_LOGIN_IP: int = 20
    RATE_LIMIT_LOGIN_IDENTITY: int = 10
    RATE_LIMIT_LOGIN_WINDOW_SECONDS: int = 300
    AUTH_HASH_CONCURRENCY: int = 4

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
    LLM_MAX_TOKENS: int = 800  # DeepSeek V4 antepone razonamiento; 400 truncaba antes del SCORE

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
    AUTO_INGEST_QUOTA: float = Field(default=0.60, ge=0.0, le=1.0)
    AUTO_INGEST_MAX_DOCUMENTS: int = Field(default=2000, ge=0)  # per collection
    AUTO_INGEST_RETENTION_DAYS: int = Field(default=30, ge=1, le=365)
    AUTO_INGEST_SCAN_LIMIT: int = Field(default=10000, ge=1)
    RAG_BM25_MAX_DOCUMENTS: int = Field(default=10000, ge=1)

    # Calibración online del vector de pesos de fusión {α, γ, w_hf}.
    # Kill-switch: default False — los pesos de tesis quedan congelados como
    # baseline del eval. Ver core/online_calibration.py.
    ONLINE_CALIBRATION_ENABLED: bool = False

    # Evaluation is explicit: frozen per-URL TI/RAG evidence, no learning or
    # adaptive calibration. Missing evidence aborts instead of consulting live TI.
    EVALUATION_MODE: bool = False
    EVALUATION_SNAPSHOT_PATH: str = ""

    # HuggingFace
    # - URL model (pirocheto/…): sklearn/ONNX, se corre LOCAL vía onnxruntime.
    #   HF_URL_ONNX_PATH: ruta a un model.onnx bundleado (offline); vacío → se
    #   descarga de HF y se cachea en la primera llamada.
    # - Email model (cybersectony/…): transformers, vía Inference API (hf-inference),
    #   necesita HUGGINGFACE_API_KEY; sin key degrada a 0.5.
    HUGGINGFACE_API_KEY: str = ""
    HF_URL_MODEL: str = "pirocheto/phishing-url-detection"
    # Commit pinneado del modelo ONNX — descarga reproducible (supply-chain).
    HF_URL_MODEL_REVISION: str = "44f3b19f705b52532e0aadf3d0d15dd892b8a2fb"
    HF_URL_ONNX_PATH: str = ""
    HF_EMAIL_MODEL: str = "cybersectony/phishing-email-detection-distilbert_v2.4.1"

    # RAG embeddings (ChromaDB)
    # - "chroma"  → función por defecto de ChromaDB (ONNX all-MiniLM-L6-v2, 384d,
    #               inglés). Cero deps.
    # - "ollama"  → embedder local vía Ollama. Para el corpus español + homoglifos
    #               usar `embeddinggemma` (300M, 768d, 100+ idiomas, CPU, ~620 MB)
    #               o `paraphrase-multilingual` (278M, 384d — drop-in sin re-index).
    # - "openai"  → endpoint remoto compatible con la API de OpenAI
    #               (`POST {EMBED_BASE_URL}/embeddings`). Sin modelo local: misma EF
    #               en Coolify y en Render sin correr Ollama en ninguno.
    #               EMBED_AUTH_SCHEME: "Bearer" (OpenAI) o "Key" (fal.run).
    # OJO: ChromaDB fija la EF por colección — cambiar de provider requiere
    # colecciones nuevas o re-embeber (ver scripts/seed_chromadb.py).
    EMBED_PROVIDER: str = "chroma"
    EMBED_MODEL: str = "embeddinggemma"
    EMBED_BASE_URL: str = "http://localhost:11434"
    EMBED_API_KEY: str = ""
    EMBED_AUTH_SCHEME: str = "Bearer"

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
    # Máx. de dominios del índice top-1M a cargar en el BK-tree al arrancar.
    # El default carga todo (~927k → build de varios minutos en CPU lenta).
    # Bajarlo acelera el arranque a costa de cobertura para dominios de rank alto.
    TOP1M_LIMIT: int = 1_000_000

    # Cache
    TI_CACHE_TTL: int = 3600

    # Logging
    LOG_LEVEL: str = "INFO"

    # Cifrado de campos forenses (AES-256-GCM). JSON {"kid": "<base64 de 32 bytes>"}.
    # Sin llaves configuradas los campos cifrados no se persisten (quedan NULL).
    FIELD_ENC_KEYS: str = ""
    FIELD_ENC_ACTIVE: str = ""

    # Correo saliente (Resend) y alertas tempranas.
    RESEND_API_KEY: str = ""
    RESEND_API_URL: str = "https://api.resend.com/emails"
    MAIL_FROM: str = ""
    MAIL_DRY_RUN: bool = False
    MAIL_TIMEOUT_S: float = Field(default=10.0, gt=0, le=60)
    ALERTS_ENABLED: bool = True
    ALERT_DAILY_CAP: int = Field(default=60, ge=0, le=1000)
    ALERT_DEDUPE_SECONDS: int = Field(default=3600, ge=60, le=86400)
    ALERT_FALLBACK_RECIPIENT: str = ""
    DASHBOARD_URL: str = "https://dashdect.mangel.dpdns.org"

    # MFA por OTP al correo para el rol base admin.
    MFA_ENABLED: bool = True
    MFA_OTP_TTL_SECONDS: int = Field(default=300, ge=60, le=900)
    MFA_MAX_ATTEMPTS: int = Field(default=5, ge=1, le=10)
    MFA_RESEND_COOLDOWN_SECONDS: int = Field(default=30, ge=5, le=300)
    MFA_CODES_PER_WINDOW: int = Field(default=5, ge=1, le=20)  # por cuenta cada 15 min
    OTP_DAILY_CAP: int = Field(default=40, ge=1, le=1000)

    # GeoIP local (DB-IP Lite, MMDB). Vacío = sin geolocalización.
    GEOIP_CITY_DB: str = ""
    GEOIP_ASN_DB: str = ""


settings = Settings()
