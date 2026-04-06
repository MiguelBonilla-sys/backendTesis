# Phase 1 — Core Setup & Scaffolding

> **Status:** 🟢 DONE  
> **Sprint:** S0 · **Branch:** `feat/phase-1-core-setup`  
> **Goal:** Runnable skeleton that connects to all data stores and passes health check.

---

## Context

This phase establishes the entire project skeleton for the FastAPI backend of the IDN Homograph Phishing Detector thesis project. The layout is **flat** (no `src/` prefix) as required by FastAPI conventions.

**Stack:** FastAPI 0.115.x · Python 3.11 · SQLAlchemy 2.x async · ChromaDB 0.5.x · Redis 7 · python-jose JWT

---

## File Map

```
backendTesis/
├── main.py                        ✅ App factory + lifespan + middleware
├── Dockerfile                     ✅ Multi-stage, non-root appuser, HEALTHCHECK
├── requirements.txt               ✅ uv pip freeze output
├── pytest.ini                     ✅ asyncio_mode=auto, cov-fail-under=90
├── .env.example                   ✅ All required keys, no real values
├── core/
│   ├── config.py                  ✅ pydantic-settings BaseSettings + @lru_cache
│   ├── constants.py               ✅ ALPHA, BETA, GAMMA, THETA, TI weights, verdicts
│   ├── exceptions.py              ✅ Custom exception hierarchy
│   ├── logger.py                  ✅ get_logger() factory (structlog or logging)
│   └── security.py                ✅ sanitize_url, hash_email_body, extract_domain
├── models/
│   ├── database.py                ✅ async SQLAlchemy engine + init_db/close_db
│   ├── chromadb_client.py         ✅ Singleton HttpClient + ensure_collections()
│   ├── orm_models.py              ✅ 7 ORM tables (User, Analysis, URLAnalysis, etc.)
│   └── redis_client.py            ✅ Async Redis + init_redis/close_redis
├── middleware/
│   └── error_handler.py           ✅ ErrorHandlerMiddleware + trace_id
├── auth/
│   └── auth.py                    ✅ JWT HS256, create_access_token, require_auth
├── routers/
│   └── health_router.py           ✅ GET /health + GET /ready
├── schemas/
│   ├── analyze_schemas.py         ✅ AnalyzeRequest, AnalyzeResponse, IDNResult, etc.
│   └── incident_schemas.py        ✅ IncidentListResponse (paginated envelope)
├── utils/
│   └── url_parser.py              ✅ extract_domain, extract_2ld, is_valid_url
└── tests/
    ├── conftest.py                 ✅ Shared fixtures
    └── unit/
        ├── test_config.py          ✅ Settings defaults, constants, TI weight sum
        ├── test_health.py          ✅ /health and /ready endpoints
        ├── test_security.py        ✅ hash_email_body, sanitize_url, punycode
        └── test_url_parser.py      ✅ extract_domain, extract_2ld, is_valid_url
```

---

## Key Decisions

### Fusion Constants (`core/constants.py`)
```python
ALPHA: float = 0.60      # IDN local weight in S_IDN
BETA: float = 0.40       # r_h weight in S_IDN_local
GAMMA: float = 0.50      # IDN weight in S_risk
THETA: float = 0.70      # PHISHING threshold
LAMBDA: float = 0.30     # asymmetric loss penalty (FN 3x more costly)

TI_VIRUSTOTAL_WEIGHT: float = 0.50
TI_URLSCAN_WEIGHT: float = 0.30
TI_GSB_WEIGHT: float = 0.20

VERDICT_PHISHING = "PHISHING"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_SAFE = "SAFE"

CHROMADB_EMAIL_COLLECTION = "email_embeddings"
CHROMADB_IDN_COLLECTION = "idn_patterns"
CHROMADB_TI_COLLECTION = "ti_signals"

RAG_TOP_K: int = 3
LLAMASTACK_TIMEOUT_SECONDS: float = 5.0
```

### ORM Tables (`models/orm_models.py`)
7 tables: `users`, `analyses`, `url_analyses`, `agent_results`, `ti_cache`, `xai_reports`, `incidents`

Key index: `analyses(verdict, created_at DESC)` and `analyses(user_id, created_at DESC)`

### Startup Validation (`main.py`)
```python
def _validate_startup_config() -> None:
    # Raises ValueError if DATABASE_URL or REDIS_URL missing
    # Raises ValueError if SECRET_KEY == "changeme..." in production
```

### Error Middleware (`middleware/error_handler.py`)
- Every error response (including unhandled 500s) includes `trace_id: uuid4`
- Never leaks stack traces to client
- Maps: `InvalidURLError → 422`, `AuthError → 401`, `TIFetchError → 502`

---

## Acceptance Criteria (all passing)

```bash
# Health endpoints
curl http://localhost:8000/health  # → 200 {"status":"ok","components":{...}}
curl http://localhost:8000/ready   # → 200 {"ready":true}

# Tests
pytest tests/unit/test_config.py -v     # TI weights sum == 1.0
pytest tests/unit/test_health.py -v     # /health, /ready structure
pytest tests/unit/test_security.py -v   # hash_email_body, sanitize_url
pytest tests/unit/test_url_parser.py -v # extract_domain, is_valid_url
```

---

## Thesis Documentation Note

> **For thesis chapter:** Phase 1 establishes the infrastructure base. The 3-layer architecture (HTTP → Router → Agent) and privacy-preserving design (no email body stored, only SHA-256 hash) comply with Ley 1581/2012 (Colombia data protection).
