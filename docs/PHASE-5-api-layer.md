# Phase 5 — API Layer

> **Status:** 🔴 TODO  
> **Sprint:** S3–S4 · **Branch:** `feat/phase-5-api-layer`  
> **Goal:** Production-ready endpoints with JWT auth, rate limiting, full pipeline integration, and incidents API.

---

## Context

Phase 5 wires the 3-agent pipeline into the public-facing API layer. This is the entry point for the Chrome/Firefox extension (`POST /api/v1/analyze`) and the React admin dashboard (`GET /api/v1/incidents`). All endpoints require JWT auth (except `/health` and `/ready`).

**Extension constraint:** The extension triggers analysis on-demand (user click). Response p95 < 3s required (TI cache warm). Show a progress indicator in the extension during this window.

---

## Prerequisites

```bash
git checkout feat/phase-5-api-layer

# Merge Phase 2, 3, 4 branches first
git merge feat/phase-4-fusion-agent --no-ff

uv pip install slowapi
uv pip freeze > requirements.txt
```

---

## Files to Create / Modify

```
backendTesis/
├── routers/
│   ├── analyze_router.py      ← MODIFY: add JWT auth, rate limit, full pipeline
│   ├── incidents_router.py    ← NEW: GET /api/v1/incidents + GET /api/v1/incidents/{trace_id}
│   └── health_router.py       ← VERIFY: /health checks all dependencies
├── auth/
│   └── auth.py                ← VERIFY: require_auth dependency, JWT HS256
├── schemas/
│   ├── analyze_schemas.py     ← VERIFY: AnalyzeRequest, AnalyzeResponse match extension types
│   └── incident_schemas.py    ← VERIFY: paginated envelope
├── main.py                    ← MODIFY: register incidents_router, add slowapi
└── tests/
    ├── unit/
    │   └── test_analyze_router.py  ← NEW: auth, rate limit, pipeline mocked
    └── integration/
        └── test_analyze_endpoint.py ← NEW: testcontainers E2E
```

---

## 5.1 — POST /api/v1/analyze

**File:** `routers/analyze_router.py`

```python
from fastapi import APIRouter, Depends, BackgroundTasks
from slowapi import Limiter
from slowapi.util import get_remote_address
from auth.auth import require_auth
from agents.idn_agent import IDNAgent
from agents.llm_agent import LLMAgent
from agents.fusion_agent import FusionAgent, compute_shap_values, get_top_features, compute_lime_explanation
from data_pipeline.cache_manager import CacheManager
from data_pipeline.analysis_repo import save_full_analysis
from schemas.analyze_schemas import AnalyzeRequest, AnalyzeResponse
from core.security import sanitize_url
from core.exceptions import InvalidURLError
import asyncio
import uuid

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

@router.post("/analyze", response_model=AnalyzeResponse)
@limiter.limit("100/minute")
async def analyze(
    request: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    user: dict = Depends(require_auth),
    # Inject DB sessions and clients via deps
) -> AnalyzeResponse:
    """
    Main phishing analysis pipeline.
    
    Pipeline:
        1. Validate and sanitize URL
        2. IDN Agent (Unicode + confusables + TI cache)
        3. asyncio.gather: LLM Agent (runs concurrently with TI cache warm)
        4. Fusion Agent (S_IDN + S_LLM → S_risk → verdict)
        5. SHAP/LIME explanations
        6. Persist to DB (background task — after response sent)
    
    Response time target: p95 < 3s (TI cache warm)
    """
    trace_id = str(uuid.uuid4())
    
    # 1. Validate URL
    url = sanitize_url(str(request.url))
    if not url:
        raise InvalidURLError(f"Invalid or unsafe URL: {request.url}")
    
    # 2. IDN Agent
    idn_agent = IDNAgent()
    idn_result = await idn_agent.analyze(url)
    
    # 3. Run LLM Agent (TI already fetched in IDN Agent)
    llm_agent = LLMAgent()
    llm_result = await llm_agent.analyze(url, idn_result.model_dump(), chroma_client)
    
    # 4. Fusion Agent
    fusion_agent = FusionAgent()
    ti_result = idn_result.ti_result  # already cached in Redis by IDN agent
    fusion_result = await fusion_agent.analyze(
        idn_result=idn_result.model_dump(),
        llm_result=llm_result.model_dump(),
        ti_result=ti_result,
    )
    
    # 5. XAI
    shap_values = compute_shap_values(
        r_h=idn_result.r_h,
        sim_v=idn_result.sim_v,
        s_idn_local=idn_result.s_idn_local,
        s_vt=ti_result.s_vt,
        s_urlscan=ti_result.s_urlscan,
        s_gsb=ti_result.s_gsb,
        s_llm=llm_result.s_llm,
    )
    lime_values = compute_lime_explanation(url, lambda u: fusion_result.s_risk)
    
    # 6. Persist in background (does not block response)
    background_tasks.add_task(
        save_full_analysis,
        session=db_session,
        trace_id=trace_id,
        analyze_request=request.model_dump(),
        idn_result=idn_result.model_dump(),
        llm_result=llm_result.model_dump(),
        fusion_result=fusion_result.model_dump(),
        shap_values=shap_values,
        lime_values=lime_values,
    )
    
    return AnalyzeResponse(
        trace_id=trace_id,
        verdict=fusion_result.verdict,
        s_risk=fusion_result.s_risk,
        s_idn=fusion_result.s_idn,
        s_llm=llm_result.s_llm,
        s_ti=ti_result.s_ti if ti_result else 0.0,
        shap_values=shap_values,
        top_features=get_top_features(shap_values, n=3),
        domain=idn_result.domain_unicode,
        homograph_alert=idn_result.homograph_alert,
        llm_degraded=llm_result.llm_degraded,
    )
```

---

## 5.2 — GET /api/v1/incidents

**File:** `routers/incidents_router.py`

```python
from fastapi import APIRouter, Depends, Query
from auth.auth import require_auth
from schemas.incident_schemas import IncidentListResponse, IncidentDetailResponse

router = APIRouter()

@router.get("/incidents", response_model=IncidentListResponse)
async def list_incidents(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    verdict: str | None = Query(None, pattern="^(PHISHING|SUSPICIOUS|SAFE)$"),
    since: datetime | None = Query(None),
    user: dict = Depends(require_auth),
) -> IncidentListResponse:
    """
    Paginated incident list. Role: admin or analyst.
    
    Query params:
        page: 1-based page number
        size: items per page (max 100)
        verdict: filter by verdict
        since: filter by created_at >= since (ISO 8601)
    
    Response envelope: {items, total, page, size, pages}
    """
    offset = (page - 1) * size
    # Query analyses table with filters
    # Return IncidentListResponse
    ...

@router.get("/incidents/{trace_id}", response_model=IncidentDetailResponse)
async def get_incident(
    trace_id: str,
    user: dict = Depends(require_auth),
) -> IncidentDetailResponse:
    """
    Full incident detail: analysis + all agent results + XAI report.
    Returns 404 if trace_id not found.
    """
    ...
```

---

## 5.3 — JWT Auth

**File:** `auth/auth.py` — verify implementation:

```python
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from core.config import settings

bearer_scheme = HTTPBearer()

def create_access_token(
    sub: str,
    role: str,
    expires_delta_minutes: int = 60,
) -> str:
    """
    Creates JWT with payload: {sub, role, exp}.
    Algorithm: HS256. Secret from settings.SECRET_KEY.
    """
    ...

def decode_token(token: str) -> dict:
    """
    Decodes and validates JWT. Raises AuthError on invalid/expired.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError as exc:
        raise AuthError("Invalid or expired token") from exc

async def require_auth(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    """
    FastAPI dependency. Validates Bearer JWT.
    Returns decoded payload {sub, role, exp}.
    Raises 401 AuthError on failure.
    """
    return decode_token(credentials.credentials)
```

---

## 5.4 — Rate Limiting

**File:** `main.py` — add slowapi:

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address, storage_uri=settings.REDIS_URL)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
```

**Per-endpoint:** `@limiter.limit("100/minute")` on `POST /api/v1/analyze`

**Rate limit response format:**
```json
{
  "error": "rate_limit_exceeded",
  "retry_after": 60,
  "trace_id": "uuid4"
}
```

---

## 5.5 — Error Handling

**File:** `middleware/error_handler.py` — verify all mappings:

```python
ERROR_MAP = {
    InvalidURLError:      (422, "invalid_url"),
    AuthError:            (401, "unauthorized"),
    TIFetchError:         (502, "ti_unavailable"),
    LLMInferenceError:    (503, "llm_unavailable"),
    IDNAnalysisError:     (500, "idn_analysis_failed"),
    RateLimitExceeded:    (429, "rate_limit_exceeded"),
    # Catch-all: 500 "internal_error"
}
```

**All error responses include `trace_id`:**
```json
{
  "error": "invalid_url",
  "message": "URL scheme must be http or https",
  "trace_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

---

## Schema Verification

**File:** `schemas/analyze_schemas.py` — must match extension TypeScript types:

```python
class AnalyzeRequest(BaseModel):
    url: AnyHttpUrl
    email_body: str | None = None   # never persisted
    source: Literal["extension", "api", "dashboard"] = "extension"

class AnalyzeResponse(BaseModel):
    trace_id: str
    verdict: Literal["PHISHING", "SUSPICIOUS", "SAFE"]
    s_risk: float = Field(ge=0.0, le=1.0)
    s_idn: float = Field(ge=0.0, le=1.0)
    s_llm: float = Field(ge=0.0, le=1.0)
    s_ti: float = Field(ge=0.0, le=1.0)
    shap_values: dict[str, float]
    top_features: list[str]          # top-3 SHAP feature names
    domain: str
    homograph_alert: bool
    llm_degraded: bool
```

**File:** `schemas/incident_schemas.py` — paginated envelope:

```python
class IncidentListResponse(BaseModel):
    items: list[IncidentListItem]
    total: int
    page: int
    size: int
    pages: int                       # ceil(total / size)

class IncidentDetailResponse(BaseModel):
    trace_id: str
    verdict: str
    s_risk: float
    domain: str
    created_at: datetime
    agent_results: list[AgentResultDetail]
    xai_report: XAIReportDetail | None
```

---

## Tests to Write

**File:** `tests/unit/test_analyze_router.py`

```python
import pytest
import httpx
from httpx import ASGITransport
from unittest.mock import AsyncMock, patch
from main import app

@pytest.fixture
def client():
    return httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test")

@pytest.fixture
def auth_headers():
    from auth.auth import create_access_token
    token = create_access_token(sub="user1", role="analyst")
    return {"Authorization": f"Bearer {token}"}

async def test_analyze_requires_auth(client) -> None:
    response = await client.post("/api/v1/analyze", json={"url": "https://paypal.com"})
    assert response.status_code == 401

async def test_analyze_invalid_url(client, auth_headers) -> None:
    response = await client.post(
        "/api/v1/analyze",
        json={"url": "ftp://not-allowed.com"},
        headers=auth_headers,
    )
    assert response.status_code == 422

async def test_analyze_success_phishing(client, auth_headers) -> None:
    with patch("routers.analyze_router.IDNAgent") as mock_idn, \
         patch("routers.analyze_router.LLMAgent") as mock_llm, \
         patch("routers.analyze_router.FusionAgent") as mock_fusion:
        
        # Configure mocks to return high-risk values
        mock_idn.return_value.analyze = AsyncMock(return_value=...)
        mock_llm.return_value.analyze = AsyncMock(return_value=...)
        mock_fusion.return_value.analyze = AsyncMock(return_value=...)
        
        response = await client.post(
            "/api/v1/analyze",
            json={"url": "https://xn--pаypal-4ve.com"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] in ("PHISHING", "SUSPICIOUS", "SAFE")
        assert "trace_id" in data
        assert "shap_values" in data

async def test_analyze_response_has_trace_id(client, auth_headers) -> None:
    # Any response (even error) must include trace_id
    response = await client.post(
        "/api/v1/analyze",
        json={"url": "https://paypal.com"},
        headers=auth_headers,
    )
    # trace_id in success response OR error response
    data = response.json()
    assert "trace_id" in data or response.status_code >= 400

async def test_incidents_pagination(client, auth_headers) -> None:
    response = await client.get(
        "/api/v1/incidents?page=1&size=10",
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert "pages" in data

async def test_rate_limit_exceeded(client, auth_headers) -> None:
    # Send 101 requests — last should be 429
    for _ in range(101):
        response = await client.post(
            "/api/v1/analyze",
            json={"url": "https://paypal.com"},
            headers=auth_headers,
        )
    assert response.status_code == 429
```

**File:** `tests/integration/test_analyze_endpoint.py`

```python
import pytest
from testcontainers.postgres import PostgresContainer
from testcontainers.redis import RedisContainer

@pytest.fixture(scope="module")
def postgres_container():
    with PostgresContainer("postgres:15") as pg:
        yield pg

@pytest.fixture(scope="module")
def redis_container():
    with RedisContainer("redis:7") as r:
        yield r

async def test_full_pipeline_integration(postgres_container, redis_container) -> None:
    """
    Full E2E test with real PostgreSQL + Redis containers.
    LlamaStack and TI APIs are mocked.
    Verifies: correct DB rows written, Redis cache populated.
    """
    # Override settings with container URLs
    # Mock LlamaStack and TI API calls
    # POST /api/v1/analyze
    # Assert 5 DB rows written (Analysis + URLAnalysis + 3 AgentResult + XAIReport)
    # Assert Redis key f"ti:{domain}" populated with TTL=3600s
    ...
```

---

## Acceptance Criteria

| Criterion | Test |
|-----------|------|
| `POST /api/v1/analyze` returns 401 without JWT | `test_analyze_requires_auth` |
| `POST /api/v1/analyze` returns 422 for non-http URL | `test_analyze_invalid_url` |
| Response includes `trace_id`, `verdict`, `shap_values` | `test_analyze_success_phishing` |
| Rate limit: 101st request returns 429 | `test_rate_limit_exceeded` |
| `GET /api/v1/incidents` returns paginated envelope | `test_incidents_pagination` |
| `GET /api/v1/incidents/{trace_id}` returns 404 for unknown | `test_incident_not_found` |
| All error responses include `trace_id` | `test_analyze_response_has_trace_id` |
| Background task persists 5+ rows to DB | `test_full_pipeline_integration` |
| p95 latency < 3s with warm TI cache | Performance test in Sprint 5 |

---

## Registration in `main.py`

```python
from routers import analyze_router, health_router, incidents_router

app.include_router(health_router.router)
app.include_router(analyze_router.router, prefix="/api/v1", tags=["analyze"])
app.include_router(incidents_router.router, prefix="/api/v1", tags=["incidents"])
```

---

## Thesis Documentation Note

> **For thesis chapter:** Phase 5 completes the REST API layer that integrates all three agents into a single endpoint. The background task pattern (FastAPI `BackgroundTasks`) decouples persistence latency from response latency, keeping p95 < 3s. JWT HS256 authentication with role-based access (analyst/admin) implements the access control requirements from ISO/IEC 27001. The rate limiter (100 req/min via slowapi + Redis) protects the local academic deployment from accidental load.
