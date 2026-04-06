---
module: backendTesis
type: implementation-plan
sprint_scope: 0–6
coverage_target: 90%
stack: FastAPI 0.115.x · Python 3.11 · LlamaStack 0.2.x · PostgreSQL 15 · ChromaDB 0.5.x · Redis 7
last_updated: 2026-03-30
---

# Backend Plan — IDN Homograph Phishing Detector API

## Status Legend
- 🔴 TODO — not started
- 🟡 IN PROGRESS — actively being worked
- 🟢 DONE — complete + tests passing
- ⏸ BLOCKED — waiting on dependency

## Sprint / Phase Map

| Phase | Sprint | Description | Branch |
|-------|--------|-------------|--------|
| 1 | S0 | Core Setup & Scaffolding | `feat/phase-1-core-setup` |
| 2 | S1 | IDN Agent | `feat/phase-2-idn-agent` |
| 3 | S2 | LLM Agent + ChromaDB RAG | `feat/phase-3-llm-agent` |
| 4 | S3 | Fusion Agent + TI Integration | `feat/phase-4-fusion-agent` |
| 5 | S3–S4 | API Layer | `feat/phase-5-api-layer` |
| 6 | S1–S6 | Testing (continuous) | merged into each feature branch |

---

## Phase 1 — Core Setup & Scaffolding 🔴
> Sprint 0 · Branch: `feat/phase-1-core-setup`
> Goal: runnable skeleton that connects to all data stores and passes health check

### 1.1 Project structure + dependencies 🔴
- Create `requirements.txt` with pinned versions:
  - `fastapi==0.115.*`, `uvicorn[standard]`, `pydantic-settings>=2`, `asyncpg`, `sqlalchemy[asyncio]>=2`
  - `chromadb==0.5.*`, `redis[hiredis]>=5`, `llama-stack-client==0.2.*`
  - `shap>=0.46`, `lime>=0.5`, `sentence-transformers`
  - `pytest>=8`, `pytest-asyncio`, `pytest-cov`, `respx`, `testcontainers[postgresql,redis]`
  - `ruff`, `black`, `bandit`
- Create `Dockerfile` (multi-stage: builder + runtime, non-root user)
- Create `.env.example` with all required keys (no real values)

**Acceptance criteria:**
- `docker build -t backend .` succeeds
- `pip install -r requirements.txt` exits 0

### 1.2 App factory + config 🔴
- `src/core/config.py` — Pydantic `BaseSettings` loading from env:
  - DB URLs (postgres, chromadb, redis)
  - TI API keys (VT, URLScan, GSB, WhoisXML)
  - Fusion params (α=0.60, β=0.40, γ=0.50, θ=0.70, λ=0.30)
  - LlamaStack host/port/model name
- `src/main.py` — FastAPI app factory with lifespan context manager
- Startup: validate all required env vars, fail fast with clear message if missing

**Acceptance criteria:**
- App raises `ValueError` at startup if any required secret is absent
- All params loaded from env (0 hardcoded values)

### 1.3 Database clients 🔴
- `src/db/postgres.py` — async SQLAlchemy 2.x engine + session factory
- `src/db/chromadb_client.py` — ChromaDB async client, initialize 3 collections:
  - `email_embeddings` (all-MiniLM-L6-v2, 384d)
  - `idn_patterns` (all-MiniLM-L6-v2, 384d)
  - `ti_signals` (text-embedding-3-small, 1536d)
- `src/db/redis_client.py` — aioredis client, TI cache helpers: `get_ti_cache(domain)`, `set_ti_cache(domain, data)`

**Acceptance criteria:**
- All clients connect on startup
- Missing DB → startup fails with descriptive error
- Redis cache key = `ti:{2LD}`, TTL=3600s

### 1.4 Shared models 🔴
- `src/core/models.py` — Pydantic v2 schemas:
  - `AnalyzeRequest`: `url: str`, `email_sha256: str`, `email_id: UUID`
  - `AnalyzeResponse`: `verdict: Literal["SAFE","SUSPICIOUS","PHISHING"]`, `s_risk: float`, `s_idn: float`, `s_llm: float`, `shap_values: dict[str,float]`, `trace_id: UUID`
  - `IncidentRecord`, `AgentResult`, `TIResult`
- `src/core/security.py` — API key middleware + rate limiter (slowapi)

**Acceptance criteria:**
- All models have field-level validators
- Schemas match extension TypeScript types (reviewed against frontendTesis/src/types/)

### 1.5 Health endpoint 🔴
- `src/api/v1/health.py` — `GET /health` returns DB/cache/LlamaStack connectivity status

**Acceptance criteria:**
- Returns 200 + `{"status":"ok","postgres":true,"redis":true,"llamastack":true}` when all up
- Returns 503 if any dependency down

---

## Phase 2 — IDN Agent 🔴
> Sprint 1 · Branch: `feat/phase-2-idn-agent`
> Goal: full 5-stage IDN detection with TI enrichment, Redis caching, unit tests ≥90%

### 2.1 Unicode normalization + Punycode decoding 🔴
- `src/agents/idn_agent.py::normalize_domain(url) -> str`
  - Extract 2LD from URL (tldextract)
  - Apply Unicode NFC normalization
  - Detect `xn--` prefix → decode with `encodings.idna`
  - Return both unicode and ASCII form

**Acceptance criteria:**
- `normalize_domain("https://xn--pple-43d.com")` → `{"unicode":"äpple.com","ascii":"xn--pple-43d.com"}`
- Handles malformed URLs gracefully (returns None, not raises)

### 2.2 TR#39 confusable detection 🔴
- Load UTF-8 confusables catalog from `data/confusables.txt` (Unicode TR#39) at module import
- `detect_confusables(domain_unicode: str) -> list[ConfusableChar]`
  - Returns list of chars where a lookalike exists in a different script
  - Flag Cyrillic, Greek, Armenian, CJK mixed with Latin

**Dependencies:** `data/confusables.txt` downloaded in Phase 4 of infraTesis

**Acceptance criteria:**
- `detect_confusables("pаypal.com")` (Cyrillic 'а') → `[ConfusableChar(char='а', position=1, script='Cyrillic', lookalike='a')]`
- Pure Latin domains → empty list

### 2.3 Homograph ratio 🔴
- `compute_homograph_ratio(domain_2ld: str, confusables: list) -> float`
  - `r_h = len(confusables) / len(domain_2ld)`
  - Min-max clamped to [0.0, 1.0]
- Alert threshold: `r_h ≥ 0.30`

**Acceptance criteria:**
- `r_h` = 0.0 for clean domain
- `r_h` ≥ 0.30 triggers `HomographAlert` flag in result

### 2.4 Visual similarity vs top-1M index 🔴
- Load Tranco/Majestic top-1M list at startup (from Redis or local file)
- `compute_visual_similarity(domain_2ld: str, confusables: list) -> float`
  - Edit distance with substitution cost = 0 for confusable pairs
  - `sim_v = 1 - edit_distance(d, d_ref) / max(len(d), len(d_ref))`
  - Compare against top-1000 closest candidates (BK-tree or sorted prefix filter)

**Acceptance criteria:**
- `compute_visual_similarity("pаypal", confusables)` vs "paypal" → `sim_v ≥ 0.95`
- Runs in <100ms for single domain

### 2.5 Local IDN score 🔴
- `compute_s_idn_local(r_h: float, sim_v: float, beta: float = 0.40) -> float`
  - `S_IDN_local = β*r_h + (1-β)*sim_v`

**Acceptance criteria:**
- Returns float in [0.0, 1.0]
- Configurable β from env/config (not hardcoded)

### 2.6 TI API clients 🔴
- `src/agents/ti_clients.py`:
  - `VirusTotalClient.check_domain(domain) -> float` — returns normalized [0,1] malicious score
  - `URLScanClient.submit_and_poll(url) -> float` — submit scan, poll for result, return verdict score
  - `GoogleSafeBrowsingClient.check_url(url) -> float`
  - `WhoisXMLClient.get_domain_age(domain) -> int` (days)
- All clients: respect rate limits (VT 500/day, URLScan 100/day, GSB 10k/day)
- All clients: raise `TIClientError` on API failure (never silently return 0)

**Acceptance criteria:**
- All clients mocked in unit tests (never call real APIs in tests)
- Rate limit exceeded → `RateLimitError` raised
- Network timeout → `TIClientError` raised

### 2.7 TI aggregation + Redis cache 🔴
- `aggregate_ti_scores(domain: str, vt: float, urlscan: float, gsb: float) -> float`
  - `S_TI = 0.50*S_VT + 0.30*S_URLScan + 0.20*S_GSB`
  - Weights loaded from config (not hardcoded)
- `get_or_fetch_ti(domain: str) -> TIResult`:
  - Check Redis: `ti:{domain}` → return cached if hit
  - On miss: call TI APIs concurrently with `asyncio.gather`
  - Store result in Redis with TTL=3600s

**Acceptance criteria:**
- Cache hit → no TI API calls made
- Cache miss → all 3 APIs called concurrently (not sequentially)
- S_TI clamped to [0.0, 1.0]

### 2.8 IDN Agent orchestration 🔴
- `IDNAgent.analyze(url: str) -> IDNResult` (stateless per request)
  - Runs steps 2.1–2.7
  - Returns: `s_idn_local`, `s_ti`, `s_idn`, `confusables`, `r_h`, `sim_v`, `domain_unicode`, `domain_ascii`

**Acceptance criteria:**
- Agent is stateless (no instance state between calls)
- Test: mock TI clients, assert full result structure

---

## Phase 3 — LLM Agent + ChromaDB RAG 🔴
> Sprint 2 · Branch: `feat/phase-3-llm-agent`
> Goal: LlamaStack inference with RAG context, returns S_LLM + reasoning trace

### 3.1 ChromaDB RAG context retrieval 🔴
- `src/db/chromadb_client.py::get_similar_emails(embedding, k=3) -> list[EmailChunk]`
- `src/db/chromadb_client.py::get_idn_pattern_context(domain, k=3) -> list[IDNPattern]`
- Cosine similarity search, top-k=3 chunks injected as context

**Acceptance criteria:**
- Returns empty list if collection empty (no crash)
- Embedding model: all-MiniLM-L6-v2 (sentence-transformers)

### 3.2 Prompt template 🔴
- `src/agents/llm_agent.py::build_prompt(url, domain_analysis, rag_context) -> str`
  - System prompt: role as phishing detection expert
  - Context injection: top-3 similar email patterns from ChromaDB
  - Task: score URL phishing probability as float [0.0, 1.0] + brief reasoning
  - Output format: JSON `{"s_llm": 0.87, "reasoning": "..."}`

**Acceptance criteria:**
- Prompt always < 4096 tokens (truncate RAG context if needed)
- Prompt includes IDN analysis summary for LLM awareness

### 3.3 LlamaStack inference 🔴
- `LLMAgent.analyze(url: str, idn_result: IDNResult) -> LLMResult`
  - Call LlamaStack API: `POST /inference/chat_completion`
  - Model: `Llama-3.1-8B-Instruct-GGUF`
  - Parse JSON response, extract `s_llm` float
  - On parse failure: `s_llm = 0.5` (neutral) + log warning

**Acceptance criteria:**
- Agent is stateless per request
- LlamaStack timeout (5s) → fallback `s_llm = 0.5` + flag `llm_degraded=true` in response
- Raw LlamaStack response stored in `agent_results` table for debugging

### 3.4 Response parsing + validation 🔴
- `parse_llm_response(raw: str) -> LLMResult`
  - JSON extraction with regex fallback
  - Validate `s_llm ∈ [0.0, 1.0]`

---

## Phase 4 — Fusion Agent + TI Integration 🔴
> Sprint 3 · Branch: `feat/phase-4-fusion-agent`
> Goal: 3-step late fusion, SHAP/LIME XAI, PostgreSQL persistence

### 4.1 Fusion formula implementation 🔴
- `FusionAgent.fuse(idn_result, llm_result, config) -> FusionResult`
  - Step 1: `S_IDN = α*S_IDN_local + (1-α)*S_TI` (α=0.60)
  - Step 2: `S_risk = γ*S_IDN + (1-γ)*S_LLM` (γ=0.50)
  - Step 3: verdict = PHISHING if `S_risk ≥ θ` (θ=0.70), SUSPICIOUS if `S_risk ≥ 0.40`, else SAFE
  - All params from config (ConfigMap / env)

**Acceptance criteria:**
- `s_risk ∈ [0.0, 1.0]`
- Verdict thresholds match dashboard color coding

### 4.2 SHAP explanation 🔴
- `compute_shap_values(features: dict[str,float]) -> dict[str,float]`
  - Features: `r_h`, `sim_v`, `s_ti_vt`, `s_ti_urlscan`, `s_ti_gsb`, `s_llm`, `domain_age_days`
  - Use `shap.LinearExplainer` or tree explainer if model fitted
  - Return top-5 SHAP values as `dict[feature_name, shap_value]`

**Acceptance criteria:**
- SHAP dict always has exactly the feature keys defined
- Values are floats (positive = pushes toward PHISHING)

### 4.3 LIME explanation 🔴
- `compute_lime_explanation(url, predict_fn) -> dict[str,float]`
  - LIME text explainer on URL string
  - Return top-5 token attributions
- Used as secondary XAI method (SHAP primary, LIME secondary)

### 4.4 PostgreSQL persistence 🔴
- `src/db/repositories/analysis_repo.py`:
  - `save_analysis(analysis: AnalysisRecord) -> UUID`
  - `save_agent_results(trace_id, idn, llm, fusion)` — 3 rows in `agent_results`
  - `save_xai_report(trace_id, shap, lime)` — 1 row in `xai_reports`
- All writes in single transaction (rollback on any failure)

**Acceptance criteria:**
- `email_sha256` stored, never raw email body
- Parameterized queries only (no string interpolation)
- Transaction atomicity: all 5 rows written or none

---

## Phase 5 — API Layer 🔴
> Sprint 3–4 · Branch: `feat/phase-5-api-layer`
> Goal: production-ready endpoints with auth, rate limiting, CORS

### 5.1 POST /api/v1/analyze 🔴
- `src/api/v1/analyze.py`
- Request: `AnalyzeRequest` (validated Pydantic model)
- Pipeline: IDN Agent → LLM Agent → Fusion Agent (sequential, async)
- Response: `AnalyzeResponse` (verdict + scores + SHAP + trace_id)
- Persist to PostgreSQL after response sent (background task)

**Acceptance criteria:**
- End-to-end latency p95 < 3s (TI cache warm)
- Returns 422 on invalid URL
- Extension receives full response within timeout

### 5.2 GET /api/v1/incidents 🔴
- `src/api/v1/incidents.py`
- Query params: `page`, `limit` (max 100), `verdict`, `since`
- Returns paginated `IncidentRecord` list with total count

### 5.3 GET /api/v1/incidents/{trace_id} 🔴
- Full incident detail: all agent results + XAI report

### 5.4 Auth + rate limiting 🔴
- API key in `X-API-Key` header (from env)
- Rate limit: 100 req/min per API key (slowapi + Redis)
- CORS: allow extension origin + frontend origin (configured via env)

### 5.5 Error handling middleware 🔴
- 500 → `{"error":"internal_error","trace_id":null}` (never leak stack traces)
- 429 → `{"error":"rate_limit_exceeded","retry_after":60}`
- 503 → `{"error":"dependency_unavailable","dependency":"llamastack"}`

---

## Phase 6 — Testing (Continuous) 🔴
> Sprint 1–6 · Tests co-located in `tests/` · Target: 90% coverage

### 6.1 Unit tests — IDN Agent 🔴
- `tests/unit/test_idn_agent.py`
- Test confusable detection, homograph ratio, visual similarity, score formula
- Mock: TI clients, Redis, top-1M list (use fixture fixtures)
- Coverage: all branches of 5-stage algorithm

### 6.2 Unit tests — LLM Agent 🔴
- `tests/unit/test_llm_agent.py`
- Mock LlamaStack HTTP (respx)
- Test prompt construction, JSON parsing, fallback on timeout

### 6.3 Unit tests — Fusion Agent 🔴
- `tests/unit/test_fusion_agent.py`
- Test all formula branches, SHAP dict structure, LIME dict
- Parametrize with edge values (0.0, 0.5, 1.0 for each input)

### 6.4 Integration tests 🔴
- `tests/integration/test_analyze_endpoint.py`
- `testcontainers` for PostgreSQL + Redis
- Mock TI APIs + LlamaStack
- Assert DB rows written correctly

### 6.5 Coverage gate 🔴
- `pytest --cov=src --cov-fail-under=90`
- Add to CI (see infraTesis plan)

---

## Worktree Commands (this module)

```bash
# In backendTesis/
git checkout -b feat/phase-1-core-setup
git worktree add ../backendTesis-review feat/phase-2-idn-agent   # for PR review
git worktree add ../backendTesis-hotfix fix/                      # for emergency fixes

# List active worktrees
git worktree list

# Remove after PR merged
git worktree remove ../backendTesis-review
```

## Key Files Quick Reference

| File | Purpose |
|------|---------|
| `src/agents/idn_agent.py` | 5-stage IDN detection (core research contribution) |
| `src/agents/llm_agent.py` | LlamaStack inference + RAG |
| `src/agents/fusion_agent.py` | Late fusion + SHAP/LIME XAI |
| `src/agents/ti_clients.py` | VirusTotal, URLScan, GSB, WhoisXML clients |
| `src/core/config.py` | Pydantic settings (all params from env) |
| `src/core/models.py` | Pydantic v2 request/response schemas |
| `src/db/redis_client.py` | TI cache (key=`ti:{2LD}`, TTL=3600s) |
| `src/db/chromadb_client.py` | Vector store (3 collections) |
| `tests/unit/` | Unit tests per agent |
| `tests/integration/` | Testcontainer-based integration tests |
