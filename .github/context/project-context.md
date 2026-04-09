# Project Context

<!-- AUTO-SYNC:START -->
## Auto Sync

- Last sync (UTC): 2026-04-09T03:10:13.654684Z
- Branch: feat/phase-1-core-setup
- Dirty entries: 20
- Dirty preview:
  - .github/auto-memory/dirty-files
  - .github/context/next-steps.md
  - .github/context/project-context.md
  - .github/context/project-history.md
  - .github/context/work-log.md
  - core/security.py
  - tests/unit/test_analyze_router.py
  - tests/unit/test_auth.py
  - tests/unit/test_cache_manager.py
  - tests/unit/test_fusion_agent.py
  - tests/unit/test_idn_agent.py
  - tests/unit/test_llm_agent.py
  - ... (+8 more)
<!-- AUTO-SYNC:END -->

## Objective

backendTesis is the backend API for IDN homograph phishing detection in the thesis system.

Main flow:

1. Validate and sanitize URL input.
2. Run IDN analysis.
3. Run LLM and TI retrieval concurrently.
4. Fuse scores into a final risk verdict.
5. Return structured response with explainability fields.

## Runtime architecture snapshot

- Entry point: main.py
- Primary route: routers/analyze_router.py
- Health route: routers/health_router.py
- Agents:
  - agents/idn_agent.py
  - agents/llm_agent.py
  - agents/fusion_agent.py
- Threat intel:
  - data_pipeline/cache_manager.py
  - data_pipeline/threat_intel.py
- Core config and constants:
  - core/config.py
  - core/constants.py
- Security helpers:
  - core/security.py
- Persistence clients:
  - models/database.py
  - models/redis_client.py
  - models/chromadb_client.py
- Schemas:
  - schemas/analyze_schemas.py
  - schemas/incident_schemas.py

## Hard constraints

- Keep async-first API and I/O.
- Keep agents stateless and per-request instantiated.
- Keep cache-first TI strategy.
- Keep verdict literals exactly: PHISHING, SUSPICIOUS, SAFE.
- Keep no-secret and no-raw-email persistence policy.
- Keep explainability shape stable for consumers.
- Keep test coverage at or above 90%.

## Planning sources

- docs/PLAN.md
- docs/PHASE-1-core-setup.md
- docs/PHASE-2-idn-agent.md
- docs/PHASE-3-llm-agent.md
- docs/PHASE-4-fusion-agent.md
- docs/PHASE-5-api-layer.md
- docs/PHASE-6-testing.md

## Quality command baseline

- pytest tests/unit/ -v
- pytest tests/integration/ -v  # when integration tests exist
- pytest --cov=. --cov-report=term-missing --cov-fail-under=90
- ruff check .
- bandit -r .
