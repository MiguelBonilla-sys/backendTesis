# Copilot Instructions for backendTesis

## Project identity

- Stack: FastAPI, Python 3.11, async SQLAlchemy, Redis, ChromaDB, LlamaStack.
- Domain: IDN homograph phishing detection with a 3-agent pipeline.
- Pipeline order: IDN Agent -> (LLM + TI concurrent) -> Fusion Agent.

## Non-negotiable engineering rules

1. Async first
- Keep route handlers async.
- Keep I/O calls awaited.
- Use concurrency only for independent I/O work.

2. Stateless agents
- Agent classes must remain stateless between requests.
- Instantiate per request through FastAPI dependencies.

3. Threat intel flow
- Cache lookup first via data_pipeline/cache_manager.py.
- External TI calls only on cache miss.
- TI calls should run concurrently when needed.

4. Data privacy
- Never store raw email body in persistent storage.
- Prefer hash_email_body and minimal derived metadata.

5. Risk and verdict consistency
- Keep fusion constants sourced from core/constants.py.
- Keep verdict values exactly: PHISHING, SUSPICIOUS, SAFE.

6. Config and secrets
- No hardcoded secrets.
- Use core/config.py environment-driven settings.
- Keep startup validation behavior in main.py.

7. Error safety
- Do not leak internal traces to API clients.
- Keep middleware/error_handler.py behavior aligned.

8. Testing bar
- Minimum project coverage: 90%.
- Run unit + integration tests for touched areas.

## Commands to use frequently

- pytest --cov=. --cov-report=term-missing --cov-fail-under=90
- pytest tests/unit/ -v
- pytest tests/integration/ -v  # when integration tests exist
- ruff check .
- bandit -r .

## Required workflow for non-trivial changes

1. Read docs/PLAN.md and the target phase document.
2. Write or update tests first when adding behavior.
3. Implement minimal change.
4. Run focused tests, then full relevant checks.
5. Run code-review and security review before finishing.
6. Update .github/context/work-log.md and next-steps.

## Source of truth files

- Main app lifecycle: main.py
- API pipeline route: routers/analyze_router.py
- Core constants: core/constants.py
- Settings: core/config.py
- Security helpers: core/security.py
- TI service: data_pipeline/threat_intel.py
- Plans: docs/PLAN.md and docs/PHASE-*.md

When uncertain, prefer existing implementation behavior over stale docs and record the decision in context/work-log.md.
