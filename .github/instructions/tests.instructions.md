---
applyTo: "tests/**/*.py"
---

# Testing instructions

Project quality gate:
- Coverage must stay at or above 90%.

Test strategy:
- Prefer test-first for new behavior.
- Cover happy path, edge cases, and failure paths.
- Mock external services (TI APIs, LlamaStack) in unit tests.
- Use integration tests when API, DB, Redis, and pipeline interactions change.

Test quality:
- Keep tests deterministic and isolated.
- Avoid flaky network dependencies.
- Keep assertions focused on behavior and contracts.

Recommended commands:
- pytest tests/unit/ -v
- pytest tests/integration/ -v  # when integration tests exist
- pytest --cov=. --cov-report=term-missing --cov-fail-under=90
