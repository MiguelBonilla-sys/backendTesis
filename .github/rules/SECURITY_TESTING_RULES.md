# Security and Testing Rules

## Security baseline

- Input validation is mandatory at every API boundary.
- Keep URL sanitization and host extraction strict.
- Keep auth checks explicit on protected endpoints.
- Return safe, user-facing error messages only.
- Keep secret material in environment variables.

## Data protection baseline

- Do not store raw email body persistently.
- Prefer hash-based identifiers for sensitive payload traces.

## Testing baseline

- 90% minimum coverage is required.
- New behavior requires tests.
- Critical paths should include integration tests.
- Validate failure behavior, not only success behavior.

## Pre-merge checks

- ruff check .
- bandit -r .
- pytest --cov=. --cov-fail-under=90

If any check fails, resolve before merge.
