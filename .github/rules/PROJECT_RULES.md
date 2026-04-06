# Project Rules (backendTesis)

This file translates the active Claude workflow into project-local rules for GitHub Copilot.

## Architecture rules

- Keep the 3-agent pipeline contract:
  - agents/idn_agent.py
  - agents/llm_agent.py
  - agents/fusion_agent.py
- Preserve route orchestration in routers/analyze_router.py.
- Preserve startup and shutdown checks in main.py.

## Coding rules

- Prefer small, focused functions.
- Keep naming explicit and domain-oriented.
- Handle exceptions explicitly; no silent pass.
- Validate all boundary input (API payloads, URL fields, external API responses).

## Security rules

- Never commit secrets.
- Use environment variables only.
- Sanitize URL input through core/security.py.
- Keep authentication and authorization checks explicit when adding protected routes.

## Data governance rules

- Never persist raw email body.
- Keep hashed identifiers for privacy-sensitive payloads.
- Keep risk score and explainability schema consistent.

## Testing rules

- Coverage gate is 90% minimum in this project.
- Every behavior change must have tests.
- Add integration tests for API and data pipeline behavior, not only unit tests.

## Collaboration rules

- For complex changes, plan first.
- For bug fixes and features, use test-first cycle.
- Run code review and security review before finalizing.
- Update context logs in .github/context after meaningful work.
