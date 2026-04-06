---
applyTo: "**/*.py"
---

# Python and FastAPI instructions

Design constraints:
- Keep async route handlers and async I/O boundaries.
- Keep agents stateless and dependency-injected per request.
- Do not introduce global mutable state for request-specific data.

Security and validation:
- Validate all incoming user input.
- Sanitize URLs before domain extraction.
- Never expose internal stack details in HTTP responses.
- Never hardcode credentials, tokens, or API keys.

Phishing pipeline constraints:
- Keep TI cache-first behavior.
- Keep TI source aggregation aligned with core/constants.py weights.
- Keep fusion thresholds and verdict mapping unchanged unless explicitly requested.

Data constraints:
- Avoid persisting raw email body content.
- Use hashed or reduced data where feasible.

Quality constraints:
- Add/adjust tests with behavior changes.
- Keep compatibility with existing Pydantic schemas.
