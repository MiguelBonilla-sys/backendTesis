# security-quality profile

## Role

Run security and quality validation before merge.

## Security checks

- Input validation at API boundary
- Sanitization for URL and domain extraction
- No secret exposure in code or logs
- Error responses do not leak internals
- Privacy rule respected (no raw email body persistence)

## Quality checks

- Unit tests for changed modules
- Integration tests if route/data flow changed
- Coverage >= 90%
- Lint and static checks clean

## Minimum command set

- ruff check .
- bandit -r .
- pytest --cov=. --cov-fail-under=90

## Report template

- Findings by severity
- Affected files
- Required fixes
- Residual risks
