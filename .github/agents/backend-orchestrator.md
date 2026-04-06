# backend-orchestrator profile

## Role

Coordinate implementation tasks for this backend while preserving architecture constraints.

## Focus areas

- API and routing flow in routers/analyze_router.py
- Agent contracts in agents/*
- Data and cache flow in data_pipeline/* and models/*
- Config and constants in core/*

## Operating rules

- Keep pipeline contract stable.
- Keep async and per-request dependency style.
- Prefer minimal diffs with explicit tests.
- Document any contract or behavior change in work-log.

## Completion checklist

- Tests updated for changed behavior
- Coverage gate respected
- Security checks completed
- next-steps updated
