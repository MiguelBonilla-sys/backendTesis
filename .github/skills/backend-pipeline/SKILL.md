---
name: backend-pipeline
description: Project-specific implementation playbook for the phishing detection pipeline.
---

# backend-pipeline skill

## Purpose

Provide a project-specific implementation playbook for the phishing backend pipeline:
- IDN agent
- LLM agent
- TI integration
- Fusion and explainability
- API orchestration and testing

## Activation conditions

Use this skill when changing any of these paths:
- agents/**
- routers/**
- data_pipeline/**
- schemas/**
- core/**
- tests/**

## Mandatory read order

1. .github/context/project-context.md
2. .github/context/execution-steps.md
3. docs/PLAN.md
4. Relevant docs/PHASE-*.md file
5. Actual runtime files in code to verify current behavior

## Domain invariants

- Pipeline order: IDN -> (LLM + TI concurrent) -> Fusion
- Agents are stateless and per-request instantiated
- TI path is cache-first, then external APIs
- Verdict values are only PHISHING, SUSPICIOUS, SAFE
- Fusion constants come from core/constants.py
- No raw email body persistence

## Formula contracts

- S_IDN_local = BETA * ratio_h + (1 - BETA) * sim_v
- S_TI = 0.50 * VT + 0.30 * URLScan + 0.20 * GSB
- S_IDN = ALPHA * S_IDN_local + (1 - ALPHA) * S_TI
- S_risk = GAMMA * S_IDN + (1 - GAMMA) * S_LLM

## Implementation checklist

1. Confirm behavior with existing code before changing docs assumptions.
2. Keep input validation and sanitized URL handling in place.
3. Keep async behavior and parallel I/O only where independent.
4. Keep response schema compatible with AnalyzeResponse.
5. Add or update tests for each changed behavior.
6. Run quality checks and security checks.
7. Update .github/context/work-log.md.

## Done criteria

- Behavior is covered by tests.
- Coverage gate remains >= 90%.
- No secrets or unsafe error leakage introduced.
- work-log and next-steps updated.
