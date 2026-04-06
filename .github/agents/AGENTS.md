# Agent Playbook for backendTesis

This file defines the recommended agent workflow for this repository.

## Core agents

- planner: Use for multi-file or architectural changes.
- tdd-guide: Use for new behavior and bug fixes.
- code-reviewer: Use after every code change.
- security-reviewer: Use before finalizing auth, input, endpoint, or data changes.
- python-reviewer: Use for Python quality and idiomatic checks (if available).
- build-error-resolver: Use when tests or build fail due breakages.

## Default execution order

1. planner
2. tdd-guide
3. implement changes
4. code-reviewer
5. security-reviewer
6. python-reviewer (or code-reviewer with Python-specific checklist)
7. build-error-resolver (only if needed)

## Parallel usage guidance

Parallelize independent checks:
- security-reviewer + python-reviewer (or code-reviewer fallback)
- unit-test focused analysis + docs impact analysis

## Mandatory outputs per task

- What changed
- What was verified
- What remains pending
- Risk summary

## Memory sync requirement

After significant work, update:
- .github/context/work-log.md
- .github/context/next-steps.md
