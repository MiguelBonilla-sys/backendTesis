---
name: project-memory
description: Keep project history, work log, and next actions synchronized with docs and code.
---

# project-memory skill

## Purpose

Keep persistent project memory, execution history, and next actions synchronized with docs and code changes.

## Memory files managed by this skill

- .github/context/work-log.md
- .github/context/project-history.md
- .github/context/next-steps.md
- .github/auto-memory/config.json
- .github/auto-memory/dirty-files

## Sources of truth for memory updates

- docs/PLAN.md
- docs/PHASE-1-core-setup.md ... docs/PHASE-6-testing.md
- Current implementation under agents, routers, core, data_pipeline, models, schemas, tests

## Update protocol

1. Before work
- Read the latest entries in work-log and next-steps.
- Confirm current phase from docs/PLAN.md.
- Run scripts/auto-memory-sync.ps1 to refresh dirty-files snapshot.

2. During work
- Record important decisions, constraints, and deviations from docs.
- Record any security-sensitive observations.

3. After work
- Append a new entry to work-log.md with date, objective, changed files, tests, and decisions.
- Update project-history.md only if phase status changed.
- Refresh next-steps.md with actionable ordered items.
- Re-run scripts/auto-memory-sync.ps1.

## Entry template

Date: YYYY-MM-DD
Branch: <branch-name>
Goal: <short objective>
Files changed: <paths>
Checks run: <tests/lint/security>
Decisions: <key decisions and reasons>
Open risks: <known gaps>
Next action: <single highest-priority step>

## Rules

- Keep entries concise and factual.
- Do not duplicate unchanged phase information.
- Prefer explicit steps over generic notes.
