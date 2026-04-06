# Team Operative One Pager

Purpose: daily execution guide for backendTesis with a stable, repeatable flow.

## One command to start daily flow

PowerShell command:
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-daily-workflow.ps1

What it does:

- Syncs auto-memory dirty-files snapshot.
- Opens reading order in VS Code (context, rules, skills, agents, memory).

## Daily sequence

1. Read project context and execution steps.
2. Confirm current phase scope with docs and runtime behavior.
3. Implement minimal changes with tests first when behavior changes.
4. Validate quality and security checks.
5. Update memory files.

## Required invariants

- Keep pipeline order: IDN -> (LLM + TI concurrent) -> Fusion.
- Keep agents stateless and per-request instantiated.
- Keep TI cache-first behavior.
- Keep verdict literals: PHISHING, SUSPICIOUS, SAFE.
- Do not persist raw email body.
- Keep coverage >= 90%.

## Validation commands

- pytest tests/unit/ -v
- pytest tests/integration/ -v (when integration tests exist)
- pytest --cov=. --cov-report=term-missing --cov-fail-under=90
- ruff check .
- bandit -r .

## Auto-memory in this repo

Path:

- .github/auto-memory/config.json
- .github/auto-memory/dirty-files

Behavior:

- triggerMode is currently default.
- dirty-files is refreshed from git status by scripts/auto-memory-sync.ps1.
- Hook enforcement enabled in .claude/settings.local.json via UserPromptSubmit.

## End-of-session checklist

- work-log updated
- next-steps updated
- project-history updated only if phase status changed
- docs/runtime divergences explicitly noted

## Ownership model

- Engineers: implementation + tests + updates to memory files.
- Reviewers: code quality + security checks + contract consistency.
- Lead: phase progress and plan/runtime alignment.
