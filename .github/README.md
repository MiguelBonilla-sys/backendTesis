# backendTesis GitHub Context

This folder stores project-specific context for GitHub Copilot and any coding agent working in this repository.

It is based on these project sources:

- CLAUDE.md
- .claude/rules/module.md
- docs/PLAN.md
- docs/PHASE-1-core-setup.md ... docs/PHASE-6-testing.md
- Current implementation under agents, routers, core, models, data_pipeline, and tests

## Folder map

- copilot-instructions.md: Global instructions for Copilot in this repo.
- instructions/: Scope-based instruction files by file pattern.
- rules/: Human-readable rules extracted from Claude workflow and adapted to this backend.
- skills/: Reusable task skills adapted to this backend.
- agents/: Agent playbooks (planner, TDD, review, security, build fix).
- context/: Living context, history, steps, work log, and next actions.
- auto-memory/: Claude-style auto-memory config and dirty-files snapshot.

## Daily start command

PowerShell command:
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-daily-workflow.ps1

This command will:

- Sync .github/auto-memory/dirty-files from git status.
- Open the daily reading order in VS Code.
- Include one-pager, memory files, and auto-memory files.

## Quick start for a new session

1. Read context/project-context.md.
2. Read context/project-history.md.
3. Read context/execution-steps.md.
4. Read docs/PLAN.md and the relevant phase file.
5. Follow copilot-instructions.md and instructions/*.instructions.md.

Equivalent explicit paths:

- .github/context/project-context.md
- .github/context/project-history.md
- .github/context/execution-steps.md

## Maintenance rule

After meaningful changes, update:

- context/work-log.md
- context/project-history.md (only when status changes)
- context/next-steps.md

Equivalent explicit paths:

- .github/context/work-log.md
- .github/context/project-history.md
- .github/context/next-steps.md

This keeps the project memory usable across sessions and agents.
