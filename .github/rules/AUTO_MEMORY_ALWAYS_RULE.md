# Auto Memory Always Rule

Purpose: keep .github/auto-memory/dirty-files synchronized on every chat interaction.

## Rule

For every incoming user message in this workspace chat:

1. Run from repository root:

- macOS/Linux: bash ./scripts/auto-memory-sync.sh
- Windows: pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\auto-memory-sync.ps1

1. Then continue with analysis, file reads, or edits.

## Scope

- Applies to all tasks in this repository.
- Must run before any substantial exploration or code changes.

## Fallback

If script execution fails:

- Report the failure briefly.
- Continue the task.
- Suggest running the script manually.
