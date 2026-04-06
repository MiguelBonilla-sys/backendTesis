# Next Steps

Ordered actionable backlog for the next sessions.

1. Standardize team daily start:

- Use pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-daily-workflow.ps1.
- Confirm everyone follows the same reading order before coding.

1. Enforce per-message memory sync in chat:

- Keep .github/instructions/backendTesis.instructions.md with the always-run auto-memory command.
- Keep .github/rules/AUTO_MEMORY_ALWAYS_RULE.md as governance reference.

1. Reconcile documentation status with runtime implementation:

- Compare each phase doc against current code behavior.
- Update docs/PLAN.md and phase files to avoid drift.

1. Strengthen pipeline tests where needed:

- Add focused tests for analyze route concurrency behavior.
- Add focused tests for TI cache-hit vs cache-miss behavior.

1. Validate security hardening:

- Re-check auth constraints for future protected endpoints.
- Keep error responses free of sensitive internals.

1. Improve observability:

- Add consistent trace identifiers across pipeline logs.
- Ensure warning/error logs are actionable and non-sensitive.

1. Keep memory cycle active:

- Update .github/context/work-log.md after each meaningful change.
- Refresh this file after each session.
- Keep .github/auto-memory/dirty-files updated via scripts/auto-memory-sync.ps1.
