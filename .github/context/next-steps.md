# Next Steps

<!-- AUTO-SYNC:START -->
## Auto Sync

- Last sync (UTC): 2026-04-09T01:33:39.113363Z
- Branch: feat/phase-1-core-setup
- Dirty entries: 9
- Dirty preview:
  - .gitattributes
  - .github/auto-memory/dirty-files
  - .github/context/next-steps.md
  - .github/context/project-context.md
  - .github/context/project-history.md
  - .github/context/work-log.md
  - scripts/auto_memory_sync.py
  - scripts/snapshot-export.sh
  - scripts/snapshot-import.sh
<!-- AUTO-SYNC:END -->

Ordered actionable backlog for the next sessions.

1. Close Phase 1 verification gaps in runtime:

- Fix invalid URL handling so extract_domain raises InvalidURLError for malformed inputs.
- Update health/readiness checks to reflect real dependency connectivity and return degraded status when needed.
- Re-run phase-1 test subset until all acceptance tests pass.

1. Resolve current unit test regressions outside Phase 1:

- Align Fusion suspicious-threshold expectation with constants/formula and tests.
- Align IDN safe-domain baseline expectations with current scoring strategy or adjust algorithm.

1. Standardize team daily start:

- Use OS-aware start command.
	- macOS/Linux: bash ./scripts/start-daily-workflow.sh
	- Windows: pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-daily-workflow.ps1
- Confirm everyone follows the same reading order before coding.
- Keep shell scripts with LF line endings (`*.sh text eol=lf`) to preserve Linux/macOS bash compatibility.

1. Enforce per-message memory sync in chat:

- Keep .github/instructions/backendTesis.instructions.md with the always-run auto-memory command.
- Keep .github/rules/AUTO_MEMORY_ALWAYS_RULE.md as governance reference.
- Add hook configuration that invokes OS-aware wrappers by default.

1. Reconcile documentation status with runtime implementation:

- Compare each phase doc against current code behavior.
- Update docs/PLAN.md and phase files to avoid drift.

1. Normalize dependency compatibility for uv workflows:

- Add platform markers for Windows-only packages (e.g., pywin32).
- Reconcile Python-version constraints (llama-stack vs project Python target).
- Align macOS x86_64 pins for onnxruntime/numba/shap so requirements.txt resolves end-to-end.

1. Validate snapshot-sharing workflow with a teammate:

- Start dependencies with `docker compose -f docker-compose.deps.yml up -d`.
- Use `.env.example` local endpoint `LLAMASTACK_URL=http://localhost:5001` when running backend on host.
- Execute one full dry-run using scripts/snapshot-export.sh and scripts/snapshot-import.sh.
- Verify checksum validation and restore order across PostgreSQL, ChromaDB, Redis, and LlamaStack.
- Capture per-machine adjustments (container/volume names) and update the guide with concrete examples.

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

- Keep scripts/auto-memory-sync.ps1 as the mandatory first command per user message.
- Let AUTO-SYNC metadata refresh .github/context/work-log.md, project-history.md, next-steps.md, and project-context.md on each run.
- Update narrative entries in .github/context/work-log.md after each meaningful change.
- Refresh this file after each session.
- Keep .github/auto-memory/dirty-files updated via OS-aware auto-memory sync.
