# Next Steps

<!-- AUTO-SYNC:START -->
## Auto Sync

- Last sync (UTC): 2026-04-14T01:46:03.189535Z
- Branch: feat/testing-podman
- Dirty entries: 20
- Dirty preview:
  - .env.example
  - .github/auto-memory/dirty-files
  - .github/context/next-steps.md
  - .github/context/project-context.md
  - .github/context/project-history.md
  - .github/context/work-log.md
  - agents/fusion_agent.py
  - agents/idn_agent.py
  - agents/llm_agent.py
  - agents/prompt_builder.py
  - agents/rag_retriever.py
  - core/config.py
  - ... (+8 more)
<!-- AUTO-SYNC:END -->

Ordered actionable backlog for the next sessions.

1. Consolidate LlamaStack model ID compatibility after compose update:

- Keep `docker-compose.deps.yml` with internal Ollama URL (`http://ollama:11434/v1`).
- Canonical runtime strategy selected: provider-scoped model IDs (`ollama/<model>`).
- Done: applied in `.env` and `core/config.py` defaults.
- Pending: align `.env.example` to avoid `ModelNotFoundError` during onboarding.
- Add/adjust one focused unit test for model ID normalization behavior in the LLM agent/config layer.

1. Complete pending Phase 1 runtime verification:

- Update health/readiness checks to reflect real dependency connectivity and return degraded status when needed.
- Re-run Phase 1 acceptance subset after health changes.

1. Sustain coverage quality after hitting target:

- Keep coverage >= 90% on every meaningful change (`pytest -q` / `pytest -v`).
- Add regression tests for any new route, agent behavior, or schema contract before merging.
- Keep warning debt visible (HTTP 422 deprecation) and schedule cleanup.

1. Keep phase tracker synchronized:

- Update `docs/PHASE-PROGRESS.md` after each sprint increment.
- Reconcile `docs/PLAN.md` and `docs/PHASE-*.md` with tracker state to reduce documentation drift.

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

- Done: `docs/PHASE-2-idn-agent.md` reconciled against runtime code/tests (2026-04-09).
- Pending: compare remaining phase docs and `docs/PLAN.md` against current code behavior.
- Update planning docs to avoid future drift after each meaningful runtime change.

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

1. Investigate ChromaDB health degradation in compose:

- `bt-api` now starts and answers requests after the `packaging` runtime fix.
- `bt-chroma` still reports unhealthy in `docker compose ps`.
- Compare app-side `chromadb.HttpClient` connectivity with the container healthcheck endpoint.
- If needed, align the Chroma image/version or healthcheck path with the runtime client expectations.

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
