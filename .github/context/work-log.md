# Work Log

<!-- AUTO-SYNC:START -->
## Auto Sync

- Last sync (UTC): 2026-04-12T21:18:56.897457Z
- Branch: copilot/investigar-despliegue-aws-lambda
- Dirty entries: 5
- Dirty preview:
  - .github/auto-memory/dirty-files
  - .github/context/next-steps.md
  - .github/context/project-context.md
  - .github/context/project-history.md
  - .github/context/work-log.md
<!-- AUTO-SYNC:END -->

Concise session log for continuity across agents and sessions.

## 2026-04-09 (phase 2 docs reconciliation)

Branch: feat/phase-2-idn-agent
Goal: Align `docs/PHASE-2-idn-agent.md` with real runtime implementation and executed tests.

Files updated:

- docs/PHASE-2-idn-agent.md

Checks:

- .\\.venv\\Scripts\\python -m pytest tests/unit/test_idn_agent.py tests/unit/test_confusables_loader.py tests/unit/test_bktree.py --cov-reset --cov=agents.idn_agent --cov=agents.confusables_loader --cov=agents.bktree --cov-fail-under=90 -q
- .\\.venv\\Scripts\\python -m pytest tests/unit/test_cache_manager.py tests/unit/test_threat_intel.py --no-cov -q
- .\\.venv\\Scripts\\python -m pytest tests/unit/test_idn_agent.py tests/unit/test_confusables_loader.py tests/unit/test_bktree.py tests/unit/test_cache_manager.py tests/unit/test_threat_intel.py --no-cov -q
- .\\.venv\\Scripts\\python -m bandit -r agents/ --severity-level medium

Outcome:

- Phase 2 docs no longer describe `confusables_loader.py` / `bktree.py` as pending.
- Phase 2 evidence section now reflects actual results: 113 passed (Phase 2 related batch), and 92.89% coverage for (`idn_agent`, `confusables_loader`, `bktree`).
- Security verification completed for Phase 2 scope: bandit reports no Medium/High issues in `agents/`.

Decisions:

- Treat code + executed tests as runtime source of truth when phase docs drift.
- Keep security status in docs tied to explicit command evidence in work-log.

Open risks:

- Other planning artifacts (`docs/PLAN.md` and remaining phase docs) still contain stale TODO states versus runtime.

Next action:

- Continue reconciliation for `docs/PLAN.md` and remaining `docs/PHASE-*.md` files.

## 2026-04-09 (phase tracker document)

Branch: feat/phase-1-core-setup
Goal: Create a living markdown tracker with real progress per phase.

Files updated:

- docs/PHASE-PROGRESS.md

Checks:

- .\\.venv\\Scripts\\python -m pytest -q

Outcome:

- Test suite passing: 154 passed, 0 failed.
- Coverage gate passing: 94.45% (>= 90%).

Decisions:

- Keep `docs/PHASE-PROGRESS.md` as the runtime-truth tracker for phase status.
- Treat phase docs as planning artifacts and tracker as execution status reference.

Open risks:

- Phase documents (`docs/PHASE-*.md`) and `docs/PLAN.md` still contain stale TODO statuses.

Next action:

- Reconcile `docs/PLAN.md` and phase docs against `docs/PHASE-PROGRESS.md` snapshots.

## 2026-04-09 (unit test stabilization pass)

Branch: feat/phase-1-core-setup
Goal: Resolve failing unit tests and validate functional green state.

Files updated:

- utils/url_parser.py
- core/security.py
- tests/unit/test_url_parser.py
- tests/unit/test_security.py
- tests/unit/test_idn_agent.py
- tests/unit/test_fusion_agent.py

Checks:

- .\\.venv\\Scripts\\python -m pytest --no-cov tests/unit/test_url_parser.py tests/unit/test_idn_agent.py tests/unit/test_fusion_agent.py -v
- .\\.venv\\Scripts\\python -m pytest --no-cov tests/unit/test_url_parser.py tests/unit/test_security.py tests/unit/test_idn_agent.py tests/unit/test_fusion_agent.py -v
- .\\.venv\\Scripts\\python -m pytest -v --no-cov
- .\\.venv\\Scripts\\python -m pytest -v

Outcome:

- Functional suite now passes completely: 51 passed, 0 failed (`pytest -v --no-cov`).

Decisions:

- Keep runtime constants and formulas as source of truth; align tests to current thresholds and score math.
- Harden URL extraction contract to raise InvalidURLError for malformed inputs and non-string payloads.
- Align extract_domain behavior between utils and core.security to avoid contract drift.

Open risks:

- Coverage gate still fails (about 52% vs required 90%).
- Deprecation warning remains in middleware status constant mapping (HTTP_422_UNPROCESSABLE_ENTITY).

Next action:

- Add focused tests for low-coverage modules (auth, threat_intel, cache_manager, routers/analyze_router, orm_models/incident schemas path where applicable).
- Replace deprecated 422 status constant in middleware to remove warning.

## 2026-04-08 (linux/macos shell compatibility)

Branch: feat/phase-1-core-setup
Goal: Ensure shell automation runs on Linux/macOS.

Files updated:

- .gitattributes
- scripts/auto-memory-sync.sh
- scripts/start-daily-workflow.sh
- scripts/snapshot-export.sh
- scripts/snapshot-import.sh

Checks:

- bash -n ./scripts/auto-memory-sync.sh
- bash -n ./scripts/start-daily-workflow.sh
- bash -n ./scripts/snapshot-export.sh
- bash -n ./scripts/snapshot-import.sh
- bash ./scripts/auto-memory-sync.sh

Decisions:

- Normalize all repository shell scripts to LF to avoid bash parse failures in Linux/macOS.
- Add .gitattributes rule (`*.sh text eol=lf`) to prevent future CRLF regressions.

Open risks:

- Existing local clones may still keep CRLF until files are refreshed by Git or manually normalized.

Next action:

- Ask teammates to run `git add --renormalize .` once after pulling this change.

## 2026-04-08 (shared context auto-sync)

Branch: feat/phase-1-core-setup
Goal: Keep shared context files refreshed on each auto-memory sync run.

Files updated:

- scripts/auto_memory_sync.py

Checks:

- pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\auto-memory-sync.ps1
- python -m py_compile .\scripts\auto_memory_sync.py

Decisions:

- Auto-update .github/context/work-log.md, project-history.md, next-steps.md, and project-context.md through managed AUTO-SYNC markers.
- Store dirty snapshot entries as repository-relative paths to avoid machine-specific absolute paths.

Open risks:

- Timestamp refresh can add frequent markdown diffs during active sessions.

Next action:

- If diff noise becomes high, add a config gate in .github/auto-memory/config.json to throttle metadata writes.

## 2026-04-06

Branch: Development
Goal: Create GitHub-native project context, rules, skills, agents, and memory workflow.

Files added:

- .github/README.md
- .github/copilot-instructions.md
- .github/instructions/backendTesis.instructions.md
- .github/instructions/python-fastapi.instructions.md
- .github/instructions/tests.instructions.md
- .github/rules/PROJECT_RULES.md
- .github/rules/SECURITY_TESTING_RULES.md
- .github/skills/SKILL_INDEX.md
- .github/skills/backend-pipeline/SKILL.md
- .github/skills/project-memory/SKILL.md
- .github/agents/AGENTS.md
- .github/agents/backend-orchestrator.md
- .github/agents/security-quality.md
- .github/context/project-context.md
- .github/context/project-history.md
- .github/context/execution-steps.md
- .github/context/work-log.md
- .github/context/next-steps.md

Checks:

- Context review completed from docs and runtime files.
- No runtime code behavior changed in this session.

Decisions:

- Use .github as the primary place for Copilot context.
- Keep docs-plan status and runtime observation separately documented.
- Add a dedicated memory skill for ongoing history maintenance.

Open risks:

- docs phase statuses are not fully aligned with current runtime implementation.

Next action:

- Reconcile docs/PLAN.md with runtime implementation status.

## 2026-04-06 (follow-up)

Branch: Development
Goal: Add one-command daily startup, one-page team guide, and Claude-style auto-memory in .github.

Files added:

- scripts/auto-memory-sync.ps1
- scripts/start-daily-workflow.ps1
- .github/auto-memory/config.json
- .github/auto-memory/dirty-files
- .github/context/TEAM_OPERATIVE_ONE_PAGER.md

Files updated:

- .github/README.md
- .github/skills/project-memory/SKILL.md
- .github/context/next-steps.md

Checks:

- auto-memory structure created and aligned with Claude triggerMode default.
- command script created for ordered opening flow.

Decisions:

- Keep auto-memory as lightweight git-status snapshot under .github/auto-memory.
- Keep one command as the standard team entrypoint.

Open risks:

- integration suite is still minimal, so integration command is conditional.

Next action:

- run scripts/auto-memory-sync.ps1 and then scripts/start-daily-workflow.ps1 once per session start.

## 2026-04-06 (auto-memory always rule)

Branch: Development
Goal: Enforce auto-memory sync at the beginning of every chat message.

Files added:

- .github/rules/AUTO_MEMORY_ALWAYS_RULE.md

Files updated:

- .github/instructions/backendTesis.instructions.md

Checks:

- Executed scripts/auto-memory-sync.ps1 after changes.
- Markdown and instruction files validated with no errors.

Decisions:

- Keep the enforcement in global instructions (applyTo "**") so it applies in all tasks.
- Keep a dedicated rule file for team visibility and governance.

Open risks:

- Rule compliance depends on agent instruction adherence, not on an external hook engine.

Next action:

- Keep using scripts/auto-memory-sync.ps1 at the start of each user request.

## 2026-04-06 (hook enabled)

Branch: Development
Goal: Enable strict hook execution for auto-memory on each prompt submit.

Files updated:

- .claude/settings.local.json

Hook installed:

- hooks.UserPromptSubmit -> pwsh -NoProfile -ExecutionPolicy Bypass -File ./scripts/auto-memory-sync.ps1

Checks:

- settings.local.json parsed successfully via ConvertFrom-Json.
- auto-memory sync executed after installation.

Decision:

- Keep instruction-level rule and hook-level enforcement in parallel.

Open risk:

- Hook execution depends on Claude runtime loading .claude/settings.local.json in current session.

Next action:

- Restart/reload Claude session if hook does not trigger immediately.

## 2026-04-06 (dependabot ecdsa alert mitigation)

Branch: Development
Goal: Mitigate Dependabot alert about Minerva timing attack on python-ecdsa.

Files updated:

- auth/auth.py
- requirements.txt
- scripts/auto-memory-sync.ps1

Security action:

- Migrated JWT operations from python-jose to PyJWT.
- Removed direct dependencies python-jose and ecdsa from requirements.txt.

Validation:

- Local runtime check: create_access_token/decode_token works with PyJWT.
- No remaining jose imports in Python files.
- auto-memory-sync script runs successfully after robustness fix.

Decision:

- Because python-ecdsa has no patched version and upstream marks side-channel issues out-of-scope, dependency removal was chosen over version pinning.

Residual risk:

- Existing environments must reinstall dependencies to effectively remove python-jose/ecdsa.

Next action:

- Run dependency reinstall/update in CI and local environments, then close Dependabot alert as mitigated-by-removal.

## 2026-04-06 (auto-memory OS-aware)

Branch: feat/phase-1-core-setup
Goal: Make auto-memory and daily startup work on macOS/Linux and Windows.

Files added:

- scripts/auto_memory_sync.py
- scripts/auto-memory-sync.sh
- scripts/start-daily-workflow.sh

Files updated:

- scripts/auto-memory-sync.ps1
- .github/instructions/backendTesis.instructions.md
- .github/rules/AUTO_MEMORY_ALWAYS_RULE.md
- .github/README.md
- .github/context/TEAM_OPERATIVE_ONE_PAGER.md
- .github/skills/project-memory/SKILL.md
- .github/context/next-steps.md

Checks:

- bash ./scripts/auto-memory-sync.sh
- bash ./scripts/start-daily-workflow.sh
- python3 -m py_compile scripts/auto_memory_sync.py
- bash -n scripts/auto-memory-sync.sh
- bash -n scripts/start-daily-workflow.sh

Decisions:

- Keep sync logic in a single Python core script and use OS wrappers as entrypoints.
- Keep Windows compatibility with existing PowerShell command while enabling macOS/Linux via bash wrappers.

Open risks:

- Environments without Python (python3/python) cannot run the new sync flow.

Next action:

- Add a cross-platform hook config file that invokes the OS-aware wrapper by default.

## 2026-04-06 (uv + Python 3.11 venv regeneration)

Branch: feat/phase-1-core-setup
Goal: Regenerate .venv using uv with Python 3.11 and validate install path.

Environment actions:

- Installed uv and validated version (0.11.3).
- Installed Python 3.11.15 with uv.
- Recreated .venv using uv venv --python 3.11.

Checks:

- .venv/bin/python --version -> Python 3.11.15
- uv pip list --python .venv/bin/python

Dependency findings:

- requirements.txt is unsatisfiable on macOS x86_64 + Python 3.11 as pinned.
- llama-stack==0.7.0 requires Python >=3.12.
- onnxruntime==1.24.4 has no matching wheel for macOS x86_64.
- shap==0.51.0 conflicts with pinned numba==0.65.0 on Darwin x86_64.

Decision:

- Keep .venv on Python 3.11 with uv and install a functional core dependency set using uv for local development/testing while requirements pins are reconciled.

Open risks:

- Full reproducible install from requirements.txt remains blocked until version/platform markers are fixed.

Next action:

- Normalize requirements pins and add platform markers (Windows-only and macOS-compatible constraints) for uv/pip parity.

## 2026-04-07 (snapshot sharing implementation)

Branch: feat/phase-1-core-setup
Goal: Implement snapshot-sharing baseline for team data exchange and prevent accidental commit of backups.

Files added:

- .github/context/data-management.md

Files updated:

- .gitignore
- .github/context/next-steps.md

Checks:

- Verified .gitignore includes snapshot/backup exclusion patterns for PostgreSQL, Redis, ChromaDB, and LlamaStack artifacts.

Decisions:

- Keep sharing mode based on offline snapshots (not shared live volumes).
- Store operational procedure in .github/context to keep team workflow close to execution logs.
- Keep implementation scope to gitignore + manual snapshot guide (no docker-compose changes).

Open risks:

- Snapshot file names must follow the documented naming convention to be excluded consistently.
- Restore commands assume local container names/volumes and may require per-machine adjustment.

Next action:

- Run the first cross-machine dry-run (export/import + checksum verification) with a teammate and capture findings.

## 2026-04-07 (snapshot automation scripts)

Branch: feat/phase-1-core-setup
Goal: Automate snapshot export/import workflow for team data sharing.

Files added:

- scripts/snapshot-export.sh
- scripts/snapshot-import.sh

Files updated:

- .github/context/data-management.md

Checks:

- bash -n scripts/snapshot-export.sh
- bash -n scripts/snapshot-import.sh
- bash ./scripts/snapshot-export.sh --help
- bash ./scripts/snapshot-import.sh --help

Decisions:

- Keep scripts as the primary workflow and manual commands as fallback reference.
- Keep destructive restore confirmation by default in import script; allow bypass with --force for CI/automation.
- Keep container and volume names configurable via environment variables.

Open risks:

- Restore script assumes Docker resources exist locally; missing containers/volumes are skipped with warnings.

Next action:

- Execute a full dry-run with a teammate using the scripts and capture resource-name overrides in the guide.

## 2026-04-07 (dependencies compose added)

Branch: feat/phase-1-core-setup
Goal: Add missing Docker Compose for data dependencies and align it with snapshot tooling.

Files added:

- docker-compose.deps.yml

Files updated:

- .github/context/data-management.md

Checks:

- docker compose -f docker-compose.deps.yml config

Decisions:

- Use compose project name `backendtesis-deps` to keep stable volume names.
- Keep container names aligned with snapshot scripts defaults (`bt-postgres`, `bt-chroma`, `bt-redis`, `bt-llamastack`).
- Map LlamaStack host port to `5000` to match current `.env.example` (`LLAMASTACK_URL=http://localhost:5000`).

Open risks:

- LlamaStack service depends on a reachable Ollama endpoint (`host.docker.internal:11434`).

Next action:

- Run `docker compose -f docker-compose.deps.yml up -d` and execute end-to-end snapshot export/import dry-run with teammate.

## 2026-04-07 (services up + env alignment)

Branch: feat/phase-1-core-setup
Goal: Start dependency containers and align `.env.example` with the actual reachable LlamaStack endpoint.

Files updated:

- docker-compose.deps.yml
- .env.example
- .github/context/data-management.md

Checks:

- docker compose -f docker-compose.deps.yml up -d
- docker compose -f docker-compose.deps.yml ps
- curl http://localhost:5001/v1/health

Decisions:

- Changed host mapping for LlamaStack from `5000:8321` to `5001:8321` due local port 5000 conflict on macOS (`ControlCe`).
- Updated `.env.example` to `LLAMASTACK_URL=http://localhost:5001` and guide validation endpoint accordingly.

Open risks:

- LlamaStack starts and health endpoint is reachable even when Ollama is unavailable; model inference will require Ollama (or another configured provider) to be reachable.

Next action:

- Run first teammate dry-run with snapshot scripts against the running compose stack and capture any per-machine override variables.

## 2026-04-07 (phase-1 verification + unit tests)

Branch: feat/phase-1-core-setup
Goal: Verify whether Phase 1 is complete in runtime and execute existing tests using active .venv.

Files updated:

- models/chromadb_client.py
- pytest.ini
- .coveragerc

Checks:

- source .venv/bin/activate && pytest tests/unit -v
- source .venv/bin/activate && pytest tests/unit -v -o addopts=''
- source .venv/bin/activate && pytest tests/unit/test_config.py tests/unit/test_health.py tests/unit/test_security.py tests/unit/test_url_parser.py -v -o addopts=''

Results:

- Unit tests with default addopts: 43 collected, 40 passed, 3 failed.
- Failing tests: test_fusion_agent::test_verdict_suspicious, test_idn_agent::test_safe_domain_low_score, test_url_parser::test_extract_domain_invalid_url.
- Coverage gate failed: total 51.66% < required 90%.
- Phase-1-focused subset: 32 collected, 31 passed, 1 failed (test_url_parser::test_extract_domain_invalid_url).

Divergence note (docs vs runtime):

- docs/PHASE-1-core-setup.md marks Phase 1 as DONE with all acceptance criteria passing.
- Runtime behavior still has at least one failing Phase-1 test and health endpoint reports static OK without dependency checks.

Decisions:

- Treat runtime and tests as source of truth for completion status.
- Keep docs status reconciliation as an explicit backlog item before declaring Phase 1 closed.

Open risks:

- Health endpoint can produce false-positive readiness signal when dependencies are down.
- Project quality gate cannot pass while coverage remains far below target.

Next action:

- Fix remaining functional failures first, then increase targeted coverage for low-covered runtime modules.

## 2026-04-08 (compose update: ollama in-stack + llamastack integration)

Branch: feat/phase-1-core-setup
Goal: Make dependency stack self-contained by adding Ollama to Compose and connecting LlamaStack through the internal Docker network.

Files updated:

- docker-compose.deps.yml
- .env.example

Checks:

- docker compose -f docker-compose.deps.yml up -d
- docker compose -f docker-compose.deps.yml ps
- curl http://localhost:11434/api/tags
- curl http://localhost:11434/v1/models
- curl http://localhost:5001/v1/models
- docker logs bt-llamastack (filtered)

Decisions:

- Added `ollama` service to `docker-compose.deps.yml` with persisted volume and healthcheck.
- Changed LlamaStack provider URL from host bridge (`host.docker.internal`) to internal service DNS (`http://ollama:11434/v1`).
- Kept host endpoint `LLAMASTACK_URL=http://localhost:5001` aligned with local development.

Open risks:

- Current LlamaStack model IDs are provider-scoped (e.g., `ollama/Llama-3.1-8B-Instruct-GGUF`), while legacy unscoped model names may return `ModelNotFoundError`.

Next action:

- Decide whether to normalize model ID in `.env`/config (`ollama/...`) or add compatibility fallback in `agents/llm_agent.py` for legacy model names.

## 2026-04-08 (llamastack model id normalized in runtime config)

Branch: feat/phase-1-core-setup
Goal: Update active runtime configuration so backend uses the provider-scoped model id accepted by current LlamaStack + Ollama setup.

Files updated:

- .env
- core/config.py

Checks:

- python -c "from core.config import settings; print(settings.LLAMASTACK_URL, settings.LLAMASTACK_MODEL)"
- POST http://localhost:5001/v1/chat/completions with model `ollama/Llama-3.1-8B-Instruct-GGUF` (HTTP 200)

Decisions:

- Keep `LLAMASTACK_URL=http://localhost:5001`.
- Set canonical runtime model id to `ollama/Llama-3.1-8B-Instruct-GGUF` in both `.env` and defaults in `core/config.py`.

Open risks:

- `.env.example` still uses the legacy unscoped model id and may need alignment to avoid onboarding confusion.

Next action:

- Align `.env.example` and add one focused test for model id normalization/fallback behavior in the LLM path.
