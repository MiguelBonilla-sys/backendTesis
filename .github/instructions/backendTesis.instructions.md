---
applyTo: "**"
---

# Global repo instructions

You are working in backendTesis, an async FastAPI backend for phishing detection.

Always do this at the beginning of every user message in chat:
1. Run from repository root with OS-aware command:
	- macOS/Linux: bash ./scripts/auto-memory-sync.sh
	- Windows: pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\auto-memory-sync.ps1
2. Continue with analysis and requested work.

Always do this before major edits:
1. Read docs/PLAN.md.
2. Read the relevant docs/PHASE-*.md file.
3. Check current code behavior in agents, routers, and core before changing contracts.

Execution priorities:
- Preserve pipeline order: IDN -> (LLM + TI concurrent) -> Fusion.
- Preserve privacy constraints.
- Preserve verdict contract and response schema consistency.

If docs and code diverge:
- Treat current code as runtime source of truth.
- Note the divergence in .github/context/work-log.md.

After meaningful changes:
- Update .github/context/work-log.md.
- If phase status changed, update .github/context/project-history.md.
- Refresh .github/context/next-steps.md.
