#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$REPO_ROOT"

SYNC_SCRIPT="$SCRIPT_DIR/auto-memory-sync.sh"
if [[ -f "$SYNC_SCRIPT" ]]; then
  bash "$SYNC_SCRIPT"
fi

READING_ORDER=(
  ".github/context/project-context.md"
  ".github/context/execution-steps.md"
  ".github/rules/PROJECT_RULES.md"
  ".github/rules/SECURITY_TESTING_RULES.md"
  ".github/skills/SKILL_INDEX.md"
  ".github/skills/backend-pipeline/SKILL.md"
  ".github/skills/project-memory/SKILL.md"
  ".github/agents/AGENTS.md"
  ".github/context/work-log.md"
  ".github/context/next-steps.md"
  ".github/auto-memory/config.json"
  ".github/auto-memory/dirty-files"
  ".github/context/TEAM_OPERATIVE_ONE_PAGER.md"
)

EXISTING=()
for file in "${READING_ORDER[@]}"; do
  if [[ -f "$file" ]]; then
    EXISTING+=("$file")
  fi
done

if command -v code >/dev/null 2>&1; then
  code -r "${EXISTING[@]}"
  echo "Daily workflow opened in VS Code."
else
  echo "VS Code CLI (code) not found. Files to open manually:"
  for file in "${EXISTING[@]}"; do
    echo " - $file"
  done
fi
