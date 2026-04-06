#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/auto_memory_sync.py"
OS_NAME="$(uname -s 2>/dev/null || echo unknown)"

run_python_sync() {
  if command -v python3 >/dev/null 2>&1; then
    python3 "$PYTHON_SCRIPT"
    return
  fi

  if command -v python >/dev/null 2>&1; then
    python "$PYTHON_SCRIPT"
    return
  fi

  echo "auto-memory: no Python interpreter found (python3/python)." >&2
  exit 1
}

if [[ "${OS:-}" == "Windows_NT" || "$OS_NAME" =~ ^(MINGW|MSYS|CYGWIN) ]]; then
  if command -v pwsh >/dev/null 2>&1; then
    pwsh -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_DIR/auto-memory-sync.ps1"
    exit $?
  fi

  if command -v powershell >/dev/null 2>&1; then
    powershell -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_DIR/auto-memory-sync.ps1"
    exit $?
  fi

  # Fallback for Windows environments without PowerShell in PATH.
  run_python_sync
  exit $?
fi

run_python_sync
