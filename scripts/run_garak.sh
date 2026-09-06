#!/usr/bin/env bash
# Capa model-level de la suite de seguridad: NVIDIA garak contra el gateway LLM
# (OpenCode Go, endpoint OpenAI-compatible). Complementa tests/security/ (que
# prueba la aplicación: fence, RAG, fusión, parsers).
#
#   pip install garak
#   OPENCODE_API_KEY=... bash scripts/run_garak.sh
#
# Consume cuota del modelo — correr fuera de horario Peak.
set -euo pipefail

: "${OPENCODE_API_KEY:?exportá OPENCODE_API_KEY}"
BASE="${LLM_BASE_URL:-https://opencode.ai/zen/go/v1}"
MODEL="${LLM_MODEL:-deepseek-v4-flash-vision-exp}"
OUT="${1:-../Reports/tests-back/adversarial/garak}"
mkdir -p "$OUT"

export OPENAI_API_KEY="$OPENCODE_API_KEY"
export OPENAI_API_BASE="$BASE"

# Probes alineadas a OWASP LLM01 (prompt injection / jailbreak) y LLM02 (leak).
garak \
  --model_type openai \
  --model_name "$MODEL" \
  --probes promptinject,dan,latentinjection,leakreplay,encoding \
  --generations 3 \
  --report_prefix "$OUT/garak-$(date +%Y%m%d)" \
  "$@"

echo "Reporte en $OUT/  (garak-*.report.jsonl + .html)"
