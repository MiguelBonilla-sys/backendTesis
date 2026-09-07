#!/bin/sh
# Sync BIDIRECCIONAL entre Coolify (local, primario) y la capa free-tier (standby
# que usa Render). Merge por PK en los dos sentidos: si Coolify se cae y Render
# sirve escrituras contra Neon/Chroma Cloud, al volver Coolify esas escrituras se
# reintegran — y las de Coolify van a la standby.
#
#   PostgreSQL -> scripts.sync_pg_bilateral : upsert por PK UUID en ambos sentidos
#                 (audit_log: una via, por watermark). Sin TRUNCATE. Schema
#                 pre-cargado en Neon con deploy/schema.sql (endpoint DIRECTO).
#                 Los BORRADOS no se propagan (ver el docstring del script).
#   ChromaDB   -> scripts.sync_chroma_standby --bidirectional : merge de las 5
#                 colecciones en ambos sentidos, re-embebiendo (Coolify=Ollama,
#                 Cloud/Render=HF; mismo modelo, distinto stack → cos ~0.6, no se
#                 pueden copiar vectores). Upsert-only, sin prune.
#   Redis      -> NO se sincroniza (cache de TI, TTL 1h; se repuebla solo).
#
# Correr en el HOST de Coolify por cron:
#   */15 * * * * . $HOME/.sync-standby.env && $HOME/sync-standby.sh >> $HOME/sync-standby.log 2>&1
# Env (en ~/.sync-standby.env): APP_UUID, STANDBY_DATABASE_URL (Neon DIRECTO, libpq),
#   STANDBY_CHROMA_*, STANDBY_EMBED_* . Ver deploy/env.shared.example.
#
# Split-brain: si los DOS lados editan la MISMA fila (mismo id) en la misma
# ventana, gana el que ya estaba (ON CONFLICT DO NOTHING). Para este sistema
# (incidents/feedback son append, users cambia poco) es aceptable.
set -eu

: "${APP_UUID:?exporta APP_UUID del recurso Coolify}"
: "${STANDBY_DATABASE_URL:?exporta STANDBY_DATABASE_URL (Neon DIRECTO, libpq)}"
: "${STANDBY_EMBED_MODEL:?exporta STANDBY_EMBED_MODEL (re-embed del corpus RAG)}"

# Lock: si una corrida previa sigue viva (el sync bidireccional puede tardar
# varios minutos), saltar en vez de solapar.
LOCK="${TMPDIR:-/tmp}/sync-standby.lock"
if ! mkdir "$LOCK" 2>/dev/null; then
  echo "$(date -u +%FT%TZ) sync-standby ya corriendo ($LOCK) — salto"
  exit 0
fi
trap 'rmdir "$LOCK" 2>/dev/null' EXIT INT TERM

BKC=$(docker ps --filter "name=backend-${APP_UUID}" --format '{{.Names}}' | head -1)
[ -n "$BKC" ] || { echo "no encuentro el contenedor backend-${APP_UUID}"; exit 1; }

echo "== $(date -u +%FT%TZ) sync-standby (bidireccional) =="

CHROMA_ENVS="-e STANDBY_CHROMA_HOST -e STANDBY_CHROMA_PORT -e STANDBY_CHROMA_API_KEY \
  -e STANDBY_CHROMA_TENANT -e STANDBY_CHROMA_DATABASE \
  -e STANDBY_EMBED_PROVIDER -e STANDBY_EMBED_MODEL -e STANDBY_EMBED_BASE_URL \
  -e STANDBY_EMBED_API_KEY -e STANDBY_EMBED_AUTH_SCHEME"

# --- PostgreSQL (merge bidireccional por PK) ---
# shellcheck disable=SC2086
docker exec -e STANDBY_DATABASE_URL "$BKC" python -m scripts.sync_pg_bilateral
echo "  postgres OK"

# --- ChromaDB (merge bidireccional, re-embed por lado) ---
# shellcheck disable=SC2086
docker exec $CHROMA_ENVS "$BKC" python -m scripts.sync_chroma_standby --bidirectional
echo "  chroma OK"

echo "== done =="
