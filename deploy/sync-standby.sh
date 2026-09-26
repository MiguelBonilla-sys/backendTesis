#!/bin/sh
# Explicit authoritative snapshot. Both application writer sets must be paused;
# destination stays fenced until PG + Chroma complete and app caches are reset.
# Do not schedule this script unattended. See docs/synchronization-and-learning.md.
# Usage: sync-standby.sh local|standby --replica-fenced --source-quiesced
set -eu

AUTHORITY="${1:-}"
case "$AUTHORITY" in local|standby) ;; *) echo "usage: $0 local|standby --replica-fenced --source-quiesced" >&2; exit 2 ;; esac
[ "${2:-}" = "--replica-fenced" ] && [ "${3:-}" = "--source-quiesced" ] || {
  echo "Destination must be fenced and source writers paused; explicit flags required." >&2; exit 2;
}

: "${APP_UUID:?exporta APP_UUID del recurso Coolify}"
: "${STANDBY_DATABASE_URL:?exporta STANDBY_DATABASE_URL (Neon DIRECTO, libpq)}"
: "${STANDBY_EMBED_MODEL:?exporta STANDBY_EMBED_MODEL (re-embed del corpus RAG)}"
: "${SOURCE_EMBED_SPACE:?exporta el embedding_space verificado del origen}"
: "${DESTINATION_EMBED_SPACE:?exporta el embedding_space verificado del destino}"

# Lock: si una corrida previa sigue viva (el snapshot puede tardar
# varios minutos), saltar en vez de solapar.
LOCK="${TMPDIR:-/tmp}/sync-standby.lock"
if ! mkdir "$LOCK" 2>/dev/null; then
  echo "$(date -u +%FT%TZ) sync-standby ya corriendo ($LOCK) — salto"
  exit 0
fi
trap 'rmdir "$LOCK" 2>/dev/null' EXIT INT TERM

BKC=$(docker ps --filter "name=backend-${APP_UUID}" --format '{{.Names}}' | head -1)
[ -n "$BKC" ] || { echo "no encuentro el contenedor backend-${APP_UUID}"; exit 1; }

echo "== $(date -u +%FT%TZ) sync-standby (authority=$AUTHORITY) =="

CHROMA_ENVS="-e STANDBY_CHROMA_HOST -e STANDBY_CHROMA_PORT -e STANDBY_CHROMA_API_KEY \
  -e STANDBY_CHROMA_TENANT -e STANDBY_CHROMA_DATABASE \
  -e STANDBY_EMBED_PROVIDER -e STANDBY_EMBED_MODEL -e STANDBY_EMBED_BASE_URL \
  -e STANDBY_EMBED_API_KEY -e STANDBY_EMBED_AUTH_SCHEME"

# PostgreSQL authoritative mirror, including security changes and deletes
# shellcheck disable=SC2086
docker exec -e STANDBY_DATABASE_URL "$BKC" python -m scripts.sync_pg_bilateral --authority "$AUTHORITY" --replica-fenced --source-quiesced
echo "  postgres OK"

# Chroma mirror in the same direction; never merge missing stale IDs back
# shellcheck disable=SC2086
docker exec $CHROMA_ENVS "$BKC" python -m scripts.sync_chroma_standby --authority "$AUTHORITY" --replica-fenced --source-quiesced --source-space "$SOURCE_EMBED_SPACE" --destination-space "$DESTINATION_EMBED_SPACE"
echo "  chroma OK"

echo "== done =="
