#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash ./scripts/snapshot-export.sh [--timestamp TS] [--backup-root DIR]

Options:
  --timestamp TS      Override timestamp (format: YYYYMMDD_HHMMSS)
  --backup-root DIR   Output root folder for snapshots (default: backups)
  -h, --help          Show this help

Environment overrides:
  PG_CONTAINER        Default: bt-postgres
  REDIS_CONTAINER     Default: bt-redis
  CHROMA_VOLUME       Default: backendtesis-deps_chroma_data
  LLAMA_VOLUME        Default: backendtesis-deps_llama_data
  PG_USER             Default: postgres
  PG_DB               Default: phishing_detector
EOF
}

TIMESTAMP=""
BACKUP_ROOT="backups"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --timestamp)
      TIMESTAMP="${2:-}"
      shift 2
      ;;
    --backup-root)
      BACKUP_ROOT="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_cmd docker
require_cmd tar

hash_cmd() {
  if command -v sha256sum >/dev/null 2>&1; then
    echo "sha256sum"
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    echo "shasum -a 256"
    return
  fi
  echo ""
}

HASH_CMD="$(hash_cmd)"
if [[ -z "$HASH_CMD" ]]; then
  echo "Missing checksum command (sha256sum or shasum)." >&2
  exit 1
fi

container_exists() {
  docker container inspect "$1" >/dev/null 2>&1
}

volume_exists() {
  docker volume inspect "$1" >/dev/null 2>&1
}

PG_CONTAINER="${PG_CONTAINER:-bt-postgres}"
REDIS_CONTAINER="${REDIS_CONTAINER:-bt-redis}"
CHROMA_VOLUME="${CHROMA_VOLUME:-backendtesis-deps_chroma_data}"
LLAMA_VOLUME="${LLAMA_VOLUME:-backendtesis-deps_llama_data}"
PG_USER="${PG_USER:-postgres}"
PG_DB="${PG_DB:-phishing_detector}"

TS="${TIMESTAMP:-$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$BACKUP_ROOT"
BACKUP_ROOT_ABS="$(cd "$BACKUP_ROOT" && pwd)"
SNAP_DIR="${BACKUP_ROOT_ABS}/${TS}"
mkdir -p "$SNAP_DIR"

exported_count=0

postgres_file="${SNAP_DIR}/postgres_${TS}.dump"
if container_exists "$PG_CONTAINER"; then
  echo "[export] PostgreSQL from ${PG_CONTAINER} -> ${postgres_file}"
  docker exec "$PG_CONTAINER" pg_dump -U "$PG_USER" -d "$PG_DB" -Fc > "$postgres_file"
  exported_count=$((exported_count + 1))
else
  echo "[warn] PostgreSQL container not found: ${PG_CONTAINER}. Skipping."
fi

redis_file="${SNAP_DIR}/redis_${TS}.rdb"
if container_exists "$REDIS_CONTAINER"; then
  echo "[export] Redis from ${REDIS_CONTAINER} -> ${redis_file}"
  docker exec "$REDIS_CONTAINER" redis-cli SAVE >/dev/null
  docker cp "${REDIS_CONTAINER}:/data/dump.rdb" "$redis_file"
  exported_count=$((exported_count + 1))
else
  echo "[warn] Redis container not found: ${REDIS_CONTAINER}. Skipping."
fi

chroma_file="${SNAP_DIR}/chroma_${TS}.tar.gz"
if volume_exists "$CHROMA_VOLUME"; then
  echo "[export] Chroma volume ${CHROMA_VOLUME} -> ${chroma_file}"
  docker run --rm \
    -v "${CHROMA_VOLUME}:/from" \
    -v "${SNAP_DIR}:/to" \
    alpine sh -c "cd /from && tar czf /to/chroma_${TS}.tar.gz ."
  exported_count=$((exported_count + 1))
else
  echo "[warn] Chroma volume not found: ${CHROMA_VOLUME}. Skipping."
fi

llama_file="${SNAP_DIR}/llamastack_${TS}.tar.gz"
if volume_exists "$LLAMA_VOLUME"; then
  echo "[export] LlamaStack volume ${LLAMA_VOLUME} -> ${llama_file}"
  docker run --rm \
    -v "${LLAMA_VOLUME}:/from" \
    -v "${SNAP_DIR}:/to" \
    alpine sh -c "cd /from && tar czf /to/llamastack_${TS}.tar.gz ."
  exported_count=$((exported_count + 1))
else
  echo "[warn] LlamaStack volume not found: ${LLAMA_VOLUME}. Skipping."
fi

if [[ "$exported_count" -eq 0 ]]; then
  echo "No artifacts were exported. Aborting." >&2
  exit 1
fi

checksum_file="${SNAP_DIR}/checksums_${TS}.sha256"
: > "$checksum_file"
(
  cd "$SNAP_DIR"
  for f in *; do
    [[ "$f" == "$(basename "$checksum_file")" ]] && continue
    if [[ "$HASH_CMD" == "sha256sum" ]]; then
      sha256sum "$f" >> "$(basename "$checksum_file")"
    else
      shasum -a 256 "$f" >> "$(basename "$checksum_file")"
    fi
  done
)

bundle_file="${BACKUP_ROOT_ABS}/snapshot_${TS}.tar.gz"
tar czf "$bundle_file" -C "$BACKUP_ROOT_ABS" "$TS"

echo "[ok] Snapshot folder: ${SNAP_DIR}"
echo "[ok] Snapshot bundle: ${bundle_file}"
echo "[ok] Checksums file: ${checksum_file}"
