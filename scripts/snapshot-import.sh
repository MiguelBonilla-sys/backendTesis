#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash ./scripts/snapshot-import.sh --snapshot PATH [--incoming-root DIR] [--force]

Options:
  --snapshot PATH     Snapshot bundle path (snapshot_YYYYMMDD_HHMMSS.tar.gz)
                      or extracted snapshot folder path
  --incoming-root DIR Extraction folder for bundles (default: incoming)
  --force             Skip destructive action confirmation
  -h, --help          Show this help

Environment overrides:
  PG_CONTAINER        Default: bt-postgres
  REDIS_CONTAINER     Default: bt-redis
  CHROMA_CONTAINER    Default: bt-chroma
  LLAMA_CONTAINER     Default: bt-llamastack
  CHROMA_VOLUME       Default: backendtesis-deps_chroma_data
  LLAMA_VOLUME        Default: backendtesis-deps_llama_data
  PG_USER             Default: postgres
  PG_DB               Default: phishing_detector
EOF
}

SNAPSHOT_PATH=""
INCOMING_ROOT="incoming"
FORCE="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --snapshot)
      SNAPSHOT_PATH="${2:-}"
      shift 2
      ;;
    --incoming-root)
      INCOMING_ROOT="${2:-}"
      shift 2
      ;;
    --force)
      FORCE="true"
      shift
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

if [[ -z "$SNAPSHOT_PATH" ]]; then
  echo "--snapshot is required." >&2
  usage
  exit 1
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_cmd docker
require_cmd tar

verify_cmd() {
  if command -v sha256sum >/dev/null 2>&1; then
    echo "sha256sum"
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    echo "shasum"
    return
  fi
  echo ""
}

VERIFY_CMD="$(verify_cmd)"
if [[ -z "$VERIFY_CMD" ]]; then
  echo "Missing checksum command (sha256sum or shasum)." >&2
  exit 1
fi

container_exists() {
  docker container inspect "$1" >/dev/null 2>&1
}

container_running() {
  docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null | grep -qi true
}

volume_exists() {
  docker volume inspect "$1" >/dev/null 2>&1
}

confirm_destructive() {
  if [[ "$FORCE" == "true" ]]; then
    return
  fi

  echo "This will replace PostgreSQL DB, Redis dump, Chroma volume, and LlamaStack volume if present."
  read -r -p "Type yes to continue: " answer
  if [[ "$answer" != "yes" ]]; then
    echo "Aborted by user."
    exit 1
  fi
}

PG_CONTAINER="${PG_CONTAINER:-bt-postgres}"
REDIS_CONTAINER="${REDIS_CONTAINER:-bt-redis}"
CHROMA_CONTAINER="${CHROMA_CONTAINER:-bt-chroma}"
LLAMA_CONTAINER="${LLAMA_CONTAINER:-bt-llamastack}"
CHROMA_VOLUME="${CHROMA_VOLUME:-backendtesis-deps_chroma_data}"
LLAMA_VOLUME="${LLAMA_VOLUME:-backendtesis-deps_llama_data}"
PG_USER="${PG_USER:-postgres}"
PG_DB="${PG_DB:-phishing_detector}"

IMPORT_DIR=""
TS=""

if [[ -d "$SNAPSHOT_PATH" ]]; then
  IMPORT_DIR="$SNAPSHOT_PATH"
  TS="$(basename "$IMPORT_DIR")"
elif [[ -f "$SNAPSHOT_PATH" ]]; then
  mkdir -p "$INCOMING_ROOT"

  base_name="$(basename "$SNAPSHOT_PATH")"
  if [[ "$base_name" =~ ^snapshot_([0-9]{8}_[0-9]{6})\.tar\.gz$ ]]; then
    TS="${BASH_REMATCH[1]}"
  else
    TS="import_$(date +%Y%m%d_%H%M%S)"
  fi

  tar xzf "$SNAPSHOT_PATH" -C "$INCOMING_ROOT"
  if [[ -d "${INCOMING_ROOT}/${TS}" ]]; then
    IMPORT_DIR="${INCOMING_ROOT}/${TS}"
  else
    first_dir="$(tar tzf "$SNAPSHOT_PATH" | head -n1 | cut -d/ -f1)"
    IMPORT_DIR="${INCOMING_ROOT}/${first_dir}"
    TS="$(basename "$IMPORT_DIR")"
  fi
else
  echo "Snapshot path does not exist: $SNAPSHOT_PATH" >&2
  exit 1
fi

if [[ ! -d "$IMPORT_DIR" ]]; then
  echo "Import directory not found after extraction: $IMPORT_DIR" >&2
  exit 1
fi

IMPORT_DIR_ABS="$(cd "$IMPORT_DIR" && pwd)"

echo "[info] Import directory: ${IMPORT_DIR_ABS}"

checksum_file="${IMPORT_DIR_ABS}/checksums_${TS}.sha256"
if [[ ! -f "$checksum_file" ]]; then
  checksum_file="$(find "$IMPORT_DIR_ABS" -maxdepth 1 -name 'checksums_*.sha256' | head -n1 || true)"
fi

if [[ -n "$checksum_file" && -f "$checksum_file" ]]; then
  echo "[verify] Checksums from $(basename "$checksum_file")"
  (
    cd "$IMPORT_DIR_ABS"
    if [[ "$VERIFY_CMD" == "sha256sum" ]]; then
      sha256sum -c "$(basename "$checksum_file")"
    else
      shasum -a 256 -c "$(basename "$checksum_file")"
    fi
  )
else
  echo "[warn] Checksums file not found. Continuing without integrity verification."
fi

confirm_destructive

postgres_file="${IMPORT_DIR_ABS}/postgres_${TS}.dump"
if [[ ! -f "$postgres_file" ]]; then
  postgres_file="$(find "$IMPORT_DIR_ABS" -maxdepth 1 -name 'postgres_*.dump' | head -n1 || true)"
fi

if [[ -n "$postgres_file" && -f "$postgres_file" ]]; then
  if container_exists "$PG_CONTAINER"; then
    echo "[restore] PostgreSQL from $(basename "$postgres_file")"
    docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d postgres -c "DROP DATABASE IF EXISTS ${PG_DB};"
    docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d postgres -c "CREATE DATABASE ${PG_DB};"
    cat "$postgres_file" | docker exec -i "$PG_CONTAINER" pg_restore -U "$PG_USER" -d "$PG_DB" --no-owner --no-privileges
  else
    echo "[warn] PostgreSQL container not found: ${PG_CONTAINER}. Skipping."
  fi
else
  echo "[warn] PostgreSQL dump not found. Skipping."
fi

redis_file="${IMPORT_DIR_ABS}/redis_${TS}.rdb"
if [[ ! -f "$redis_file" ]]; then
  redis_file="$(find "$IMPORT_DIR_ABS" -maxdepth 1 -name 'redis_*.rdb' | head -n1 || true)"
fi

if [[ -n "$redis_file" && -f "$redis_file" ]]; then
  if container_exists "$REDIS_CONTAINER"; then
    echo "[restore] Redis from $(basename "$redis_file")"
    docker cp "$redis_file" "${REDIS_CONTAINER}:/data/dump.rdb"
    docker restart "$REDIS_CONTAINER" >/dev/null
  else
    echo "[warn] Redis container not found: ${REDIS_CONTAINER}. Skipping."
  fi
else
  echo "[warn] Redis dump not found. Skipping."
fi

chroma_file="${IMPORT_DIR_ABS}/chroma_${TS}.tar.gz"
if [[ ! -f "$chroma_file" ]]; then
  chroma_file="$(find "$IMPORT_DIR_ABS" -maxdepth 1 -name 'chroma_*.tar.gz' | head -n1 || true)"
fi

if [[ -n "$chroma_file" && -f "$chroma_file" ]]; then
  if volume_exists "$CHROMA_VOLUME"; then
    echo "[restore] Chroma volume from $(basename "$chroma_file")"
    if container_exists "$CHROMA_CONTAINER" && container_running "$CHROMA_CONTAINER"; then
      docker stop "$CHROMA_CONTAINER" >/dev/null
    fi
    docker run --rm \
      -v "${CHROMA_VOLUME}:/to" \
      -v "${IMPORT_DIR_ABS}:/from" \
      alpine sh -c "find /to -mindepth 1 -delete && cd /to && tar xzf /from/$(basename "$chroma_file")"
    if container_exists "$CHROMA_CONTAINER"; then
      docker start "$CHROMA_CONTAINER" >/dev/null
    fi
  else
    echo "[warn] Chroma volume not found: ${CHROMA_VOLUME}. Skipping."
  fi
else
  echo "[warn] Chroma archive not found. Skipping."
fi

llama_file="${IMPORT_DIR_ABS}/llamastack_${TS}.tar.gz"
if [[ ! -f "$llama_file" ]]; then
  llama_file="$(find "$IMPORT_DIR_ABS" -maxdepth 1 -name 'llamastack_*.tar.gz' | head -n1 || true)"
fi

if [[ -n "$llama_file" && -f "$llama_file" ]]; then
  if volume_exists "$LLAMA_VOLUME"; then
    echo "[restore] LlamaStack volume from $(basename "$llama_file")"
    if container_exists "$LLAMA_CONTAINER" && container_running "$LLAMA_CONTAINER"; then
      docker stop "$LLAMA_CONTAINER" >/dev/null
    fi
    docker run --rm \
      -v "${LLAMA_VOLUME}:/to" \
      -v "${IMPORT_DIR_ABS}:/from" \
      alpine sh -c "find /to -mindepth 1 -delete && cd /to && tar xzf /from/$(basename "$llama_file")"
    if container_exists "$LLAMA_CONTAINER"; then
      docker start "$LLAMA_CONTAINER" >/dev/null
    fi
  else
    echo "[warn] LlamaStack volume not found: ${LLAMA_VOLUME}. Skipping."
  fi
else
  echo "[warn] LlamaStack archive not found. Skipping."
fi

echo "[ok] Import completed from ${IMPORT_DIR_ABS}"
