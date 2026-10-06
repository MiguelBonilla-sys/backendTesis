#!/usr/bin/env bash
# T35 — recuperabilidad: caída de PostgreSQL y de Redis con carga, y restauración desde pg_dump.
# Uso: recovery.sh <out_dir>   (entorno de pruebas perf-pg / perf-redis, backend en :18200)
set -euo pipefail
OUT=${1:?out dir}
BASE=http://127.0.0.1:18200
JS="$(dirname "$0")/perf.js"
export BASE STUDENT=jsfandinon@academia.usbbog.edu.co ADMIN=mabonillat@academia.usbbog.edu.co
export PASS='PerfTest2026!'
psqlc() { podman exec perf-pg psql -U postgres -d phishing_detector -Atc "$1"; }
log() { echo "$(date +%H:%M:%S) $*" | tee -a "$OUT/recovery-timeline.txt"; }

: > "$OUT/recovery-timeline.txt"
log "incidentes antes: $(psqlc 'select count(*) from incidents')"

# 1) Caída de PostgreSQL durante 30 s con 5 usuarios virtuales constantes (3 min).
MODE=rendimiento VUS=5 DUR=3m k6 run --quiet --summary-export "$OUT/k6-recovery-pg.json" \
  --out json="$OUT/k6-recovery-pg-points.json" "$JS" > "$OUT/k6-recovery-pg.txt" 2>&1 &
K6=$!
sleep 60; log "postgres STOP"; podman stop -t 5 perf-pg >/dev/null
sleep 30; log "postgres START"; podman start perf-pg >/dev/null
until podman exec perf-pg pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
log "postgres listo"
wait $K6 || true
log "incidentes después: $(psqlc 'select count(*) from incidents')"

# 2) Caída de Redis durante 15 s (sesiones y rate limiter dependen de él).
MODE=rendimiento VUS=5 DUR=90s k6 run --quiet --summary-export "$OUT/k6-recovery-redis.json" \
  --out json="$OUT/k6-recovery-redis-points.json" "$JS" > "$OUT/k6-recovery-redis.txt" 2>&1 &
K6=$!
sleep 30; log "redis STOP"; podman stop -t 5 perf-redis >/dev/null
sleep 15; log "redis START"; podman start perf-redis >/dev/null
wait $K6 || true

# 3) Respaldo y restauración: pg_dump -> base nueva -> conteos y migraciones idénticos.
podman exec perf-pg pg_dump -U postgres -Fc phishing_detector > "$OUT/backup.dump"
log "pg_dump: $(wc -c < "$OUT/backup.dump") bytes"
podman exec perf-pg psql -U postgres -c "DROP DATABASE IF EXISTS restore_check" >/dev/null
podman exec perf-pg psql -U postgres -c "CREATE DATABASE restore_check" >/dev/null
podman exec -i perf-pg pg_restore -U postgres -d restore_check < "$OUT/backup.dump"
for q in "select count(*) from incidents" "select count(*) from users" "select count(*) from roles" \
         "select string_agg(version, ',' order by version) from schema_migrations"; do
  a=$(psqlc "$q"); b=$(podman exec perf-pg psql -U postgres -d restore_check -Atc "$q")
  log "restauración [$q]: original=$a restaurada=$b $([ "$a" = "$b" ] && echo OK || echo DIFIERE)"
done
rm -f "$OUT/backup.dump"
gzip -f "$OUT"/k6-recovery-*-points.json
