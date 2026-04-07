# Data Management Guide

Guia operativa para compartir la misma data entre companeros usando snapshots (sin subir artefactos al repositorio).

## Alcance

Servicios contemplados:
- PostgreSQL (`DATABASE_URL`)
- ChromaDB (`CHROMADB_HOST`, `CHROMADB_PORT`)
- Redis (`REDIS_URL`)
- LlamaStack (`LLAMASTACK_URL`)

Este flujo asume que cada companero levanta contenedores localmente y solo intercambian snapshots.

## Levantar dependencias con Compose

Este repositorio incluye un compose dedicado para servicios de datos:

```bash
docker compose -f docker-compose.deps.yml up -d
```

Detener servicios:

```bash
docker compose -f docker-compose.deps.yml down
```

Ver estado:

```bash
docker compose -f docker-compose.deps.yml ps
```

El compose ya usa nombres compatibles con los scripts:
- Contenedores: `bt-postgres`, `bt-chroma`, `bt-redis`, `bt-llamastack`
- Volumenes: `backendtesis-deps_chroma_data`, `backendtesis-deps_llama_data` (via `name: backendtesis-deps`)

## Flujo recomendado (automatico)

Usa scripts del repositorio para minimizar errores manuales.

Exportar:

```bash
bash ./scripts/snapshot-export.sh
```

Importar:

```bash
bash ./scripts/snapshot-import.sh --snapshot backups/snapshot_YYYYMMDD_HHMMSS.tar.gz
```

Opciones utiles:

```bash
bash ./scripts/snapshot-export.sh --timestamp 20260407_120000 --backup-root backups
bash ./scripts/snapshot-import.sh --snapshot backups/snapshot_20260407_120000.tar.gz --force
```

Ayuda:

```bash
bash ./scripts/snapshot-export.sh --help
bash ./scripts/snapshot-import.sh --help
```

## Convencion recomendada

Usar timestamp y carpeta dedicada por export:

```bash
TS="$(date +%Y%m%d_%H%M%S)"
SNAP_DIR="backups/${TS}"
mkdir -p "$SNAP_DIR"
```

Nombres sugeridos:
- `postgres_${TS}.dump`
- `redis_${TS}.rdb`
- `chroma_${TS}.tar.gz`
- `llamastack_${TS}.tar.gz`
- `checksums_${TS}.sha256`

## Variables de entorno operativas

Define los nombres/volumenes una sola vez por terminal:

```bash
export PG_CONTAINER="bt-postgres"
export REDIS_CONTAINER="bt-redis"
export CHROMA_CONTAINER="bt-chroma"
export LLAMA_CONTAINER="bt-llamastack"

# Ajusta estos dos nombres segun tus volumenes Docker reales
export CHROMA_VOLUME="backendtesis-deps_chroma_data"
export LLAMA_VOLUME="backendtesis-deps_llama_data"
```

Tip para descubrir volumenes:

```bash
docker volume ls
```

## Exportar snapshots (equipo origen)

Si usas scripts automaticos, esta seccion puede quedar como referencia de bajo nivel.

### 1) PostgreSQL

```bash
docker exec "$PG_CONTAINER" \
  pg_dump -U postgres -d phishing_detector -Fc \
  > "$SNAP_DIR/postgres_${TS}.dump"
```

### 2) Redis

```bash
docker exec "$REDIS_CONTAINER" redis-cli SAVE
docker cp "$REDIS_CONTAINER":/data/dump.rdb "$SNAP_DIR/redis_${TS}.rdb"
```

### 3) ChromaDB (volumen)

```bash
docker run --rm \
  -v "$CHROMA_VOLUME":/from \
  -v "$PWD/$SNAP_DIR":/to \
  alpine sh -c "cd /from && tar czf /to/chroma_${TS}.tar.gz ."
```

### 4) LlamaStack (volumen/config local)

```bash
docker run --rm \
  -v "$LLAMA_VOLUME":/from \
  -v "$PWD/$SNAP_DIR":/to \
  alpine sh -c "cd /from && tar czf /to/llamastack_${TS}.tar.gz ."
```

### 5) Checksum y paquete final

```bash
(
  cd "$SNAP_DIR"
  shasum -a 256 * > "checksums_${TS}.sha256"
)

tar czf "snapshot_${TS}.tar.gz" -C backups "$TS"
```

## Compartir con companero

1. Compartir solo `snapshot_${TS}.tar.gz` por Drive/OneDrive/S3/etc.
2. Enviar tambien checksum por canal separado (chat seguro o gestor de secretos).
3. No compartir archivos `.env`, llaves API ni JWT secrets dentro del snapshot.

Opcional cifrado:

```bash
gpg --symmetric --cipher-algo AES256 "snapshot_${TS}.tar.gz"
```

## Importar snapshots (equipo destino)

Si usas scripts automaticos, esta seccion puede quedar como referencia de bajo nivel.

### 1) Extraer paquete

```bash
mkdir -p incoming
tar xzf "snapshot_${TS}.tar.gz" -C incoming
IMPORT_DIR="incoming/${TS}"
```

### 2) Validar integridad

```bash
(
  cd "$IMPORT_DIR"
  shasum -a 256 -c "checksums_${TS}.sha256"
)
```

### 3) Restaurar PostgreSQL

```bash
docker exec "$PG_CONTAINER" psql -U postgres -d postgres -c "DROP DATABASE IF EXISTS phishing_detector;"
docker exec "$PG_CONTAINER" psql -U postgres -d postgres -c "CREATE DATABASE phishing_detector;"

cat "$IMPORT_DIR/postgres_${TS}.dump" | docker exec -i "$PG_CONTAINER" \
  pg_restore -U postgres -d phishing_detector --no-owner --no-privileges
```

### 4) Restaurar Redis

```bash
docker cp "$IMPORT_DIR/redis_${TS}.rdb" "$REDIS_CONTAINER":/data/dump.rdb
docker restart "$REDIS_CONTAINER"
```

### 5) Restaurar ChromaDB

```bash
docker stop "$CHROMA_CONTAINER"
docker run --rm \
  -v "$CHROMA_VOLUME":/to \
  -v "$PWD/$IMPORT_DIR":/from \
  alpine sh -c "rm -rf /to/* && cd /to && tar xzf /from/chroma_${TS}.tar.gz"
docker start "$CHROMA_CONTAINER"
```

### 6) Restaurar LlamaStack

```bash
docker stop "$LLAMA_CONTAINER"
docker run --rm \
  -v "$LLAMA_VOLUME":/to \
  -v "$PWD/$IMPORT_DIR":/from \
  alpine sh -c "rm -rf /to/* && cd /to && tar xzf /from/llamastack_${TS}.tar.gz"
docker start "$LLAMA_CONTAINER"
```

## Validacion post-restore

```bash
docker exec "$PG_CONTAINER" psql -U postgres -d phishing_detector -c "SELECT 1;"
docker exec "$REDIS_CONTAINER" redis-cli ping
curl -sS "http://localhost:8001/api/v2/heartbeat"
curl -sS "http://localhost:5001/v1/health"
```

## Politica recomendada de retencion

- Retener snapshots maximo 14 dias.
- Mantener ultimo snapshot valido por servicio.
- Borrar snapshots locales antiguos en cada cierre de sprint.

## Seguridad

- Nunca subir snapshots al repositorio Git.
- Nunca incluir secretos (`.env`, API keys, JWT secrets).
- Preferir checksum + cifrado cuando se comparte fuera de la red interna.
