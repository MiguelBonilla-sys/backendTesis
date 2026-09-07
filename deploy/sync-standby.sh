#!/bin/sh
# Sincroniza el estado de la instancia primaria (Coolify, DBs locales) hacia la
# standby free-tier, para que la 2a instancia del backend (Render) tenga lo mismo
# si Coolify se cae.
#
#   PostgreSQL -> dump completo del primario, restore atomico en Neon.
#   ChromaDB   -> las 5 colecciones hacia Chroma Cloud, RE-EMBEBIENDO los docs con
#                 el embedder del destino (HF). Coolify embebe con Ollama y Render
#                 con HuggingFace: aunque es el MISMO modelo (embeddinggemma-300m),
#                 los stacks dan vectores distintos (cos ~0.6 para el mismo texto),
#                 asi que copiar vectores tal cual romperia la retrieval de Render.
#   Redis      -> NO se sincroniza: es cache de TI (TTL 1h). Tras el failover se
#                 repuebla solo desde las TI APIs, dentro de la cuota gratuita.
#
# Correr en el HOST de Coolify por cron, p. ej.:
#   */15 * * * * APP_UUID=2tfwirwa01imva8glms5kf4w \
#     STANDBY_DATABASE_URL='postgresql://neondb_owner:...@ep-...-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require' \
#     STANDBY_CHROMA_HOST=api.trychroma.com STANDBY_CHROMA_PORT=443 \
#     STANDBY_CHROMA_API_KEY=ck-... STANDBY_CHROMA_TENANT=<uuid> STANDBY_CHROMA_DATABASE=tesis \
#     STANDBY_EMBED_MODEL=google/embeddinggemma-300m \
#     STANDBY_EMBED_BASE_URL=https://router.huggingface.co/hf-inference/models \
#     STANDBY_EMBED_API_KEY=hf_... \
#     /data/coolify/.../backendTesis/deploy/sync-standby.sh >> /var/log/sync-standby.log 2>&1
#
# OJO failback: el sync es una via (primario -> standby). Si Render sirve escrituras
# mientras Coolify esta caido y luego Coolify vuelve, el proximo dump PISA esos datos.
# Al recuperar Coolify: pausar este cron, migrar a mano lo que Render haya escrito, reanudar.
set -eu

: "${APP_UUID:?exporta APP_UUID del recurso Coolify}"
: "${STANDBY_DATABASE_URL:?exporta STANDBY_DATABASE_URL (Neon, formato libpq)}"
: "${STANDBY_EMBED_MODEL:?exporta STANDBY_EMBED_MODEL (re-embed del corpus RAG)}"

PGC=$(docker ps --filter "name=postgres-${APP_UUID}" --format '{{.Names}}' | head -1)
BKC=$(docker ps --filter "name=backend-${APP_UUID}"  --format '{{.Names}}' | head -1)
[ -n "$PGC" ] || { echo "no encuentro el contenedor postgres-${APP_UUID}"; exit 1; }
[ -n "$BKC" ] || { echo "no encuentro el contenedor backend-${APP_UUID}"; exit 1; }

echo "== $(date -u +%FT%TZ) sync-standby =="

# --- PostgreSQL ---
docker exec "$PGC" pg_dump --no-owner --no-acl --clean --if-exists \
    -U postgres -d phishing_detector \
  | docker run -i --rm postgres:15-alpine \
      psql --single-transaction -v ON_ERROR_STOP=1 "$STANDBY_DATABASE_URL" >/dev/null
echo "  postgres OK"

# --- ChromaDB (re-embed con HF) ---
docker exec \
    -e STANDBY_CHROMA_HOST -e STANDBY_CHROMA_PORT -e STANDBY_CHROMA_API_KEY \
    -e STANDBY_CHROMA_TENANT -e STANDBY_CHROMA_DATABASE \
    -e STANDBY_EMBED_PROVIDER -e STANDBY_EMBED_MODEL -e STANDBY_EMBED_BASE_URL \
    -e STANDBY_EMBED_API_KEY -e STANDBY_EMBED_AUTH_SCHEME \
    "$BKC" python -m scripts.sync_chroma_standby
echo "  chroma OK"

echo "== done =="
