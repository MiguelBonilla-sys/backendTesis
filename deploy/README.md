# Deploy — Coolify (Docker Compose)

`docker-compose.coolify.yml` levanta el stack completo: `backend` (build desde
`../Dockerfile`) + `postgres` + `redis` + `chromadb` + `ollama` (embeddinggemma).
El dominio se asigna al servicio `backend:8000` desde la config del recurso en Coolify.

## Variables de entorno del recurso (Coolify → Environment Variables)

Secrets (no van al repo): `LLM_API_KEY`, `HUGGINGFACE_API_KEY`, `VIRUSTOTAL_API_KEY`,
`URLSCAN_API_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`, `WHOISXML_API_KEY`,
`POSTGRES_PASSWORD`, `SECRET_KEY`, `JWT_SECRET_KEY`.
Resto: `LLM_MODEL`, `LLM_MODEL_FALLBACK`, `LLM_PROVIDER`, `LLM_BASE_URL`,
`POSTGRES_USER`, `POSTGRES_DB`, `CORS_ORIGINS`.

## Schema de la base (una sola vez por volumen `pgdata` nuevo)

Coolify pre-crea los bind mounts a archivos del repo como **directorios vacíos**,
así que el schema no se puede montar en `/docker-entrypoint-initdb.d/`. Cargarlo a mano:

```bash
PC=$(docker ps --filter "name=postgres-<app_uuid>" --format '{{.Names}}' | head -1)
docker exec -i "$PC" psql -U postgres -d phishing_detector -v ON_ERROR_STOP=1 < deploy/schema.sql
docker exec -i "$PC" psql -U postgres -d phishing_detector -v ON_ERROR_STOP=1 < deploy/seed_users.sql
```

`schema.sql` es idempotente (`CREATE ... IF NOT EXISTS`) — re-ejecutarlo no rompe nada.

## Seed del RAG (ChromaDB) — después de que `backend` esté healthy

El contenedor corre como `appuser` (no-root); los scripts escriben snapshots bajo
`../.firecrawl`, así que se copian a `/app/.firecrawl` y se corre como root (op puntual).

```bash
BC=$(docker ps --filter "name=backend-<app_uuid>" --format '{{.Names}}' | head -1)
docker cp .firecrawl "$BC:/.firecrawl"                 # snapshots Firecrawl revisados (fuera de git)
X="docker exec -u root -w /app $BC python -m"
$X scripts.ingest_firecrawl_knowledge --apply
$X scripts.ingest_firecrawl_knowledge --sources data/real_case_sources.json --output ../.firecrawl/real-cases --apply
$X scripts.seed_usb_institutional --apply
$X scripts.seed_chromadb --apply
$X scripts.verify_rag_knowledge
```

## Notas

- `TOP1M_LIMIT` (default 1_000_000) acota el índice top-1M que el IDN agent carga en
  el BK-tree al arrancar. En CPU lenta, cargar todo tarda varios minutos; el compose
  lo fija en `150000` (~75 s de arranque, cobertura suficiente para impersonation real).
- El backend degrada solo (no bloquea) si ChromaDB, Ollama, el gateway LLM o HF fallan.
- Cloudflare en modo Flexible + redirect-to-https de Traefik = loop 302. Si el dominio
  redirige en bucle, apagar "Redirect to HTTPS" en el recurso Coolify.
