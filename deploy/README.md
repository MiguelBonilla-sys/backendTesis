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

## Segunda instancia — Render (failover)

Topología: el **primario (Coolify) es 100% local** (sus PG/Redis/Chroma +
`embeddinggemma` por Ollama, `docker-compose.coolify.yml` sin cambios) y se
**sincroniza** hacia la capa free-tier. El **secundario (Render)** corre contra
esa capa (Neon + Redis Cloud + Chroma Cloud + `embeddinggemma` por HuggingFace).

```
Coolify backend ── PG/Redis/Chroma LOCALES + Ollama(embeddinggemma)   (autoritativo)
       │
       └── cron deploy/sync-standby.sh (host Coolify, */15) ──▶ Neon + Chroma Cloud
                                                                   ▲
Render backend ── Neon + Redis Cloud + Chroma Cloud + HF(embeddinggemma) ─┘
```

- **Primario**: Coolify. Sin cambios en el compose. `EMBED_PROVIDER=ollama`.
- **Secundario**: `../render.yaml` (blueprint). Render no corre compose → un solo
  Web Service desde el `Dockerfile`. Dashboard → New → Blueprint → repo `backendTesis`.
  `EMBED_PROVIDER=hf` + `google/embeddinggemma-300m` vía HuggingFace Inference
  (`feature-extraction`) — mismo modelo que el Ollama de Coolify, sin correr Ollama.

### Sincronización primario → standby (`deploy/sync-standby.sh`)

Cron en el **host de Coolify** (`*/15 * * * *`), con `APP_UUID`, `STANDBY_DATABASE_URL`
(Neon, libpq), `STANDBY_CHROMA_*` y `STANDBY_EMBED_*` en el entorno.

| Componente | Cómo | Nota |
|---|---|---|
| **PostgreSQL** | `pg_dump --clean --if-exists` del contenedor local → `psql --single-transaction` a Neon | restore atómico; ventana de pérdida ≤ intervalo del cron |
| **ChromaDB** | `scripts.sync_chroma_standby` — copia `documents`+`metadatas` de las 5 colecciones y **re-embebe con HF** antes de escribir en Chroma Cloud. Paginado de a 300 (límite free tier) | `--check` compara conteo+dimensión; `--reverse` hidrata un Chroma local; `--prune` propaga borrados |
| **Redis** | **no se sincroniza** | caché de TI (TTL 1h); tras el failover se repuebla solo desde las TI APIs, dentro de la cuota gratis |

**Por qué re-embebe y no copia vectores.** Coolify embebe con Ollama (GGUF) y
Render/Cloud con HuggingFace. Es el **mismo modelo** (`embeddinggemma-300m`, 768d)
pero **distinto stack de serving**: para el mismo texto los vectores dan
`cos ≈ 0.6`, no son intercambiables (Ollama aplica los prompts de tarea de
embeddinggemma vía template; el `feature-extraction` de HF embebe el texto crudo).
Copiar vectores cruzaría dos espacios → retrieval de Render degradada. Por eso el
sync trae solo el texto y lo re-embebe con `STANDBY_EMBED_*` (HF).

Cada entorno queda **internamente consistente**: Coolify escribe y consulta con
Ollama; Chroma Cloud tiene vectores HF y Render consulta con HF. Los `id`, el
texto y la metadata son idénticos en los dos lados; solo difieren los vectores.
`verify_rag_knowledge` → hit@3 ≈ 1.0 en ambos.

fal.run no tiene embeddinggemma. Si HF se queda corto de cuota, el fallback es
`EMBED_PROVIDER=openai` + fal `baai/bge-m3` (1024d) en Render/Cloud — implica
re-seedear las 5 colecciones de Chroma Cloud con ese modelo.

**Failback (importante):** el sync es una vía. Si Render sirve escrituras mientras
Coolify está caído y luego Coolify vuelve, el próximo `pg_dump` **pisa** esos datos.
Al recuperar Coolify: pausar el cron, migrar a mano lo que Render haya escrito
(volumen bajo: `incidents`/`feedback` nuevos), reanudar.

Alternativa a menor lag para Postgres: replicación lógica con Neon como *subscriber*
(`wal_level=logical` + `CREATE PUBLICATION` en Coolify). Necesita que Neon alcance
la PG de Coolify (exponerla con TLS+allowlist, o un túnel). El dump por cron alcanza
para la tesis.

**Reglas para que el failover sea transparente:**

1. `SECRET_KEY` / `JWT_SECRET_KEY` **idénticos** en las dos instancias (si no, el
   JWT emitido por una no vale en la otra).
2. `EMBED_MODEL` = `embeddinggemma-300m` (768d) en las dos; solo cambia el
   `EMBED_PROVIDER` (`ollama` en Coolify, `hf` en Render). El sync re-embebe, así
   que la dimensión coincide y `--check` da paridad.
3. Lista completa de vars: `env.shared.example`.

**Schema en Neon** (una vez): correr `schema.sql` + `seed_users.sql` contra el
`DATABASE_URL` de Neon (idempotentes). Sin `psql` a mano: hay un script asyncpg en
el scratchpad de la sesión, o `python -c` con `asyncpg.connect(...).execute(open(...).read())`.

**Seed del RAG en Chroma Cloud** (una vez, desde cualquier entorno con el `.env`):
`python -m scripts.seed_usb_institutional --apply`, `scripts.seed_chromadb --apply`,
`scripts.ingest_firecrawl_knowledge --apply`, luego `scripts.verify_rag_knowledge`.

## Notas

- `TOP1M_LIMIT` (default 1_000_000) acota el índice top-1M que el IDN agent carga en
  el BK-tree al arrancar. En CPU lenta, cargar todo tarda varios minutos; el compose
  lo fija en `150000` (~75 s de arranque, cobertura suficiente para impersonation real).
- El backend degrada solo (no bloquea) si ChromaDB, Ollama, el gateway LLM o HF fallan.
- Cloudflare en modo Flexible + redirect-to-https de Traefik = loop 302. Si el dominio
  redirige en bucle, apagar "Redirect to HTTPS" en el recurso Coolify.
