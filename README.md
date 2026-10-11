# backendTesis — API del detector de phishing por homografía IDN

API en FastAPI que recibe una URL, un correo o un archivo `.eml` y devuelve un veredicto
con su puntaje de riesgo y las razones que lo explican. La usan la extensión de navegador,
el complemento de Outlook y el dashboard de administración.

Proyecto de grado de Ingeniería de Sistemas, Universidad de San Buenaventura, Bogotá (2026).
Autores: Juan Sebastián Fandiño Novoa y Miguel Ángel Bonilla Torres.

## Cómo decide

`services/orchestrator.py` combina cinco fuentes y `agents/fusion_agent.py` calcula el riesgo final:

1. **IDN Agent** (`agents/idn_agent.py`): normaliza el dominio (NFC y Punycode), detecta
   caracteres confundibles con el catálogo Unicode TR#39 (`data/confusables.txt`) y mide la
   similitud visual contra el top de dominios (`data/top1m.txt`) con un BK-tree.
2. **Threat Intelligence** (`data_pipeline/`): VirusTotal, URLScan.io, Google Safe Browsing
   y WhoisXML, consultados en paralelo y cacheados en Redis durante una hora.
3. **LLM Agent** (`agents/llm_agent.py`): analiza el contenido con un modelo remoto a través
   de `core/llm_gateway.py`. Antes de enviar, redacta los datos personales e inyecta como
   contexto los casos parecidos que recupera de ChromaDB (RAG).
4. **Clasificador de URL de HuggingFace** (`agents/hf_agent.py`): modelo ONNX que corre dentro
   de la imagen; su puntaje se combina con el del LLM con un peso de 0,40.
5. **Sondeo web y señales del correo**: `agents/web_probe_agent.py` visita la URL con un
   cliente endurecido contra SSRF y busca formularios de login, cadenas de redirección y
   suplantación de marca. Del correo se toman SPF, DKIM, la diferencia entre remitente y
   Return-Path, la urgencia del texto y los adjuntos sospechosos (`EmailSignals` en
   `schemas/analyze.py`). Ambas señales suben el riesgo con un tope fijo.

El veredicto es `PHISHING` cuando el riesgo alcanza θ = 0,30, el umbral recalibrado en el
Sprint 6, y `LEGITIMATE` por debajo. El código conserva el nivel `SUSPICIOUS`, pero su umbral
coincide con θ y en la práctica no se emite. θ, los pesos de la fusión y la justificación
de ambos están en `core/constants.py`; no se configuran por variables de entorno.

## Requisitos

- Python 3.11 o superior (la imagen usa 3.12) y [uv](https://docs.astral.sh/uv/).
- PostgreSQL 15, Redis 7, ChromaDB 1.5.5 y Ollama con `embeddinggemma`. El compose de
  `infraTesis` los levanta.
- Una llave del gateway LLM (`LLM_API_KEY`). Las llaves de Threat Intelligence son opcionales:
  sin ellas, esas señales quedan en cero.

## Correr en local

```bash
# 1. Servicios de datos (desde el repo de infraestructura)
cd ../infraTesis && cp .env.example .env   # completar POSTGRES_PASSWORD
podman compose up -d postgres redis chromadb ollama ollama-pull-embed

# 2. Dependencias y configuración del backend
cd ../backendTesis
uv venv && uv pip install -r requirements.txt
cp .env.example .env                       # misma contraseña de Postgres y LLM_API_KEY

# 3. API
uv run uvicorn main:app --reload --port 8000
curl http://localhost:8000/health          # {"status":"ok",...}
curl http://localhost:8000/ready           # 200 cuando el BK-tree terminó de cargar
```

Con un volumen de Postgres nuevo, el compose carga el schema y los usuarios semilla. Sobre
una base existente, el schema se aplica de nuevo sin perder datos con `make migrate` desde
`infraTesis`, o con `scripts/init_db.py`, que toma `DATABASE_URL` del entorno y no del `.env`:

```bash
set -a && . ./.env && set +a && uv run python scripts/init_db.py
```

Para levantar todo en contenedores (backend y dashboard incluidos), usar `make up` en
`infraTesis`.

## Endpoints principales

Todos cuelgan de `/api/v1` salvo `/health` y `/ready`. La documentación interactiva queda
en `/docs` cuando `API_DOCS_ENABLED=true`.

| Ruta | Uso |
|---|---|
| `POST /auth/login`, `/auth/mfa/verify`, `/auth/mfa/resend`, `/auth/refresh`, `/auth/logout` | Sesión con JWT; los administradores confirman con un código OTP enviado al correo |
| `POST /auth/register` | Alta de estudiantes con correo institucional |
| `POST /analyze`, `/analyze_email`, `/analyze_batch` | Análisis de una URL, de un correo o de un lote |
| `POST /analyze_eml` | Análisis de un archivo `.eml` con sus encabezados completos |
| `POST /report` | Reporte manual de una URL como phishing |
| `GET /incidents`, `/incidents/{id}`, `/incidents/by_hash/{hash}` | Incidentes con categoría, impacto, remediación y origen |
| `GET /metrics/summary`, `GET /settings` | Métricas y parámetros de fusión vigentes, para el dashboard |
| `GET/POST/PATCH/DELETE /roles`, `GET/PATCH /users`, `GET /permissions` | Roles y permisos administrables |

Cada ruta exige un permiso (`auth/permissions.py`). Sin ese permiso responde 403 y sin sesión, 401.

## Datos que guarda

`deploy/schema.sql` es el schema canónico, con las migraciones 001 a 006 aplicadas en orden
e idempotentes. Por cada incidente se guardan la URL, el dominio, los puntajes, las razones,
la categoría del ataque y su impacto en confidencialidad, integridad y disponibilidad.
Cuando hay encabezados, también se guardan la fecha del mensaje, el país, la ciudad, el ISP
y el ASN del servidor de salida.

La IP de origen, el Message-ID y los encabezados se cifran con AES-256-GCM (`core/crypto.py`).
Si `FIELD_ENC_KEYS` no está configurada, esos tres campos no se guardan. El cuerpo del
correo no se persiste mientras `STORE_EMAIL_CONTENT=false` (Ley 1581 de 2012).

## Pruebas

```bash
./verify.sh                    # pytest completo, exige 90 % de cobertura
uv run pytest -m unit          # por tipo: unit, integration, system, regression,
                               # smoke, sanity, acceptance (pyproject.toml)
uv run ruff check . && uv run bandit -r . -x tests
```

Las pruebas de integración levantan su propio Postgres y ChromaDB efímeros; se omiten si
la máquina no tiene los binarios de Postgres o un motor de contenedores con la imagen de
ChromaDB descargada. La suite adversaria de agentes y RAG está en `tests/security/`.

## Scripts de operación

| Script | Para qué |
|---|---|
| `scripts/init_db.py` | Aplica `deploy/schema.sql` a la base de `DATABASE_URL` (variable de entorno) |
| `scripts/seed_chromadb.py --apply` | Siembra las colecciones del RAG |
| `scripts/verify_rag_knowledge.py` | Mide la recuperación del RAG (hit@3) |
| `scripts/backfill_classification.py [--dry-run]` | Clasifica incidentes anteriores a la migración 006 |
| `scripts/rotate_field_key.py [--apply]` | Valida o rota la llave de cifrado de campos |
| `scripts/retain_email_metadata.py` | Borra metadatos de correo vencidos según la política de retención |
| `scripts/fetch_geoip.py` | Descarga las bases DB-IP Lite de ciudad y ASN |

Los scripts de evaluación (`eval_*.py`, `recalibrate_*.py`) reproducen las métricas de la tesis.

## Despliegue

Producción corre en Coolify con `docker-compose.coolify.yml`, en
`https://back-tesi.mangel.dpdns.org`. El procedimiento (variables, schema, siembra del RAG,
respaldo) está en `deploy/README.md` y la lista de variables en `deploy/env.shared.example`.
Los manifiestos de Kubernetes para el laboratorio están en el repo `infraTesis`.

## Licencias de datos

`data/confusables.txt` proviene de Unicode (TR#39). Las bases de geolocalización son
«IP Geolocation by DB-IP» (CC BY 4.0), y el dashboard muestra esa atribución junto al origen
del incidente.
