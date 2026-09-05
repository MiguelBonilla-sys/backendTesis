# Conocimiento público para los agentes

Carga verificada el 5 de septiembre de 2026: **122 documentos de 16 fuentes originales**
(116 fragmentos técnicos de T13 y seis fichas de casos reales de T14),
en `security_knowledge`, sobre ChromaDB local (`localhost:8001`) con Ollama
`embeddinggemma`. La persistencia está en `TesisDEV/.local-rag/chroma`.
La instancia configurada estaba apagada; se inició una base local. Esto no acredita
una carga en el despliegue Kubernetes ni una migración de una base remota.

Se usó Firecrawl CLI autenticada: su MCP no estaba expuesto en esta sesión. El
importador acepta tanto JSON de `search` como el sobre `data.markdown` de scrape/MCP.
Los datos recuperados se tratan como contenido no confiable en los agentes.

## Qué conoce el RAG

| Colección | Uso | ¿Se cargó en esta revisión? |
|---|---|---|
| `security_knowledge` | Referencias y reportes públicos con URL, fecha y hash, sin veredicto | Sí: 122 documentos |
| `email_embeddings` | Patrones observados, con veredicto y procedencia | No |
| `idn_patterns` | Patrones IDN observados/sintéticos | No |
| `ti_signals` | Evidencia TI de incidentes | No |
| `usb_baseline` | Contexto legítimo institucional | No; correo real depende de T9 |

El conocimiento público incluye confusables y scripts mixtos
([Unicode UTS #39](https://www.unicode.org/reports/tr39/)); phishing, adjuntos y
enlaces ([MITRE T1566](https://attack.mitre.org/techniques/T1566/),
[T1566.001](https://attack.mitre.org/techniques/T1566/001/),
[T1566.002](https://attack.mitre.org/techniques/T1566/002/)); reconocimiento y
formación ([CISA](https://www.cisa.gov/secure-our-world/recognize-and-report-phishing),
[formación CISA](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/teach-employees-avoid-phishing));
autenticación de correo ([Microsoft en inglés](https://learn.microsoft.com/en-us/defender-office-365/email-authentication-about),
[en español](https://learn.microsoft.com/es-es/defender-office-365/email-authentication-about));
robo de cookies de sesión
([Microsoft Defender](https://learn.microsoft.com/en-us/defender-xdr/session-cookie-theft-alert));
y reconocimiento de phishing
([INCIBE](https://www.incibe.es/incibe/protegete-conoce-a-fondo-phishing)).
La página de reconocimiento de CISA figura como archivada en el snapshot; se
conserva como referencia histórica, no como aviso vigente de campaña.

T14 agrega seis reportes revisados: KeePass/IDN, AiTM/BEC, Storm-2372, códigos de
dispositivo dinámicos, QR corporativo y DIAN. Son fichas en español, no correos
etiquetados. El manifiesto `data/real_case_sources.json` conserva publicación,
período observado, evidencia y síntesis; los originales y hashes están en
`../.firecrawl/real-cases/`. Detalle: `../../docs/casos-reales-firecrawl-2026-09-05.md`.

```bash
python -m scripts.ingest_firecrawl_knowledge --sources data/real_case_sources.json --output ../.firecrawl/real-cases --apply
python -m scripts.verify_rag_knowledge --sources data/real_case_sources.json --cases data/real_case_queries.json --verify-idempotency --output ../.firecrawl/real-cases/retrieval-check.json
```

## Artefactos

- `data/knowledge_sources.json`: selección de URLs, idioma, tema, archivo de
  snapshot y filtros de secciones. Es la entrada reproducible de la ingesta.
- `../.firecrawl/*.json`: respuestas originales de Firecrawl, fuera de Git.
- `../.firecrawl/knowledge/<host>/<ruta>/index.md`: secciones utilizadas.
- `../.firecrawl/knowledge/chunks.jsonl`: documentos listos para ingesta.
- `../.firecrawl/knowledge/manifest.json`: URL, editor, fecha de recuperación,
  hashes SHA-256 del snapshot y del contenido seleccionado, cantidad por fuente y
  resultado de aplicación. `retrieved_at` es fecha de consulta, no de publicación.
- `../.firecrawl/knowledge/retrieval-check.json`: consultas y fuentes recuperadas.

Cada fragmento tiene ID estable derivado de URL + contenido. La recarga hace upsert;
solo elimina fragmentos obsoletos de la misma URL creados por este importador,
después de guardar correctamente todos los nuevos. Los snapshots permiten regenerar
versiones anteriores. No borra colecciones ni modifica incidentes.

## Reproducir localmente

Desde `backendTesis`, con el entorno existente:

```bash
source .venv/bin/activate
pytest -q
```

Si los servicios no están activos, ejecutar cada uno en su terminal. Usar la misma
ruta de persistencia para conservar la carga:

```bash
ollama serve
```

```bash
source .venv/bin/activate
chroma run --host 127.0.0.1 --port 8001 --path ../.local-rag/chroma
```

La carga verificada usó `EMBED_PROVIDER=ollama`, `EMBED_MODEL=embeddinggemma` y
`EMBED_BASE_URL=http://localhost:11434`. Ese modelo ya estaba instalado localmente.
Una instalación nueva debe preparar el mismo modelo antes de ingerir.

```bash
# Preparación sin escribir en ChromaDB; exige todos los snapshots seleccionados.
python -m scripts.ingest_firecrawl_knowledge

# Aplicación al destino configurado en core/config.py / .env.
python -m scripts.ingest_firecrawl_knowledge --apply

# Consulta ad hoc: devuelve fragmentos y enlaces; no llama al LLM generativo.
python -m scripts.verify_rag_knowledge --query '¿Cómo funcionan SPF, DKIM y DMARC?'

# Prueba de recuperación e idempotencia; vuelve a aplicar los snapshots revisados.
python -m scripts.verify_rag_knowledge --verify-idempotency
```

El comando con `--query` comparte la ruta de salida por defecto del informe; usar
`--output ../.firecrawl/knowledge/consulta.json` si se quiere conservar la comprobación
anterior. Para otro ChromaDB, establecer sus variables en el proceso; no cambiar el
modelo de embeddings de colecciones existentes para resolver errores de conexión.

## Actualizar fuentes con Firecrawl

Primero comprobar autenticación con `firecrawl --status`. Descargar una URL pública
revisada a un archivo nuevo. Ejemplo desde la raíz del workspace:

```bash
firecrawl scrape 'https://www.unicode.org/reports/tr39/' --only-main-content --json -o .firecrawl/unicode-current.json
```

Actualizar el campo `snapshot` de esa fuente en `data/knowledge_sources.json` y la
fecha real de consulta. Revisar contenido, título y filtros de secciones antes de
aplicar. Para las fuentes de una búsqueda que compartían un archivo, usar un archivo
individual por URL al refrescar: no sobrescribir un JSON compartido con una sola página.
La selección rechaza URLs fuera de los hosts aprobados, HTTP, credenciales, fallos de
scrape, páginas vacías, secciones ausentes y rutas que escapen del directorio de snapshots.

## Recuperación y límites

Los canales denso y BM25 se ejecutan de forma independiente, con hasta 5 segundos
por operación de recuperación. BM25Plus evita perder coincidencias en colecciones
pequeñas; los tokens preservan dominios completos y equivalencias Punycode/Unicode.
RRF combina rangos. La ponderación por procedencia usa relevancia no negativa;
cuarentena, rechazo y caducidad se excluyen, incluso si son los únicos candidatos.

El agente pide candidatos por colección, deduplica texto, etiqueta procedencia y
distribuye hasta 15 fragmentos en 6.000 caracteres. El baseline no queda descartado
por un prefijo largo de ejemplos de ataque. El reranker opcional y el conductor
también delimitan datos no confiables y aplican redacción por patrones.

Las ocho consultas de humo recuperaron fuentes esperadas en top-3 tanto en denso
como híbrido (8/8 en ambos). Por tanto, esta prueba no demuestra superioridad del
híbrido; sí se probaron regresiones donde BM25 recupera al fallar los embeddings.
El replay de T13 mantuvo los mismos 116 IDs y se comprobó que LLMAgent incluye las
referencias en el prompt. Tras T14, el replay conserva 122 IDs; las seis consultas
nuevas dan 6/6 top-3 en ambos modos y las ocho anteriores siguen 8/8. Suite final de
backend: 904 passed, 25 skipped, cobertura 92,13 %.
No son ejemplos independientes para medir la precisión del detector ni justifican
F1, ROC, p95 o significancia. No se llamó al LLM generativo en esta comprobación.

Para evaluar el detector: congelar corpus y colecciones, desactivar autoaprendizaje
y calibración, registrar pesos/modelos/flags y usar snapshots TI. La redacción no
garantiza anonimización completa y siguen pendientes T1 (retención de correo) y T9
(autorización institucional). La base de esta sesión no contiene correo personal.
