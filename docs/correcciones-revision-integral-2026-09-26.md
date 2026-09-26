# Correcciones de la revisión integral — 2026-09-26

Solicitud: corregir el backend a partir de la revisión completa. Tarea T21.
Base revisada: commit `22d07fcf3f7afb6273f45e93eadb1689fc3288af`.
Se conservaron los archivos previos y los reportes históricos. Los cambios están en el árbol de trabajo; no se hizo commit, push ni despliegue.

## Resultado por hallazgo

| Revisión | Corrección | Evidencia |
|---|---|---|
| H01 — CORS | Lista exacta de orígenes; arranque rechaza comodines, rutas y credenciales en orígenes. Operaciones de cookies validan Origin. | `test_auth_session_security.py`: origen ajeno, origen permitido y clientes Bearer. |
| H02 — sesiones | JWT con tipo, sid, jti y claims obligatorios; access y refresh separados. Sesiones Redis, rotación atómica de refresh, revocación al salir, estado/rol/contraseña actuales en PostgreSQL. Fallos de almacenes devuelven 503. | Regresiones de replay, cambio de cuenta y permisos; Redis real: cinco renovaciones concurrentes, una aceptada. |
| H03 — EML incompleto | Fallos de una o más URLs devuelven 503. Un EML sin enlaces pasa por análisis de contenido; si faltan clasificadores, queda SUSPICIOUS con estado parcial/indeterminado. Más de diez enlaces se rechazan explícitamente. | `test_email_failure_safety.py`. |
| H04 — confianza del correo | From se obtiene del buzón real; nombre visible y remitentes ambiguos no autentican el dominio. SPF/DKIM desconocidos son null. Cabeceras cargadas por el usuario nunca habilitan admisión al baseline USB. | Regresiones de remitente suplantado y cabeceras fabricadas. |
| H05 — caché TI | Caché versionada por proveedor: GSB por URL, reputación por host y WHOIS por dominio registrable. | Regresión con rutas y tenants distintos; solo WHOIS comparte respuesta entre subdominios. |
| H06 — réplica Chroma | Autoridad explícita, réplica fuera de servicio, copia de actualizaciones y borrados, reemplazo de metadata antigua. Espacios de embeddings declarados y contrastados con metadata; incompatibilidad detiene la operación. | Chroma real temporal: purga sin resurrección, eliminación de caducidad antigua, rechazo de modelo/dimensión incompatibles. |
| H07 — réplica PostgreSQL | Valores completos y borrados en transacción; cambios de rol, contraseña, is_active e ingested se propagan. Auditoría usa UUID global sin watermark de tiempo. | PostgreSQL real: cambios, borrados, eventos atrasados y repetición sin duplicados nuevos. |
| H08 — calibración | θ no baja del piso neutral más un margen de 0,01; se recalcula el mínimo si cambian los pesos. | Regresión para θ=0,20, valores no finitos y selección acotada. |
| H09 — disponibilidad HF/LLM | `agent_status` separa inferencia válida, fallback, timeout y error; incluye modelo, revisión disponible y latencia. Se persiste en incidentes. Una API remota no atribuye una revisión ONNX que no verificó. | Regresión: dos scores 0,5 con estados distintos; salidas inválidas excluidas de evaluación. |
| H10 — evaluación | Deduplicación de URLs, grupos por dominio/campaña/base sintética, calibración separada del test. Snapshot TI/probe/RAG, hashes de configuración y corpus; aprendizaje, calibración adaptativa y conductor desactivados. Comparación agrupada usa solo test. | Regresiones de grupos disjuntos, snapshot inmóvil, ausencia de consultas TI/probe/RAG en vivo y θ independiente de las etiquetas de test. |
| H11 — probe sin efecto | Evidencia conjunta de formulario de credenciales, marca suplantada y envío externo puede aportar aunque el score base sea menor a 0,30. Login aislado y destinos confiables conservan el filtro. | Regresión con detección nueva por probe y controles contra falsos positivos; contribuciones reconstruyen el score. |
| H12 — aprendizaje | Cuota real por colección, máximo absoluto, caducidad, identidad estable por URL, admisión serializada entre procesos mediante PostgreSQL. BM25 acotado, reconstrucción compartida y protección ante purgas durante la reconstrucción. | `test_knowledge_admission.py`, `test_hybrid_retrieval.py`. |
| H13 — esquema | `deploy/schema.sql` es canónico; el otro path es un enlace. Migración repetible de username a email, campos de correo, auditoría global y telemetría; conserva IDs y cuentas históricas. | Migración real desde esquema anterior, repetición y réplica hacia esquema nuevo. |
| H14 — durabilidad | Guardado esperado antes de responder; si falla, 503 sin acuse de éxito. Autoaprendizaje exige incidente persistido. Tareas opcionales se drenan/cancelan al apagar. Feedback conserva el UUID del administrador. | Escrituras reales UUID/JSONB y prueba de fallo de almacenamiento vía HTTP. |
| H15 — pruebas | Precheck correcto en /ready; pruebas live requieren activación y credenciales explícitas y fallan si se solicitan sin backend listo. Cobertura incluye ahora `models/chromadb_client.py`. | Suite completa más Redis, PostgreSQL y Chroma temporales reales. |
| H16 — admisión y CPU | Login limitado por IP e identidad; bcrypt fuera del event loop, concurrencia acotada. X-Forwarded-For solo se usa detrás de proxies declarados. | Regresiones de límite, origen de IP y autenticación. |
| H17 — secreto Redis | Inicialización deja de registrar la URL de conexión. | Inspección del log y diff; no se publican credenciales. |

## Otros ajustes

- Probe conecta al mismo IP público que valida. Valida todas las respuestas DNS y cada conexión; conserva Host/SNI y desactiva proxies del entorno. DNS no bloquea el event loop.
- Capacidad por proceso: 8 análisis simultáneos, 10 s máximos en cola y 45 s de ejecución; respuestas 503/504, liberación del cupo incluso al cancelar.
- `/health` indica vida del proceso; `/ready` verifica PostgreSQL, Redis e IDN, y declara RAG degradado. Render y Compose usan `/ready`.
- `STORE_EMAIL_CONTENT=false` evita almacenar HTML/imágenes/adjuntos por defecto. Los metadatos del correo todavía contienen datos personales.
- `python -m scripts.retain_email_metadata` cuenta campos antiguos que se limpiarían. `--apply` realiza la limpieza idempotente; 30 días por defecto. No es anonimización integral: URLs, explicaciones, scores y auditoría permanecen. El operador debe programar este mantenimiento.
- NumPy del entorno virtual se alineó con `requirements.txt` (2.4.4); el lock evita volver a una versión incompatible con numba. `uv pip check --python .venv/bin/python` pasó.

## Verificación

Gate inicial: **972 passed, 28 skipped**, cobertura 92,62 %.
Suite integrada: **1087 passed, 28 skipped**, cobertura **92,33 %**, incluyendo Chroma antes excluido del denominador.

Comando:

```sh
cd backendTesis
source .venv/bin/activate
pytest -q
```

Evidencia final: `docs/revision-2026-09-26/pytest.txt`.
Las pruebas de stores crean y limpian sus propios procesos/contenedores y datos. No usan bases ni colecciones de producción. En macOS sus procesos se lanzan con posix_spawn para evitar el fallo de fork observado tras inicializar Network.framework.

Las pruebas unitarias usan dobles para fallos controlados y proveedores remotos. La suite live no se ejecutó contra un despliegue completo. Los tests de stores se omiten en entornos sin los binarios/imágenes locales requeridos; **sí se ejecutaron aquí**. No se descargan imágenes durante pytest.

## Pasos de despliegue

1. Conservar backup y aplicar `python -m scripts.init_db` con `DATABASE_URL` explícita en cada base, antes de desplegar el código que escribe `agent_status`. La prueba local no sustituye la verificación del esquema real del destino.
2. Configurar `CORS_ORIGINS` con los orígenes reales del dashboard, onboarding y extensión; establecer `TRUSTED_PROXY_CIDRS` solo con los proxies del ingreso controlado.
3. Desplegar y comprobar `/ready`, login, análisis, consulta del incidente y feedback. Los JWT anteriores requieren **nuevo inicio de sesión**. Un failover con Redis independiente también requiere autenticación nueva.
4. Retirar cron de sincronización bilateral. Para copiar réplicas, seguir [sincronización y aprendizaje](synchronization-and-learning.md): autoridad única, writers pausados, espacios de embeddings verificados y réplica fuera de servicio hasta terminar ambas copias. No etiquetar una colección antigua con un modelo supuesto.
5. Revisar minimización/retención y programar el mantenimiento explícito. Una carga EML no verifica SPF/DKIM; la admisión de correo institucional requiere procedencia verificable y resolver el protocolo T9.
6. Repetir la evaluación del detector con corpus único, split independiente y snapshot congelado. No reutilizar las cifras históricas como validación del detector corregido.

## Límites

El reporte de 2026-09-15 conserva 600 filas, 480 URLs únicas y 420 scores HF iguales a 0,5 sin telemetría para determinar su procedencia. La selección del umbral y su evaluación usaban las mismas filas. Las métricas y significancia publicadas quedan como **resultados históricos no validados bajo el protocolo corregido**.

No se hizo una nueva evaluación externa, prueba de carga, despliegue ni ingesta de correo institucional. Los límites de concurrencia no acreditan la meta p95 < 8 s. Un modelo LLM remoto puede cambiar y producir variación aun con evidencias de entrada congeladas. Chroma y PostgreSQL no comparten una transacción: la réplica debe permanecer cercada ante un fallo parcial.

Las regresiones verifican los defectos corregidos; no constituyen una garantía de ausencia total de fallos.
