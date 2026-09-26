# Revisión integral del backend — 25 de septiembre de 2026

## Dictamen

El backend tiene una estructura modular razonable, una suite amplia y defensas concretas. Es una base funcional que merece conservarse. La revisión encuentra, sin embargo, problemas de seguridad de sesión, clasificación, aprendizaje y sincronización que requieren corrección antes de considerar cerrada su validación.

El mayor problema transversal es que varios estados distintos se presentan como equivalentes: token de acceso y de renovación; señal ausente y señal negativa; análisis fallido y correo legítimo; cabecera declarada y autenticación verificada; documento ausente y documento eliminado. Las pruebas actuales cubren muchas funciones individualmente, pero no todas estas interacciones.

La prioridad es corregir esos contratos y medir de nuevo. Esta revisión no aporta una razón para migrar a microservicios, sumar agentes o reescribir el backend.

## Alcance y evidencia

- Fuente principal: archivos actuales de `backendTesis`, commit `22d07fcf3f7afb6273f45e93eadb1689fc3288af`.
- Revisión de API, autenticación, esquemas, parsing, agentes, fusión, RAG, persistencia, sincronización, configuración, Docker y scripts de evaluación.
- Gate inicial: **972 passed, 28 skipped, 92,62 % de cobertura**, Python **3.14.5**. El contenedor declara Python **3.12**.
- Los defectos indicados como reproducidos se comprobaron en el proceso local con ASGI, funciones reales y dobles de servicios. Las llamadas de proveedores, escrituras de bases y aprendizaje se interceptaron.
- Se recalcularon estadísticas de los JSON existentes. No se ejecutó una nueva evaluación del detector contra páginas o proveedores externos.
- No se verificaron producción, políticas reales de los proxies, carga concurrente sostenida, restauración de backups ni nuevas vulnerabilidades publicadas de dependencias. Las conclusiones sobre despliegue se limitan a sus archivos versionados.
- Los archivos preexistentes `.coverage 2`, `.coverage 3` y `.coverage 4` se conservaron. Esta sesión agrega el informe y sus evidencias, sin modificar la implementación.

Artefactos: [resultados de reproducción](revision-2026-09-25/evidence.json) y [programa de reproducción local](revision-2026-09-25/reproduce.py). Desde la raíz de `backendTesis`:

```bash
PYTHONPATH=. .venv/bin/python docs/revision-2026-09-25/reproduce.py /tmp/backend-review-evidence.json
```

El programa no imprime tokens ni credenciales. Comprueba el comportamiento de la configuración cargada; no reproduce las políticas de cookies de un navegador real. El JSON conservado corresponde a la revisión original.

**Prioridad:** P1 = corregir antes de ampliar exposición o apoyar decisiones en el resultado afectado; P2 = corregir en la siguiente iteración de robustez. La prioridad describe el impacto técnico, no un CVSS ni una prueba de explotación de producción.

## Hallazgos prioritarios

### H01 · P1 · CORS permite orígenes de terceros con cookies de sesión

**Evidencia:** `core/config.py:58`, `main.py:75`, `routers/auth_router.py:157`. El patrón admite cualquier proyecto bajo `vercel.app`, `onrender.com` y los dominios ngrok contemplados. `allow_credentials=True` y las cookies de producción usan, por defecto, `SameSite=None`.

**Reproducción:** una petición ASGI a `/api/v1/auth/refresh` con una cookie válida y `Origin: https://review-untrusted.vercel.app` devuelve 200, tokens en el cuerpo, `Access-Control-Allow-Origin` para ese origen y `Access-Control-Allow-Credentials: true`.

**Impacto:** una página controlada por un tercero en un origen admitido puede leer respuestas autenticadas cuando el navegador envía las cookies. La comprobación confirma la autorización del servidor; la explotación en navegador depende de sus restricciones de cookies. Los manifiestos de Coolify y Render no sobrescriben ese patrón amplio.

**Corrección y aceptación:** restringir a orígenes exactos del producto y extensiones autorizadas; validar origen/protección CSRF en operaciones con cookies. Un origen arbitrario de Vercel no debe obtener una respuesta autenticada legible, mientras el dashboard legítimo debe seguir funcionando.

### H02 · P1 · Renovación y autorización no respetan el ciclo de vida de la cuenta

**Evidencia:** `auth/dependencies.py:40`, `auth/jwt.py:14`, `routers/auth_router.py:183`. `require_auth` acepta cualquier JWT que decodifique correctamente, incluido `type=refresh`. La renovación copia `sub` y `role` del token sin consultar si la cuenta sigue activa ni si conserva ese rol. Tampoco invalida el refresh anterior.

**Reproducción:** un refresh token como Bearer obtiene 200 en `/api/v1/auth/me`; después de renovar, el token anterior vuelve a renovar con 200. La ausencia de consulta a la cuenta se confirma en el código de la ruta.

**Impacto:** se elude la duración prevista del access token. Una cuenta desactivada o degradada de administrador puede conservar sus privilegios mediante renovaciones sucesivas mientras mantenga un refresh válido. Cerrar sesión solo elimina cookies del cliente.

**Corrección y aceptación:** exigir tipo de access token y claims obligatorios; consultar estado/rol vigente al renovar; implementar revocación y rotación mediante identificador o versión de sesión. Probar refresh usado como access, reutilización, logout, cuenta desactivada y cambio de rol.

### H03 · P1 · Un EML cuyo análisis falla puede quedar clasificado como legítimo

**Evidencia:** `routers/eml_router.py:143` y `routers/eml_router.py:164`. Se eliminan de la agregación los resultados que son excepciones. Si no queda ninguno, se ejecuta la misma rama que para un correo sin URLs.

**Reproducción:** un EML con una URL y fallo simulado del pipeline devuelve HTTP 200, `email_verdict=LEGITIMATE`, `email_s_risk=0.0` y cero análisis. Además, para correos sin URLs el score se limita a 0,39 y se compara contra 0,40: la rama SUSPICIOUS es inalcanzable. Esa ruta no clasifica el contenido con el LLM/HF ni integra plenamente adjuntos y suplantación.

**Impacto:** un error de análisis se comunica como ausencia de amenaza. Un correo de ingeniería social sin enlaces también puede recibir una conclusión excesivamente favorable.

**Corrección y aceptación:** representar análisis incompleto/indeterminado; distinguir cero URLs de fallos de las URLs existentes; definir un análisis de contenido independiente. Probar fallos totales, parciales, correos sin enlaces y adjuntos sospechosos.

### H04 · P1 · Datos del EML pueden adquirir confianza de baseline institucional

**Evidencia:** `utils/email_parser.py:188`, `utils/email_parser.py:194`, `data_pipeline/knowledge_updater.py:119`, `routers/eml_router.py:178`. El parser toma el primer dominio encontrado por regex en `From`; los resultados SPF/DKIM se leen de cabeceras del archivo subido, sin establecer una fuente confiable ni alineación con el remitente institucional.

**Reproducción:** `From: "registro@usbbog.edu.co" <attacker@evil.invalid>` y cabeceras que declaran SPF/DKIM pass para `evil.invalid` producen `sender_domain=usbbog.edu.co` y activan `ingest_legit_baseline`. El EML sintético no contiene URLs; la escritura real se sustituyó por un mock.

**Impacto:** un usuario autenticado puede introducir evidencia con peso de baseline institucional mediante contenido que controla. SPF/DKIM declarados en un archivo no demuestran autenticación del dominio USB.

**Corrección y aceptación:** parsear direcciones con un parser de correo, representar autenticación como evidencia declarada salvo fuente verificada y exigir procedencia/alineación antes de aprender. Un nombre visible con una dirección USB o cabeceras aportadas libremente no debe conferir confianza institucional.

### H05 · P1 · La caché TI reutiliza señales de una URL para otras diferentes

**Evidencia:** `data_pipeline/threat_intel.py:62`, `data_pipeline/threat_intel.py:89`, `data_pipeline/threat_intel.py:117`. Se cachea el `TIResult` completo por dominio registrable. GSB consulta la URL completa; VT/URLScan pueden depender del hostname completo.

**Reproducción:** después de consultar `/clean`, `/phish` en el mismo dominio recibe la señal GSB previa sin consultar al proveedor. También `safe.vercel.app` y `evil.vercel.app` comparten la clave `vercel.app`. En ambos casos hubo una sola consulta simulada; la segunda señal, preparada como positiva, nunca se consultó.

**Impacto:** falsos negativos o positivos según qué recurso calentó la caché, durante el TTL configurado.

**Corrección y aceptación:** separar cachés por semántica: WHOIS por dominio registrable, reputación de host por host y GSB por URL normalizada. Probar rutas distintas, subdominios y tenants de hosting.

### H06 · P1 · La sincronización RAG puede restaurar conocimiento purgado

**Evidencia:** `routers/incidents_router.py:467`, `scripts/sync_chroma_standby.py:175`, `scripts/sync_chroma_standby.py:244`. El feedback legítimo elimina documentos del incidente, pero la sincronización bilateral copia IDs ausentes sin registrar eliminaciones. También omite cambios de contenido/metadatos si el ID ya existe en destino.

**Reproducción:** un documento eliminado en local pero presente en standby produce cero copias en el pase de ida y una copia de vuelta. El documento purgado reaparece.

**Impacto:** al ejecutar el sync bilateral, un falso positivo descartado vuelve al conocimiento. Las confirmaciones sobre documentos existentes también pueden quedar desalineadas entre instancias.

**Corrección y aceptación:** definir autoridad/versiones y propagar marcas de eliminación, o usar una réplica unidireccional coherente con el modelo operativo. Tras purgar y sincronizar en ambos sentidos, el documento debe seguir ausente; las actualizaciones deben converger.

### H07 · P1 · La sincronización PostgreSQL ignora cambios de usuarios y feedback

**Evidencia:** `scripts/sync_pg_bilateral.py:57`. Solo copia `src_ids - dst_ids` y usa `ON CONFLICT DO NOTHING`. Si una fila existe en ambos lados, no compara sus campos.

**Reproducción:** dos instancias con el mismo ID de usuario producen cero escrituras aunque sus datos puedan diferir.

**Impacto:** al usar el standby pueden reaparecer contraseñas, roles o estados de cuenta anteriores; `feedback.ingested` tampoco se propaga. Adicionalmente, el watermark de auditoría usa el máximo timestamp global del destino (`:81`), por lo que un evento propio reciente puede hacer que se omitan eventos anteriores todavía no copiados del origen.

**Corrección y aceptación:** definir propietario y resolución de conflictos por entidad; replicar actualizaciones/eliminaciones con versiones o un mecanismo de replicación apropiado. Validar desactivación, cambio de contraseña/rol, feedback procesado y eventos concurrentes en ambas instancias.

### H08 · P1 · La recalibración reintroduce el umbral inseguro que se quiso evitar

**Evidencia:** `core/constants.py:36`, `core/calibration.py:26`, `core/calibration.py:42`, `core/calibration.py:130`, `main.py:47`. THETA es 0,30, pero el margen ±0,10 permite 0,20. El estado neutral con IDN/TI=0 y LLM/HF=0,5 produce riesgo 0,25.

**Reproducción:** 15 muestras phishing con score 0,22 y 15 legítimas con 0,10 hacen que `choose_theta` seleccione 0,20. Al cargarlo, la misma entrada neutral cambia de LEGITIMATE a PHISHING sin aumentar su riesgo.

**Impacto:** un ajuste permitido puede transformar degradaciones de servicios en alertas. El flag `ONLINE_CALIBRATION_ENABLED` controla pesos; la carga de theta desde DB al iniciar ocurre por separado.

**Corrección y aceptación:** expresar el piso de seguridad como invariante de la configuración efectiva, considerar los pesos efectivos y representar indisponibilidad explícitamente. Probar el umbral seleccionado/cargado, no solo la constante THETA. Su ocurrencia requiere aplicar una calibración compatible con ese escenario; no se afirma que producción tenga hoy theta=0,20.

## Evaluación, robustez y operación

### H09 · P1 para la conclusión experimental · El baseline mezcla predicción e indisponibilidad

**Evidencia:** `agents/hf_agent.py:130`, `agents/hf_agent.py:190`, `scripts/eval_baseline_vs_pipeline.py:233` y el JSON `reports/baseline_vs_pipeline_20260915_002802.json`.

En **420 de 600 filas (70 %)**, `s_hf` vale exactamente 0,5. Ese valor también representa timeout/error/fallback. El evaluador convierte `s_hf >= 0.5` en PHISHING sin registrar si hubo inferencia válida. **204 de los 216 falsos positivos del baseline** están en esas filas.

No puede afirmarse que las 420 filas sean fallos: el reporte carece del estado que permitiría distinguirlo. Precisamente por ello, «0 errores» HTTP no demuestra 600 inferencias válidas. La afirmación de superioridad frente al clasificador debe considerarse provisional hasta resolver esa ambigüedad.

**Corrección y aceptación:** devolver y persistir estado por agente (`ok`, timeout, modelo ausente, error), modelo/revisión y duración; prevalidar el baseline y separar evaluación del modelo de evaluación del sistema degradado. No eliminar retrospectivamente todos los scores 0,5 suponiendo que son fallos.

### H10 · P2 · El experimento repite URLs y usa los mismos casos para calibrar y reportar

**Evidencia:** `scripts/eval_datasets.py:250`, `scripts/run_t5_t6.py:149`, `docs/EVAL-T4-T7.md` y resultados crudos.

Las 600 filas contienen **480 URLs distintas**. El bloque HF de 300 filas tiene 180 URLs únicas; las repeticiones corresponden a legítimos. Hay 28 URLs repetidas, algunas hasta 10 veces. El loader toma las primeras filas por clase sin deduplicar. Theta se selecciona mirando el mismo conjunto sobre el que se reporta el resultado recalculado.

**Impacto:** las observaciones repetidas sobreponderan ciertos casos y debilitan la interpretación de 600 observaciones independientes. Las métricas tras elegir el umbral describen el conjunto usado para calibrarlo; no estiman por sí solas generalización a casos nuevos.

**Corrección y aceptación:** deduplicar y agrupar por dominio/campaña cuando corresponda, separar calibración y prueba, fijar revisión/hashes de corpus y conocimiento. Guardar configuración, estados de proveedores y mecanismos de aprendizaje desactivados. Los scripts actuales no verifican ese congelamiento; el reporte histórico tampoco permite reconstruirlo por completo.

### H11 · P2 · El probe ya no puede convertir un resultado legítimo en phishing con los valores base

**Evidencia:** `core/constants.py:36`, `core/constants.py:122`, `agents/fusion_agent.py:199`. El probe solo suma si base + email ≥ 0,30; ese valor ya alcanza THETA=0,30.

**Reproducción:** base neutral 0,25 y probe 0,60 con señales de formulario/marca/acción externa terminan en probe efectivo 0 y veredicto LEGITIMATE. Con theta base, el probe puede aumentar el score de un caso que ya era phishing, pero no aportar detecciones binarias adicionales.

**Corrección y aceptación:** revisar conjuntamente gate, confianza del destino y umbrales con una evaluación de ablación. No basta bajar el gate sin estudiar falsos positivos de logins legítimos. El resultado depende de los valores base; theta adaptado y conductor pueden cambiar el comportamiento.

### H12 · P2 · La cuota de autoaprendizaje está declarada pero no se aplica

**Evidencia:** `core/config.py:102`, `services/analysis.py:152`, `data_pipeline/knowledge_updater.py:218`, `models/chromadb_client.py:287`, `data_pipeline/hybrid_retrieval.py:95`.

`AUTO_INGEST_QUOTA` no tiene lectores en producción. Cada nuevo análisis elegible utiliza el ID del incidente y escribe tres documentos, aunque la URL ya se haya analizado. El peso reducido por procedencia no limita la cantidad. Cada upsert invalida el índice BM25; reconstruirlo obtiene y tokeniza los documentos de la colección.

**Impacto:** crecimiento y aumento del coste de recuperación con el uso; la cuota comentada no constituye una defensa contra saturación del conocimiento. No se midió un límite de RAM ni un ataque de carga real.

**Corrección y aceptación:** aplicar la cuota, deduplicación por contenido/entidad, retención y límites de trabajo; coordinar reconstrucciones de BM25 y medir su coste. Con cuota cero no debe entrar autoaprendizaje; repetir la misma evidencia no debe aumentar indefinidamente su influencia.

### H13 · P2 · El inicializador de DB crea un esquema incompatible con el código actual

**Evidencia:** `scripts/init_db.py:14`, `scripts/schema.sql:15`, `deploy/schema.sql:26`, `routers/auth_router.py:239`, `services/persistence.py:81`.

`init_db.py` carga `scripts/schema.sql`, que define `users.username` y carece de varios campos actuales de incidents. Autenticación consulta `users.email`; persistencia utiliza las columnas de correo. `deploy/schema.sql` sí contiene esa forma actual.

**Impacto:** inicializar desde el script disponible puede romper login/registro y provocar fallos de persistencia. No implica que una instalación ya creada con el esquema de despliegue falle hoy.

**Corrección y aceptación:** una fuente de esquema con migraciones versionadas, usada por ambos caminos. Probar arranque desde DB vacía y actualización de una DB anterior. `CREATE TABLE IF NOT EXISTS` no actualiza columnas de tablas existentes.

### H14 · P2 · Las respuestas exitosas no garantizan persistencia

**Evidencia:** `routers/analyze_router.py:141`, `routers/eml_router.py:246`, `services/persistence.py:63`, `services/persistence.py:270`.

Las escrituras se lanzan con `asyncio.create_task`; los helpers capturan errores y solo los registran. Incluso un reporte manual obtiene 201 antes de confirmar su INSERT. No hay cola durable ni espera de esas tareas al cerrar el proceso.

**Impacto:** respuestas válidas pueden no aparecer en historial; un reinicio o fallo de DB puede perder reportes. En `/analyze`, autoingesta y persistencia se programan separadamente, pudiendo crear conocimiento sin un incidente recuperable para corregirlo por feedback.

**Corrección y aceptación:** confirmar la escritura esencial antes de 201 o usar una cola/outbox durable con estado consultable e idempotencia. Probar indisponibilidad de DB y terminación durante una escritura, incluyendo la relación incidente–documentos RAG.

### H15 · P2 · La suite live puede omitirse aunque el servidor esté sano

**Evidencia:** `tests/integration/test_agents_live.py:27`, `routers/health_router.py:21`, `pyproject.toml:24`, `tests/conftest.py`.

El detector de disponibilidad consulta `/api/v1/health`, pero la aplicación publica `/health`. La reproducción ASGI devuelve respectivamente 404 y 200. Esa condición omite todo el módulo live en una instancia que exponga las rutas del código actual. Su helper de autenticación también genera un token local cuando falla el login, ocultando fallos del flujo real.

La cobertura global excluye explícitamente `models/chromadb_client.py` y los scripts. Existen pruebas del cliente Chroma, pero su ejecución no contribuye a ese porcentaje. EML tiene 44 % de cobertura y los routers de análisis/incidentes 68 %/77 % aproximadamente. Los stubs globales sustituyen inicialización de IDN, Chroma y gateway en buena parte de la suite.

**Corrección y aceptación:** corregir health del precheck y exigir login real en la suite de integración. Añadir un job de integración aislado con DB/Redis/Chroma, y regresiones de los fallos aquí descritos. Mantener visible qué verifica cada capa de tests.

### H16 · P2 · Falta control de intentos en login y la IP del límite puede ser declarada por el cliente

**Evidencia:** `routers/auth_router.py:78`, `routers/auth_router.py:245`, `core/rate_limiter.py:69`, `Dockerfile:38`.

Login no llama al limitador; la verificación bcrypt es síncrona dentro de una ruta async. `get_client_ip` confía directamente en el primer elemento de `X-Forwarded-For`. El contenedor configura confianza en todos los proxies para Uvicorn.

**Impacto:** intentos repetidos sobre cuentas conocidas pueden consumir CPU y bloquear el event loop; si un cliente puede introducir ese header hasta la app, puede variar la clave del limitador. La explotabilidad del segundo caso depende de que el proxy real reescriba o preserve headers externos, algo no verificado aquí.

**Corrección y aceptación:** límite por identidad e IP confiable, hash en worker acotado, proxy trust explícito y normalización del header en el borde. Probar login repetido y petición con `X-Forwarded-For` externo sin generar carga contra producción.

### H17 · P2 · El log de arranque puede incluir la credencial de Redis

**Evidencia:** `models/redis_client.py:27` registra `settings.REDIS_URL` completa.

**Impacto:** cuando la URL contiene usuario/password, esos secretos llegan al sistema de logs. No fue necesario leer ni mostrar credenciales reales para identificarlo.

**Corrección y aceptación:** registrar host/puerto/base de forma explícita, sin userinfo ni parámetros sensibles. Un test con una URL sintética que contenga contraseña debe demostrar que esta no aparece en los logs.

## Otras observaciones concretas

- **Entorno no idéntico al declarado:** `uv pip check --python .venv/bin/python` termina con exit 1: numba requiere `numpy<2.5`, pero el entorno tiene 2.5.3; `requirements.txt` fija 2.4.4. Pasar pytest no comprueba todas las dependencias opcionales. No se instalaron ni modificaron paquetes. Docker ya filtra `pywin32`, por lo que su presencia en requirements no demuestra un build Linux roto.
- **SPF/DKIM desconocido se presenta como fallo:** `services/analysis.py:214` genera razones de autenticación fallida desde booleanos False por defecto. `/analyze_email` no recibe cabeceras y construye `EmailSignals` sin esa evidencia. Conviene representar `unknown`, `pass` y `fail` por separado.
- **Atribución del feedback perdida:** `routers/incidents_router.py:462` hace `getattr(current_user, "id", None)` sobre un diccionario JWT. El campo `confirmed_by` termina en NULL; además el token usa el email como `sub` y no aporta el UUID requerido por la FK. Resolver al usuario en DB permite conservar quién confirmó el veredicto.
- **Readiness:** `/health` solo devuelve una respuesta estática. Sirve para comprobar que responde el proceso, pero no detecta una DB caída ni un detector degradado. Separar liveness/readiness y exponer disponibilidad por señal sin datos sensibles.
- **Minimización:** `services/persistence.py:81` conserva asunto, remitentes, destinatarios, HTML y metadatos del correo. El hash del correo no anonimiza esos otros campos. Hace falta definir retención y depuración; esta es una observación técnica, no una conclusión jurídica sobre consentimiento o cumplimiento.
- **SSRF y bloqueo del loop:** `agents/web_probe_agent.py:121` resuelve DNS síncronamente y la petición HTTP vuelve a resolver el host por su transporte. La validación de A/AAAA y redirects es valiosa, pero no fija la conexión a la dirección validada. Quedan por verificar el control de egress y el caso de cambio DNS entre comprobación y conexión; no se ejecutó un ataque DNS real.
- **Capacidad:** `/analyze_email` puede lanzar hasta 35 pipelines concurrentes por request (`routers/analyze_router.py:199`); no se observa un presupuesto global en ese flujo. Antes de crecer en usuarios, medir concurrencia, colas, coste por correo y p95/p99, incluyendo fallos de proveedores y reconstrucción BM25. No se atribuye un rendimiento medido a partir de los timeouts del código.

## Qué está bien construido

- Separación entre routers, servicios, esquemas, agentes y acceso a datos; `run_pipeline_core` concentra la lógica compartida y evita duplicar la fórmula principal.
- Fusión verificable con límites de score, contribuciones explícitas y pruebas de saturación. Las contribuciones se interpretan correctamente como atribución analítica; el nombre `shap` no convierte el método en SHAP estadístico.
- Uso de consultas parametrizadas, passwords con bcrypt, firmas JWT verificadas y roles administrativos en incidentes/feedback. Los problemas de sesión anteriores están en la autorización y el ciclo de vida, no en ausencia de firma.
- Límites del probe, comprobación de redirects y direcciones no públicas; los casos residuales están delimitados arriba.
- RAG con procedencia, exclusión de cuarentena/caducidad, recuperación híbrida y presupuestos de contexto. Mantener el espacio de embeddings configurado evita cambiarlo silenciosamente ante fallos.
- Gateway centralizado, redacción antes de servicios externos y revisión fijada del modelo ONNX en configuración y Docker. El runtime del contenedor usa usuario no root.
- Hay evidencia cruda de evaluación y se reconoce el recall por debajo de la meta. Eso permite detectar y corregir los problemas metodológicos sin inventar resultados.

## Qué permiten afirmar las métricas existentes

Recalculando únicamente el JSON guardado con corte 0,30:

| Resultado del pipeline | Valor |
|---|---:|
| Verdaderos positivos | 200 |
| Falsos negativos | 100 |
| Falsos positivos | 0 |
| Verdaderos negativos | 300 |
| Precisión | 1,0000 |
| Recall | 0,6667 |
| F1 | 0,8000 |

Son métricas de esas 600 filas históricas. El detector deja sin detectar 100 de los 300 casos etiquetados phishing en esa muestra al usar ese corte. No prueban precisión perfecta en producción ni resuelven H09/H10. No se recalibraron pesos, umbrales ni conocimiento durante esta revisión.

## Secuencia recomendada de corrección

1. Sesiones/orígenes y frontera de confianza del EML: H01–H04, controles de login y logs.
2. Correctitud de señales y aprendizaje: H05, H08, H11, H12; conservar el comportamiento de degradación como caso explícito.
3. Persistencia y failover: H06, H07, H13, H14. Comprobar también correcciones administrativas y eliminaciones al volver del standby.
4. Validación: H15, entorno reproducible y regresiones de cada corrección; después, experimento independiente con H09/H10 resueltos.

Cada corrección puede hacerse como una tarea separada con su prueba de aceptación. Esta revisión no marca esas correcciones como implementadas.

## Verificación de cierre

Suite completa de cierre: `pytest -q -rs`, **972 passed, 28 skipped, 4 warnings**, exit 0 en **13,31 s**; cobertura **92,62 %**. [Salida completa](revision-2026-09-25/pytest.txt).

Las 28 omisiones corresponden a 25 pruebas del módulo live y tres pruebas de seguridad que requieren `SECURITY_LIVE=1`. No constituyen validación de servicios externos en esta sesión; el defecto del precheck live se describe en H15.

El programa de reproducción se ejecutó nuevamente desde su ubicación final y sus 13 entradas de evidencia coincidieron con el JSON conservado. `git diff --check` pasó. La incompatibilidad de dependencias observada con `uv pip check` permanece registrada; no se modificó el entorno para ocultarla. Las correcciones de producto quedan pendientes, según el alcance de evaluación solicitado.
