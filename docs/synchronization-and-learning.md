# Sincronización y límites del aprendizaje

## Autoridad, recuperación y borrados

El sistema tiene **una autoridad de escritura por vez**, PostgreSQL y Chroma de la misma instancia. Los scripts anteriores que unían IDs ausentes en ambos sentidos ya no son válidos: restauraban documentos purgados y omitían cambios de contraseña, rol, estado y feedback. El nombre `sync_pg_bilateral.py` se conserva por compatibilidad de importación, pero su ejecución ahora hace una copia autoritativa.

Antes de sincronizar:

1. Aplicar `deploy/schema.sql` en ambas bases y conservar un backup recuperable. `python -m scripts.init_db` usa ese mismo esquema. La migración de `users.username` conserva los valores e IDs; los nombres históricos que no sean correos requieren un mapeo explícito del operador antes de iniciar sesión por email. No se inventan correos ni se eliminan usuarios.
2. Elegir la instancia que contiene la historia válida completa. Parar solicitudes de escritura, feedback, aprendizaje y jobs en ambos lados; esperar las tareas pendientes. Impedir que balanceadores o cron reactiven la réplica. Si hubo escrituras divergentes, reconciliarlas en la autoridad **antes** del espejo: el script no decide qué negocio conservar.
3. Ejecutar ambos scripts con la **misma** autoridad. Ejemplo, desde el contenedor configurado para las bases locales:

   ```sh
   python -m scripts.sync_pg_bilateral --authority local --replica-fenced --source-quiesced
   python -m scripts.sync_chroma_standby --authority local --replica-fenced --source-quiesced \
     --source-space ESPACIO_VERIFICADO_ORIGEN --destination-space ESPACIO_VERIFICADO_DESTINO
   ```

   Los flags son una declaración operacional explícita; el programa no puede verificar el estado del balanceador. Sin ellos se detiene antes de abrir conexiones de escritura. `--dry-run` de PostgreSQL y `--check` de Chroma no mutan datos. `--check` solo compara conteos y dimensiones, no certifica igualdad del contenido.
4. Mantener la réplica fuera de servicio hasta que ambos terminen. Reiniciar los procesos que la usarán para vaciar índices BM25 y cachés anteriores. Las sesiones Redis no se replican: exigir nuevo login al promover una instancia. Reactivar exactamente una autoridad.

Si el standby atendió escrituras durante una caída, permanece como autoridad: al recuperar local, usar `--authority standby` para ambos scripts antes de cambiar el tráfico. Nunca sincronizar desde el local antiguo hacia un standby que atendió la caída. Los cron anteriores deben retirarse; `deploy/sync-standby.sh` exige autoridad y flags en cada invocación y no debe ejecutarse sin la ventana operacional.

PostgreSQL replica valores completos, elimina filas ausentes en la autoridad y aplica su copia en una transacción con locks. Un error de esquema, FK o unicidad aborta la copia: no se descartan conflictos silenciosamente. Los eventos de auditoría llevan UUID global y se agregan en ambos lados por ese UUID, conservando eventos con relojes y secuencias locales diferentes; no dependen de un máximo timestamp. La primera migración puede conservar duplicados semánticos de auditoría histórica que ya carecía de identidad global.

Chroma copia documentos/metadatos modificados y elimina IDs ausentes, incluso si una colección origen válida está vacía. Una colección origen ausente o inaccesible es un error, nunca permiso para vaciar el destino. No borra colecciones ni cambia su dimensión para resolver incompatibilidades. El embedder destino debe seguir siendo el configurado para su colección; si ambos lados usan espacios diferentes, configurar `STANDBY_EMBED_*` para re-embebido. Chroma no ofrece transacción entre colecciones y PostgreSQL/Chroma no comparten transacción: ante fallo parcial, mantener la réplica cercada y repetir desde la misma autoridad. Los IDs estables hacen la repetición idempotente.

Cada colección debe declarar en su metadata `embedding_space`, identificando el modelo/revisión/configuración efectivamente usados. Los argumentos deben coincidir con esa metadata; la copia directa exige el mismo espacio. Colecciones heredadas sin procedencia verificada detienen el proceso: revisar su creación y el modelo antes de registrar la etiqueta, preservando el resto de metadata. No inferir identidad del modelo solo por su dimensión. Si no se puede verificar, preparar otra colección con procedencia conocida y una migración revisada. El wrapper exige `SOURCE_EMBED_SPACE` y `DESTINATION_EMBED_SPACE` coherentes con la dirección seleccionada.

Una actualización elimina y repone únicamente la fila modificada de la réplica: Chroma fusiona metadata en upsert y, sin este reemplazo, conservaría campos de caducidad/cuarentena retirados por la autoridad. Se comprueban los embeddings antes de reemplazar la fila. Un fallo de red posterior requiere repetir con la réplica todavía fuera de servicio.

## Autoaprendizaje

`AUTO_INGEST_QUOTA` ahora limita la fracción de documentos automáticos **en cada una** de las tres colecciones. Cero desactiva admisión. Una colección vacía no recibe predicciones automáticas hasta tener suficientes referencias confiables. `AUTO_INGEST_MAX_DOCUMENTS` agrega un máximo absoluto por colección (2000 por defecto). La admisión y la escritura comparten un advisory lock transaccional PostgreSQL entre procesos; sin DB, sin incidente persistido, con feedback LEGITIMATE anterior o con error de Chroma, la admisión se rechaza.

Los documentos se identifican por SHA-256 de la URL sin fragmento, preservando host, ruta y query. Repetir análisis sobre la misma URL sobrescribe una única evidencia por colección, aunque cambie el incidente; una predicción no puede sobrescribir evidencia confirmada. El feedback legítimo purga el ID estable y los IDs históricos de incidentes de esa URL. Su fila persistida bloquea posteriores reingestas automáticas de la entidad; un administrador puede agregar evidencia confirmada nueva.

La evidencia automática lleva `expires_at`, con retención de `AUTO_INGEST_RETENTION_DAYS` (30 días por defecto). La recuperación excluye vencidos y registros automáticos sin fecha válida; la siguiente admisión elimina físicamente los vencidos. `AUTO_INGEST_SCAN_LIMIT` limita el barrido de metadata (10000); si un corpus legado supera ese presupuesto, falla cerrado y requiere una limpieza supervisada, sin truncarlo automáticamente. No se purgan referencias humanas ni colecciones completas.

La autoingesta ya no invalida BM25 en cada escritura; se incorpora al expirar su TTL. Confirmaciones y purgas invalidan inmediatamente el índice local. Un lock por colección evita reconstrucciones concurrentes y una generación impide publicar un índice construido mientras se purgaba. La lectura está paginada y `RAG_BM25_MAX_DOCUMENTS` acota a 10000 documentos el canal léxico; el canal denso sigue disponible sobre el corpus completo. Construcción/tokenización se realizan fuera del event loop. Estos son límites verificables de trabajo, no una medición de p95 bajo carga real.
