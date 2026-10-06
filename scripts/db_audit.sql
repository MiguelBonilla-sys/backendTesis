-- =============================================================================
-- db_audit.sql — verificación estática del checklist CIS PostgreSQL 15
-- (subconjunto ejecutable, T32)
--
-- Cada fila devuelta es UN hallazgo; cero filas = controles conformes en el
-- subconjunto verificado. Las referencias CIS son de la edición PostgreSQL 15
-- del benchmark y se citan como referencia del control, no como resultado de
-- una auditoría certificada. Algunos controles CIS exigen configuración a
-- nivel de clúster (pg_hba, postgresql.conf) que aquí solo se observa.
--
-- Ejecución:
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=0 -f scripts/db_audit.sql
--   (o desde el contenedor: podman exec -i <postgres> psql -U "$POSTGRES_USER" \
--        -d "$POSTGRES_DB" < scripts/db_audit.sql)
-- =============================================================================

SELECT
  'db-audit.01' AS check_id,
  'CIS 3.2 (Authentication) — password_encryption debe ser scram-sha-256' AS description,
  current_setting('password_encryption') AS observed
WHERE current_setting('password_encryption') <> 'scram-sha-256'

UNION ALL SELECT
  'db-audit.02',
  'CIS 3.3 (Network) — ssl debe estar activado',
  current_setting('ssl')
WHERE current_setting('ssl') <> 'on'

UNION ALL SELECT
  'db-audit.03',
  'CIS 3.1 (Logging) — log_destination debe incluir stderr/csvlog/syslog',
  current_setting('log_destination')
WHERE current_setting('log_destination') NOT IN ('stderr', 'csvlog', 'syslog')

UNION ALL SELECT
  'db-audit.04',
  'CIS 3.1 (Logging) — log_connections debe estar activado',
  current_setting('log_connections')
WHERE current_setting('log_connections') <> 'on'

UNION ALL SELECT
  'db-audit.05',
  'CIS 3.1 (Logging) — log_disconnections debe estar activado',
  current_setting('log_disconnections')
WHERE current_setting('log_disconnections') <> 'on'

UNION ALL SELECT
  'db-audit.06',
  'CIS 3.1 (Logging) — log_min_error_statement debe ser error o más severo',
  current_setting('log_min_error_statement')
WHERE current_setting('log_min_error_statement') NOT IN ('error', 'log', 'fatal', 'panic')

UNION ALL SELECT
  'db-audit.07',
  'CIS 3.1 (Logging) — log_statement debe incluir ddl/mod/all',
  current_setting('log_statement')
WHERE current_setting('log_statement') NOT IN ('ddl', 'mod', 'all')

UNION ALL SELECT
  'db-audit.08',
  'CIS 3.1 (Logging) — log_line_prefix debe incluir %m (tiempo), %u (usuario), %d (bd), %h (host)',
  current_setting('log_line_prefix')
WHERE NOT (
  current_setting('log_line_prefix') LIKE '%m%' AND
  current_setting('log_line_prefix') LIKE '%u%' AND
  current_setting('log_line_prefix') LIKE '%d%' AND
  current_setting('log_line_prefix') LIKE '%h%'
)

UNION ALL SELECT
  'db-audit.09',
  'CIS 3.6 (pg_hba) — no debe haber entradas con método trust',
  line_number::text
FROM pg_hba_file_rules
WHERE auth_method = 'trust'

UNION ALL SELECT
  'db-audit.10',
  'CIS 3.4 (Authorization) — PUBLIC no debe tener CREATE sobre el esquema public',
  'public'
FROM pg_namespace n
CROSS JOIN LATERAL aclexplode(n.nspacl) a
WHERE n.nspname = 'public' AND a.grantee = 0 AND a.privilege_type = 'CREATE'

UNION ALL SELECT
  'db-audit.11',
  'CIS 3.4 (Authorization) — PUBLIC no debe tener EXECUTE sobre funciones sensibles de pg_catalog',
  p.proname || ' (' || a.privilege_type || ')'
FROM pg_proc p
CROSS JOIN LATERAL aclexplode(p.proacl) a
WHERE p.proname IN ('pg_read_file', 'pg_write_file', 'pg_read_all_settings', 'pg_ls_dir')
  AND a.grantee = 0 AND a.privilege_type = 'EXECUTE'

UNION ALL SELECT
  'db-audit.12',
  'CIS 3.4 (Authorization) — solo el superusuario debe tener super/CREATEDB/CREATEROLE/REPLICATION',
  r.rolname ||
    CASE WHEN r.rolsuper THEN ' super' ELSE '' END ||
    CASE WHEN r.rolcreatedb THEN ' createdb' ELSE '' END ||
    CASE WHEN r.rolcreaterole THEN ' createrole' ELSE '' END ||
    CASE WHEN r.rolreplication THEN ' replication' ELSE '' END
FROM pg_roles r
WHERE r.rolname NOT IN ('postgres')
  AND (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication)

UNION ALL SELECT
  'db-audit.13',
  'CIS 3.5 (Extensions) — extensiones instaladas fuera de la lista permitida (plpgsql, pgcrypto)',
  e.extname || ' (' || e.extversion || ')'
FROM pg_extension e
WHERE e.extname NOT IN ('plpgsql', 'pgcrypto')

UNION ALL SELECT
  'db-audit.14',
  'CIS 3.4 (Authorization) — objetos de esquemas comunes con dueño distinto del superusuario',
  n.nspname || '.' || c.relname || ' dueño ' || pg_get_userbyid(c.relowner)
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname IN ('public', 'pg_catalog', 'information_schema')
  AND c.relkind IN ('r', 'v', 'm')
  AND pg_get_userbyid(c.relowner) <> 'postgres'
;
