-- =============================================================
-- seed_users.sql — usuarios por defecto (dev/tesis)
-- Corre después de schema.sql (orden alfabético en /docker-entrypoint-initdb.d).
-- Idempotente: ON CONFLICT DO NOTHING. Hashes bcrypt — sin contraseñas en claro.
-- Vendorizado desde infraTesis/scripts/seed_users.sql.
-- =============================================================

INSERT INTO users (email, password_hash, role, is_active)
VALUES
  (
    'mabonillat@academia.usbbog.edu.co',
    '$2b$12$m6Skj063sf1wFCviOiqApe1LpygyIcCps/4BqQX/4WgosfbyVKWp2',
    'admin',
    true
  ),
  (
    'jsfandinon@academia.usbbog.edu.co',
    '$2b$12$rLSoO6YrhPAy2j4.JRSLgOfpy1KeEk0ZabHXOjutPP45LbcJx8ej6',
    'student',
    true
  )
ON CONFLICT (email) DO NOTHING;
