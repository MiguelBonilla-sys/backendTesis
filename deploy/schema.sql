-- Canonical PostgreSQL schema and ordered, additive migrations.
-- Used by docker-entrypoint-initdb.d, scripts/schema.sql (symlink) and init_db.py.
-- Safe on empty DB and legacy username schemas; preserves IDs, passwords and rows.
BEGIN;
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 001: reconcile the historical users.username contract before email indexes.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public'
               AND table_name='users' AND column_name='username') THEN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public'
                       AND table_name='users' AND column_name='email') THEN
            ALTER TABLE users RENAME COLUMN username TO email;
        ELSE
            UPDATE users SET email = username WHERE email IS NULL;
            ALTER TABLE users ALTER COLUMN username DROP NOT NULL;
        END IF;
        ALTER TABLE users ALTER COLUMN email TYPE VARCHAR(255);
        -- Historical non-email usernames are preserved for explicit operator mapping.
        -- Do not invent addresses or create users with new identifiers.
    END IF;
END $$;

-- -----------------------------------------------------------
-- 1. users  (auth_router.py consulta por email)
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    email         VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(72)  NOT NULL,          -- bcrypt
    role          VARCHAR(20)  NOT NULL DEFAULT 'student'
                      CHECK (role IN ('student', 'admin', 'viewer')),
    is_active     BOOLEAN      NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_users_email ON users(email);

-- -----------------------------------------------------------
-- 2. incidents  (services/persistence.py — una fila por análisis)
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    email_hash          VARCHAR(64),                        -- content digest; other email fields may contain PII
    url                 TEXT         NOT NULL,
    domain              VARCHAR(253) NOT NULL,
    verdict             VARCHAR(20)  NOT NULL
                            CHECK (verdict IN ('PHISHING', 'SUSPICIOUS', 'LEGITIMATE')),
    s_risk              NUMERIC(7,6) NOT NULL DEFAULT 0.0,
    s_idn               NUMERIC(7,6) NOT NULL DEFAULT 0.0,
    s_llm               NUMERIC(7,6) NOT NULL DEFAULT 0.0,
    s_ti                NUMERIC(7,6) NOT NULL DEFAULT 0.0,
    llm_reason          TEXT,
    shap_contributions  JSONB        DEFAULT '{}',
    analyzed_by         VARCHAR(100),
    email_subject       TEXT         NOT NULL DEFAULT '',
    email_from          TEXT         NOT NULL DEFAULT '',
    email_to            TEXT         NOT NULL DEFAULT '',
    all_urls            JSONB        NOT NULL DEFAULT '[]',
    reasons             JSONB        NOT NULL DEFAULT '[]',
    email_body_html     TEXT         NOT NULL DEFAULT '',
    email_images        JSONB        NOT NULL DEFAULT '[]',
    email_attachments   JSONB        NOT NULL DEFAULT '[]',
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_incidents_email_hash ON incidents(email_hash);
CREATE INDEX IF NOT EXISTS ix_incidents_created    ON incidents(created_at DESC);
CREATE INDEX IF NOT EXISTS ix_incidents_verdict    ON incidents(verdict);
CREATE INDEX IF NOT EXISTS ix_incidents_domain     ON incidents(domain);

-- -----------------------------------------------------------
-- 3. analyzed_urls  (histórico por URL)
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS analyzed_urls (
    id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    url_hash       VARCHAR(64)  UNIQUE NOT NULL,
    url            TEXT         NOT NULL,
    domain         VARCHAR(255) NOT NULL,
    first_seen     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    analysis_count INTEGER      NOT NULL DEFAULT 1,
    last_verdict   VARCHAR(20)  CHECK (last_verdict IN ('PHISHING', 'LEGITIMATE', 'SUSPICIOUS')),
    last_s_risk    NUMERIC(6,4)
);
CREATE INDEX IF NOT EXISTS idx_analyzed_urls_domain  ON analyzed_urls(domain);
CREATE INDEX IF NOT EXISTS idx_analyzed_urls_verdict ON analyzed_urls(last_verdict);

-- -----------------------------------------------------------
-- 4. idn_scores  (detalle del IDN Agent por incidente)
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS idn_scores (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id       UUID         NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    domain_unicode    VARCHAR(255) NOT NULL,
    confusable_chars  JSONB,
    homograph_ratio   NUMERIC(6,4) NOT NULL DEFAULT 0,
    visual_similarity NUMERIC(6,4) NOT NULL DEFAULT 0,
    s_idn_local       NUMERIC(6,4) NOT NULL DEFAULT 0,
    is_mixed_script   BOOLEAN      NOT NULL DEFAULT FALSE,
    is_suspicious     BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_idn_scores_incident ON idn_scores(incident_id);
CREATE INDEX IF NOT EXISTS idx_idn_scores_mixed    ON idn_scores(is_mixed_script);

-- -----------------------------------------------------------
-- 5. ti_results  (resultados de las TI APIs por incidente)
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS ti_results (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID         NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    s_vt        NUMERIC(6,4) NOT NULL DEFAULT 0,
    s_urlscan   NUMERIC(6,4) NOT NULL DEFAULT 0,
    s_gsb       NUMERIC(6,4) NOT NULL DEFAULT 0,
    s_ti        NUMERIC(6,4) NOT NULL DEFAULT 0,
    cache_hit   BOOLEAN      NOT NULL DEFAULT FALSE,
    queried_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ti_results_incident ON ti_results(incident_id);

-- -----------------------------------------------------------
-- 6. audit_log  (traza de seguridad — ISO/IEC 27001/27037)
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL    PRIMARY KEY,
    event_type  VARCHAR(50)  NOT NULL,
    actor       VARCHAR(50),
    resource    VARCHAR(255),
    ip_address  INET,
    status      VARCHAR(20)  NOT NULL CHECK (status IN ('SUCCESS', 'FAILURE', 'BLOCKED')),
    detail      JSONB,
    occurred_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_log_event    ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor    ON audit_log(actor);
CREATE INDEX IF NOT EXISTS idx_audit_log_occurred ON audit_log(occurred_at DESC);

-- -----------------------------------------------------------
-- 7. simulation_events  (módulo educativo)
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS simulation_events (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    student_hash  VARCHAR(64)  NOT NULL,
    campaign_id   VARCHAR(50)  NOT NULL,
    event_type    VARCHAR(30)  NOT NULL CHECK (event_type IN ('SENT', 'OPENED', 'CLICKED', 'REPORTED')),
    url_displayed TEXT,
    is_idn_attack BOOLEAN      NOT NULL DEFAULT FALSE,
    clicked       BOOLEAN      NOT NULL DEFAULT FALSE,
    reported      BOOLEAN      NOT NULL DEFAULT FALSE,
    occurred_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sim_student    ON simulation_events(student_hash);
CREATE INDEX IF NOT EXISTS idx_sim_campaign   ON simulation_events(campaign_id);
CREATE INDEX IF NOT EXISTS idx_sim_event_type ON simulation_events(event_type);

-- -----------------------------------------------------------
-- 8. feedback  (loop de confirmación admin -> ingesta ChromaDB)
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS feedback (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id       UUID        REFERENCES incidents(id) ON DELETE CASCADE,
    confirmed_verdict VARCHAR(20) NOT NULL
                          CHECK (confirmed_verdict IN ('PHISHING', 'SUSPICIOUS', 'LEGITIMATE')),
    confirmed_by      UUID        REFERENCES users(id),
    note              TEXT,
    ingested          BOOLEAN     NOT NULL DEFAULT false,
    ingested_at       TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_feedback_ingested ON feedback(ingested, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_feedback_incident ON feedback(incident_id);

-- -----------------------------------------------------------
-- 9. theta_calibrations  (auditoría de recalibración de θ — T12)
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS theta_calibrations (
    id          UUID             PRIMARY KEY DEFAULT gen_random_uuid(),
    old_theta   DOUBLE PRECISION NOT NULL,
    new_theta   DOUBLE PRECISION NOT NULL,
    n_feedback  INTEGER          NOT NULL,
    loss        DOUBLE PRECISION NOT NULL,
    reason      TEXT             NOT NULL,
    created_at  TIMESTAMPTZ      NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_theta_calibrations_created ON theta_calibrations(created_at DESC);

-- -----------------------------------------------------------
-- 10. weight_calibrations  (calibración online de α/γ/w_hf — T12)
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS weight_calibrations (
    id         UUID             PRIMARY KEY DEFAULT gen_random_uuid(),
    alpha      DOUBLE PRECISION NOT NULL,
    gamma      DOUBLE PRECISION NOT NULL,
    w_hf       DOUBLE PRECISION NOT NULL,
    old_alpha  DOUBLE PRECISION NOT NULL,
    old_gamma  DOUBLE PRECISION NOT NULL,
    old_w_hf   DOUBLE PRECISION NOT NULL,
    n_labels   DOUBLE PRECISION NOT NULL,
    loss       DOUBLE PRECISION NOT NULL,
    reason     TEXT             NOT NULL,
    created_at TIMESTAMPTZ      NOT NULL DEFAULT NOW()
);

-- 001 continued: CREATE TABLE IF NOT EXISTS does not upgrade existing tables.
ALTER TABLE users ALTER COLUMN email TYPE VARCHAR(255);
ALTER TABLE users ALTER COLUMN password_hash TYPE VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('student', 'admin', 'viewer'));
ALTER TABLE incidents ALTER COLUMN analyzed_by TYPE VARCHAR(255);
ALTER TABLE audit_log ALTER COLUMN actor TYPE VARCHAR(255);
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS email_subject TEXT NOT NULL DEFAULT '';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS email_from TEXT NOT NULL DEFAULT '';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS email_to TEXT NOT NULL DEFAULT '';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS all_urls JSONB NOT NULL DEFAULT '[]';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS reasons JSONB NOT NULL DEFAULT '[]';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS email_body_html TEXT NOT NULL DEFAULT '';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS email_images JSONB NOT NULL DEFAULT '[]';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS email_attachments JSONB NOT NULL DEFAULT '[]';
INSERT INTO schema_migrations(version) VALUES ('001_legacy_schema_reconciliation') ON CONFLICT DO NOTHING;

-- 002: global audit identity survives independent sequences and clock skew.
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS event_id UUID NOT NULL DEFAULT gen_random_uuid();
CREATE UNIQUE INDEX IF NOT EXISTS ix_audit_event_id ON audit_log(event_id);
INSERT INTO schema_migrations(version) VALUES ('002_audit_event_identity') ON CONFLICT DO NOTHING;

-- 003: preserve detector availability separately from numeric scores.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS agent_status JSONB NOT NULL DEFAULT '{}';
INSERT INTO schema_migrations(version) VALUES ('003_agent_status') ON CONFLICT DO NOTHING;

-- 004: administrable roles. users.role stays as the base role used by the JWT claim.
-- System roles use fixed UUIDs so the bilateral sync (merge by PK) sees the same rows.
CREATE TABLE IF NOT EXISTS roles (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(60)  UNIQUE NOT NULL,
    description TEXT         NOT NULL DEFAULT '',
    permissions JSONB        NOT NULL DEFAULT '[]',
    is_system   BOOLEAN      NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
INSERT INTO roles (id, name, description, permissions, is_system) VALUES
    ('00000000-0000-4000-8000-000000000001', 'admin', 'Administrador de seguridad',
     '["analyze:run","incidents:read","incidents:feedback","incidents:forensics","metrics:read","settings:read","settings:write","users:manage","roles:manage","alerts:receive","audit:read"]', true),
    ('00000000-0000-4000-8000-000000000002', 'student', 'Estudiante',
     '["analyze:run"]', true),
    ('00000000-0000-4000-8000-000000000003', 'viewer', 'Consulta',
     '["analyze:run","incidents:read","metrics:read"]', true)
ON CONFLICT (id) DO NOTHING;
ALTER TABLE users ADD COLUMN IF NOT EXISTS role_id UUID REFERENCES roles(id);
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_recovery JSONB NOT NULL DEFAULT '[]';
CREATE INDEX IF NOT EXISTS ix_users_role_id ON users(role_id);
INSERT INTO schema_migrations(version) VALUES ('004_rbac') ON CONFLICT DO NOTHING;

-- 005: message forensics. IP, Message-ID and headers are stored encrypted (core/crypto.py).
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS mail_date TIMESTAMPTZ;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS origin_country CHAR(2);
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS origin_city TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS origin_isp TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS origin_asn INTEGER;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS header_source VARCHAR(20) NOT NULL DEFAULT 'none';
ALTER TABLE incidents DROP CONSTRAINT IF EXISTS incidents_header_source_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_header_source_check
    CHECK (header_source IN ('outlook-addin', 'eml', 'gmail-original', 'none'));
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS origin_ip_enc TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS message_id_enc TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS headers_enc TEXT;
CREATE INDEX IF NOT EXISTS ix_incidents_country ON incidents(origin_country);
INSERT INTO schema_migrations(version) VALUES ('005_forensics') ON CONFLICT DO NOTHING;

-- 006: incident classification (category, CIA impact).
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS primary_category VARCHAR(40);
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS categories JSONB NOT NULL DEFAULT '[]';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS impact JSONB NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS ix_incidents_category ON incidents(primary_category);
INSERT INTO schema_migrations(version) VALUES ('006_classification') ON CONFLICT DO NOTHING;
COMMIT;
