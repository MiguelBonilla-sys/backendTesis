-- =============================================================
-- phishing_detector — schema de despliegue (Coolify / producción)
-- =============================================================
-- Fuente de verdad para el schema que consume el código actual.
-- Reconcilia la deriva entre backendTesis/scripts/schema.sql (users.username,
-- incidents sin columnas de email) e infraTesis/scripts/schema.sql (users.email,
-- incidents completo, sin tablas auxiliares). Ver tarea T1 (sync tesis <-> código).
--
--   users, incidents, feedback            -> forma de infraTesis (auth usa users.email;
--                                            persistence.py inserta 19 columnas en incidents)
--   analyzed_urls, idn_scores, ti_results,
--   audit_log, simulation_events,
--   theta_calibrations                    -> backendTesis/scripts/schema.sql
--   weight_calibrations                   -> scripts/recalibrate_weights.py (T12 online)
--
-- Idempotente: CREATE ... IF NOT EXISTS en todo. Lo aplica el entrypoint de
-- postgres:15-alpine desde /docker-entrypoint-initdb.d/ (solo en primer init).
-- Authors: Juan Sebastián Fandiño Novoa & Miguel Ángel Bonilla Torres — USB Bogotá, 2026
-- =============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- -----------------------------------------------------------
-- 1. users  (auth_router.py consulta por email)
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    email         VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(72)  NOT NULL,          -- bcrypt
    role          VARCHAR(20)  NOT NULL DEFAULT 'student'
                      CHECK (role IN ('student', 'admin')),
    is_active     BOOLEAN      NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_users_email ON users(email);

-- -----------------------------------------------------------
-- 2. incidents  (services/persistence.py — una fila por análisis)
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    email_hash          VARCHAR(64),                        -- SHA-256 del correo, nunca PII cruda
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
