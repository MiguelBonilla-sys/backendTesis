-- ============================================================
-- Schema: phishing_detector
-- PostgreSQL 15 — no PII, emails as SHA-256 hashes
-- Ley 1581/2012 compliance
-- Authors: Juan Sebastián Fandiño Novoa & Miguel Ángel Bonilla Torres
-- USB Bogotá, 2026
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ----------------------------------------------------------------
-- TABLE 1: users
-- Admin/viewer accounts for dashboard access
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    username      VARCHAR(50)  UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,  -- bcrypt hash
    role          VARCHAR(20)  NOT NULL DEFAULT 'viewer'
                  CHECK (role IN ('admin', 'student', 'viewer')),
    is_active     BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_login    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- ----------------------------------------------------------------
-- TABLE 2: incidents
-- Main analysis results — one row per analyzed URL
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id                 UUID         PRIMARY KEY,
    email_hash         VARCHAR(64)  NOT NULL DEFAULT '',  -- SHA-256 of email (may be empty)
    url                TEXT         NOT NULL,
    domain             VARCHAR(255) NOT NULL,
    verdict            VARCHAR(20)  NOT NULL
                       CHECK (verdict IN ('PHISHING', 'LEGITIMATE', 'SUSPICIOUS')),
    s_risk             NUMERIC(6,4) NOT NULL CHECK (s_risk BETWEEN 0 AND 1),
    s_idn              NUMERIC(6,4) NOT NULL CHECK (s_idn BETWEEN 0 AND 1),
    s_llm              NUMERIC(6,4) NOT NULL CHECK (s_llm BETWEEN 0 AND 1),
    s_ti               NUMERIC(6,4) NOT NULL CHECK (s_ti BETWEEN 0 AND 1),
    llm_reason         TEXT,
    shap_contributions JSONB,       -- dict[str, float] SHAP feature contributions
    analyzed_by        VARCHAR(50), -- username who triggered analysis
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incidents_verdict    ON incidents(verdict);
CREATE INDEX IF NOT EXISTS idx_incidents_domain     ON incidents(domain);
CREATE INDEX IF NOT EXISTS idx_incidents_created    ON incidents(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_email_hash ON incidents(email_hash);

-- ----------------------------------------------------------------
-- TABLE 3: analyzed_urls
-- Deduplicated URL registry — avoids re-analyzing same URL
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analyzed_urls (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    url_hash        VARCHAR(64)  UNIQUE NOT NULL,  -- SHA-256 of URL
    url             TEXT         NOT NULL,
    domain          VARCHAR(255) NOT NULL,
    first_seen      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    analysis_count  INTEGER      NOT NULL DEFAULT 1,
    last_verdict    VARCHAR(20)  CHECK (last_verdict IN ('PHISHING', 'LEGITIMATE', 'SUSPICIOUS')),
    last_s_risk     NUMERIC(6,4)
);

CREATE INDEX IF NOT EXISTS idx_analyzed_urls_domain  ON analyzed_urls(domain);
CREATE INDEX IF NOT EXISTS idx_analyzed_urls_verdict ON analyzed_urls(last_verdict);

-- ----------------------------------------------------------------
-- TABLE 4: idn_scores
-- IDN Agent detailed scores per incident
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS idn_scores (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id       UUID         NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    domain_unicode    VARCHAR(255) NOT NULL,
    confusable_chars  JSONB,       -- list[str]
    homograph_ratio   NUMERIC(6,4) NOT NULL DEFAULT 0,
    visual_similarity NUMERIC(6,4) NOT NULL DEFAULT 0,
    s_idn_local       NUMERIC(6,4) NOT NULL DEFAULT 0,
    is_mixed_script   BOOLEAN      NOT NULL DEFAULT FALSE,
    is_suspicious     BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_idn_scores_incident ON idn_scores(incident_id);
CREATE INDEX IF NOT EXISTS idx_idn_scores_mixed    ON idn_scores(is_mixed_script);

-- ----------------------------------------------------------------
-- TABLE 5: ti_results
-- Threat Intelligence API results per incident
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ti_results (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID         NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    s_vt        NUMERIC(6,4) NOT NULL DEFAULT 0,
    s_urlscan   NUMERIC(6,4) NOT NULL DEFAULT 0,
    s_gsb       NUMERIC(6,4) NOT NULL DEFAULT 0,
    s_ti        NUMERIC(6,4) NOT NULL DEFAULT 0,
    cache_hit   BOOLEAN      NOT NULL DEFAULT FALSE,  -- TRUE si vino de Redis
    queried_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ti_results_incident ON ti_results(incident_id);

-- ----------------------------------------------------------------
-- TABLE 6: audit_log
-- Security audit trail — all significant actions
-- ISO/IEC 27001 + 27037 compliance
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL    PRIMARY KEY,
    event_type  VARCHAR(50)  NOT NULL,  -- LOGIN, ANALYZE, REPORT, etc.
    actor       VARCHAR(50),            -- username or 'system'
    resource    VARCHAR(255),           -- URL or endpoint affected
    ip_address  INET,
    status      VARCHAR(20)  NOT NULL CHECK (status IN ('SUCCESS', 'FAILURE', 'BLOCKED')),
    detail      JSONB,
    occurred_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_event    ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor    ON audit_log(actor);
CREATE INDEX IF NOT EXISTS idx_audit_log_occurred ON audit_log(occurred_at DESC);

-- ----------------------------------------------------------------
-- TABLE 7: simulation_events
-- Educational module — phishing simulation interactions
-- Records student interactions with simulated phishing campaigns
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS simulation_events (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    student_hash  VARCHAR(64)  NOT NULL,  -- SHA-256 of student email
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

-- ----------------------------------------------------------------
-- Default admin user (password must be set via env + bcrypt)
-- ----------------------------------------------------------------
-- DO NOT insert credentials here — use migrations or env vars
-- Example: INSERT INTO users (username, password_hash, role)
--          VALUES ('admin', '$2b$12$...bcrypt_hash...', 'admin');
