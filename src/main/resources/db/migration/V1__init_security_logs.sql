-- -----------------------------------------------------
-- Schema Setup: Security Logs
-- Represents the initial state (Baseline) of the JPA Entity SecurityLog
-- PostgreSQL Dialect
-- -----------------------------------------------------

CREATE TABLE security_logs (
    id BIGSERIAL PRIMARY KEY,
    resource_name VARCHAR(255) NOT NULL,
    threat_type VARCHAR(255) NOT NULL,
    severity VARCHAR(255) NOT NULL,
    status VARCHAR(255) NOT NULL,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    snyk_id VARCHAR(255),
    jira_key VARCHAR(255),
    pr_number INTEGER,
    ai_fixed BOOLEAN NOT NULL DEFAULT FALSE,
    is_approved BOOLEAN NOT NULL DEFAULT FALSE,
    resolved_at TIMESTAMP,
    original_code TEXT,
    patched_code TEXT,
    fix_explanation TEXT
);
