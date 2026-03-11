ALTER TABLE security_logs ADD COLUMN scanner_name VARCHAR(50);
ALTER TABLE security_logs ADD COLUMN ai_engine_name VARCHAR(50);
ALTER TABLE security_logs ADD COLUMN processing_time_ms BIGINT;
ALTER TABLE security_logs RENAME COLUMN snyk_id TO vuln_id;
-- v12 삭제: UNIQUE 제약
