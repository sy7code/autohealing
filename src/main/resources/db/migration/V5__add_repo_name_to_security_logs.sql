-- 추가된 다중 레포지토리 로깅 지원을 위한 필드
ALTER TABLE security_logs ADD COLUMN repo_name VARCHAR(255);
