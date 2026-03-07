CREATE TABLE plugin_configs (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    plugin_type VARCHAR(20) NOT NULL,
    auth_type VARCHAR(20) DEFAULT 'BEARER',
    auth_header_name VARCHAR(100),
    api_url VARCHAR(500),
    api_key_encrypted TEXT,
    http_method VARCHAR(10) DEFAULT 'GET',
    result_json_path VARCHAR(200),
    title_field VARCHAR(100),
    severity_field VARCHAR(100),
    severity_mapping_json TEXT,
    id_field VARCHAR(100),
    model_name VARCHAR(100),
    enabled BOOLEAN DEFAULT true
);
