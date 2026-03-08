-- v19: 플러그인별 커스텀 파라미터 저장을 위한 컬럼 추가
ALTER TABLE plugin_configs ADD COLUMN custom_params_json TEXT;
