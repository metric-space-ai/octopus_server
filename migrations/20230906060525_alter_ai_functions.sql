-- Add migration script here

DELETE FROM ai_functions;

DROP INDEX ai_functions_is_available;
DROP INDEX ai_functions_warmup_status;

ALTER TABLE ai_functions DROP COLUMN base_function_url;
ALTER TABLE ai_functions DROP COLUMN health_check_url;
ALTER TABLE ai_functions DROP COLUMN is_available;
ALTER TABLE ai_functions DROP COLUMN k8s_configuration;
ALTER TABLE ai_functions DROP COLUMN setup_url;
ALTER TABLE ai_functions DROP COLUMN warmup_at;
ALTER TABLE ai_functions DROP COLUMN warmup_execution_time;
ALTER TABLE ai_functions DROP COLUMN warmup_status;

DROP TYPE ai_functions_warmup_statuses;

ALTER TABLE ai_functions ADD COLUMN original_file_name VARCHAR(256) NOT NULL;
ALTER TABLE ai_functions ADD COLUMN original_function_body TEXT NOT NULL;
ALTER TABLE ai_functions ADD COLUMN port INT;
ALTER TABLE ai_functions ADD COLUMN processed_function_body TEXT;
