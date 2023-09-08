-- Add migration script here

ALTER TABLE chat_messages DROP COLUMN ai_function_id;

DROP TABLE ai_functions;
DROP TYPE ai_functions_health_check_statuses;
DROP TYPE ai_functions_setup_statuses;
DROP TYPE ai_functions_warmup_statuses;

CREATE TYPE ai_services_health_check_statuses AS ENUM('not_working', 'ok');
CREATE TYPE ai_services_setup_statuses AS ENUM('not_performed', 'performed');

CREATE TABLE ai_services(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_map JSON NOT NULL,
    health_check_execution_time INT NOT NULL DEFAULT 0,
    health_check_status ai_services_health_check_statuses NOT NULL DEFAULT 'not_working',
    is_enabled BOOLEAN NOT NULL DEFAULT false,
    original_file_name VARCHAR(256) NOT NULL,
    original_function_body TEXT NOT NULL,
    port INT NOT NULL,
    processed_function_body TEXT,
    setup_execution_time INT NOT NULL DEFAULT 0,
    setup_status ai_services_setup_statuses NOT NULL DEFAULT 'not_performed',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    health_check_at TIMESTAMP WITH TIME ZONE,
    setup_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    UNIQUE(port)
);

CREATE INDEX ai_services_deleted_at ON ai_services(deleted_at);
CREATE INDEX ai_services_health_check_status ON ai_services(health_check_status);
CREATE INDEX ai_services_is_enabled ON ai_services(is_enabled);
CREATE INDEX ai_services_setup_status ON ai_services(setup_status);

CREATE TYPE ai_functions_request_content_types AS ENUM('application_json');
CREATE TYPE ai_functions_response_content_types AS ENUM('application_json', 'image_jpeg', 'image_png', 'text_plain');

CREATE TABLE ai_functions(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ai_service_id UUID NOT NULL REFERENCES ai_services ON DELETE CASCADE,
    description TEXT NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT false,
    name VARCHAR(256) NOT NULL,
    parameters JSON NOT NULL,
    request_content_type ai_functions_request_content_types NOT NULL DEFAULT 'application_json',
    response_content_type ai_functions_response_content_types NOT NULL DEFAULT 'application_json',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    UNIQUE(name)
);

CREATE INDEX ai_functions_is_enabled ON ai_functions(is_enabled);
CREATE INDEX ai_functions_request_content_type ON ai_functions(request_content_type);
CREATE INDEX ai_functions_response_content_type ON ai_functions(response_content_type);

ALTER TABLE chat_messages ADD COLUMN ai_function_id UUID REFERENCES ai_functions ON DELETE SET NULL;

CREATE INDEX chat_messages_ai_function_id ON chat_messages(ai_function_id);
