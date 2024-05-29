-- Add migration script here

ALTER TABLE ai_functions ADD COLUMN display_name VARCHAR(256);

CREATE TYPE ai_service_generator_statuses AS ENUM('changed', 'deployed', 'generated', 'generating', 'initial', 'internet_research_ended', 'internet_research_started');

CREATE TABLE ai_service_generators(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    ai_service_id UUID REFERENCES ai_services ON DELETE SET NULL,
    description TEXT NOT NULL,
    internet_research_results TEXT,
    log TEXT,
    name VARCHAR(256) NOT NULL,
    original_function_body TEXT,
    sample_code TEXT,
    status ai_service_generator_statuses NOT NULL DEFAULT 'initial',
    version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX ai_service_generators_user_id ON ai_service_generators(user_id);
CREATE INDEX ai_service_generators_ai_service_id ON ai_service_generators(ai_service_id);
CREATE INDEX ai_service_generators_deleted_at ON ai_service_generators(deleted_at);
CREATE INDEX ai_service_generators_name ON ai_service_generators(name);
CREATE INDEX ai_service_generators_version ON ai_service_generators(version);

ALTER TABLE ai_services ADD COLUMN ai_service_generator_id UUID REFERENCES ai_service_generators ON DELETE SET NULL;

CREATE INDEX ai_services_ai_service_generator_id ON ai_services(ai_service_generator_id);

ALTER TABLE chat_messages ADD COLUMN suggested_ai_function_id UUID REFERENCES ai_functions ON DELETE CASCADE;

CREATE INDEX chat_messages_suggested_ai_function_id ON chat_messages(suggested_ai_function_id);
