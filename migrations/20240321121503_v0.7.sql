-- Add migration script here

CREATE TYPE wasp_generator_statuses AS ENUM('changed', 'generated', 'generating', 'initial');

CREATE TABLE wasp_generators(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    wasp_app_id UUID,
    api_access_secret VARCHAR(256),
    api_access_url VARCHAR(256),
    code BYTEA,
    description TEXT NOT NULL,
    log TEXT,
    name VARCHAR(256) NOT NULL,
    status wasp_generator_statuses NOT NULL DEFAULT 'initial',
    version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX wasp_generators_user_id ON wasp_generators(user_id);
CREATE INDEX wasp_generators_wasp_app_id ON wasp_generators(wasp_app_id);
CREATE INDEX wasp_generators_deleted_at ON wasp_generators(deleted_at);
CREATE INDEX wasp_generators_name ON wasp_generators(name);
CREATE INDEX wasp_generators_version ON wasp_generators(version);

ALTER TABLE wasp_apps ADD COLUMN wasp_generator_id UUID REFERENCES wasp_generators ON DELETE SET NULL;

CREATE INDEX wasp_apps_wasp_generator_id ON wasp_apps(wasp_generator_id);
