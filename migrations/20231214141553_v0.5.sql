-- Add migration script here

CREATE TABLE wasp_apps(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    allowed_user_ids UUID [],
    code BYTEA NOT NULL,
    description TEXT NOT NULL,
    formatted_name VARCHAR(256) NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT false,
    name VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX wasp_apps_deleted_at ON wasp_apps(deleted_at);
CREATE INDEX wasp_apps_is_enabled ON wasp_apps(is_enabled);
CREATE INDEX wasp_apps_formatted_name ON wasp_apps(formatted_name);

ALTER TABLE chat_messages ADD COLUMN wasp_app_id UUID REFERENCES wasp_apps ON DELETE SET NULL;

CREATE INDEX chat_messages_wasp_app_id ON chat_messages(wasp_app_id);
CREATE INDEX parameters_deleted_at ON parameters(deleted_at);
