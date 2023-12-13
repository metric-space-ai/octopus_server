-- Add migration script here

ALTER TABLE ai_services ADD COLUMN allowed_user_ids UUID [];
ALTER TABLE users ADD COLUMN is_invited BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE parameters(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(256) NOT NULL,
    value TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX parameters_name ON parameters(name);
