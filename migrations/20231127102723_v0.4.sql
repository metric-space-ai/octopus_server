-- Add migration script here

ALTER TABLE ai_services ADD COLUMN allowed_user_ids UUID [];
ALTER TABLE users ADD COLUMN is_invited BOOLEAN NOT NULL DEFAULT false;
