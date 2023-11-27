-- Add migration script here

ALTER TABLE ai_services ADD COLUMN allowed_user_ids UUID [];
