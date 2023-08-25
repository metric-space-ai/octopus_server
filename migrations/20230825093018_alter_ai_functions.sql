-- Add migration script here

ALTER TABLE ai_functions ADD COLUMN has_file_response BOOLEAN NOT NULL DEFAULT false;
