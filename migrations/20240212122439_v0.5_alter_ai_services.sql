-- Add migration script here

CREATE TYPE ai_services_types AS ENUM('normal', 'system');

ALTER TABLE ai_services ADD COLUMN type ai_services_types NOT NULL DEFAULT 'normal';
