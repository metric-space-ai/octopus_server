-- Add migration script here

ALTER TYPE ai_services_statuses ADD VALUE IF NOT EXISTS 'restarting' AFTER 'parsing_started';
