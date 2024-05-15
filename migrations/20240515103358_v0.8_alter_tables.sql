-- Add migration script here

ALTER TABLE ai_services ADD COLUMN color VARCHAR(7) DEFAULT '#b7b7b7';
ALTER TABLE chat_messages ADD COLUMN color VARCHAR(7);
