-- Add migration script here

ALTER TABLE chat_messages ADD COLUMN is_sensitive BOOLEAN NOT NULL DEFAULT false;
