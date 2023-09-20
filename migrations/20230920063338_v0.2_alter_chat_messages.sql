-- Add migration script here

ALTER TABLE chat_messages ADD COLUMN is_anonymized BOOLEAN NOT NULL DEFAULT false;
