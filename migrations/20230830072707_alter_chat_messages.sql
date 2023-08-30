-- Add migration script here

ALTER TABLE chat_messages ADD COLUMN bypass_sensitive_information_filter BOOLEAN NOT NULL DEFAULT false;
