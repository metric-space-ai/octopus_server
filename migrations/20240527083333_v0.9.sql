-- Add migration script here

ALTER TABLE ai_functions ADD COLUMN display_name VARCHAR(256);

ALTER TABLE chat_messages ADD COLUMN suggested_ai_function_id UUID REFERENCES ai_functions ON DELETE CASCADE;

CREATE INDEX chat_messages_suggested_ai_function_id ON chat_messages(suggested_ai_function_id);
