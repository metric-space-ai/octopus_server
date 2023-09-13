-- Add migration script here

ALTER TABLE chat_messages ADD COLUMN ai_function_call JSON;
