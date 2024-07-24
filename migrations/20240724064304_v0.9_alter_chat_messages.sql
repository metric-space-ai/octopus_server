-- Add migration script here

ALTER TABLE chat_messages ADD COLUMN suggested_llm VARCHAR(256);
ALTER TABLE chat_messages ADD COLUMN suggested_model VARCHAR(256);
ALTER TABLE chat_messages ADD COLUMN suggested_secondary_model BOOLEAN NOT NULL DEFAULT false;

UPDATE parameters SET name = 'MAIN_LLM_OPENAI_PRIMARY_MODEL' WHERE name = 'MAIN_LLM_OPENAI_MODEL';
