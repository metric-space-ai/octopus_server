-- Add migration script here

ALTER TABLE chat_messages ADD COLUMN used_llm VARCHAR(256);
ALTER TABLE chat_messages ADD COLUMN used_model VARCHAR(256);

CREATE INDEX chat_messages_used_llm ON chat_messages(used_llm);
CREATE INDEX chat_messages_used_model ON chat_messages(used_model);
