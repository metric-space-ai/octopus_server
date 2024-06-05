-- Add migration script here

ALTER TABLE chat_messages ADD COLUMN ai_service_id UUID REFERENCES ai_services ON DELETE SET NULL;

CREATE INDEX chat_messages_ai_service_id ON chat_messages(ai_service_id);

UPDATE chat_messages
SET ai_service_id = subquery.ai_service_id
FROM (SELECT id, ai_service_id FROM ai_functions) AS subquery
WHERE chat_messages.ai_function_id = subquery.id;
