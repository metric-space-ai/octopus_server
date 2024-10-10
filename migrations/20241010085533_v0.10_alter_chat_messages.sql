-- Add migration script here

ALTER TABLE chat_messages ADD COLUMN suggested_simple_app_id UUID REFERENCES simple_apps ON DELETE CASCADE;
ALTER TABLE chat_messages ADD COLUMN suggested_wasp_app_id UUID REFERENCES wasp_apps ON DELETE CASCADE;

CREATE INDEX chat_messages_suggested_simple_app_id ON chat_messages(suggested_simple_app_id);
CREATE INDEX chat_messages_suggested_wasp_app_id ON chat_messages(suggested_wasp_app_id);
