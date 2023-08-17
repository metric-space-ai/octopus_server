-- Add migration script here

CREATE TABLE chat_audits(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chat_id UUID NOT NULL REFERENCES chats ON DELETE CASCADE,
    chat_message_id UUID NOT NULL REFERENCES chat_messages ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    trail JSON NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX chat_audits_chat_id ON chat_audits(chat_id);
CREATE INDEX chat_audits_chat_message_id ON chat_audits(chat_message_id);
CREATE INDEX chat_audits_user_id ON chat_audits(user_id);
CREATE INDEX chat_audits_created_at ON chat_audits(created_at);
