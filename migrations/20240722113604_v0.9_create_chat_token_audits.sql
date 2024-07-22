-- Add migration script here

CREATE TABLE chat_token_audits(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chat_id UUID NOT NULL REFERENCES chats ON DELETE CASCADE,
    chat_message_id UUID NOT NULL REFERENCES chat_messages ON DELETE CASCADE,
    company_id UUID NOT NULL REFERENCES companies ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    input_tokens BIGINT NOT NULL,
    llm VARCHAR(256) NOT NULL,
    model VARCHAR(256) NOT NULL,
    output_tokens BIGINT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX chat_token_audits_chat_id ON chat_token_audits(chat_id);
CREATE INDEX chat_token_audits_chat_message_id ON chat_token_audits(chat_message_id);
CREATE INDEX chat_token_audits_company_id ON chat_token_audits(company_id);
CREATE INDEX chat_token_audits_user_id ON chat_token_audits(user_id);
CREATE INDEX chat_token_audits_llm ON chat_token_audits(llm);
CREATE INDEX chat_token_audits_model ON chat_token_audits(model);
CREATE INDEX chat_token_audits_created_at ON chat_token_audits(created_at);
