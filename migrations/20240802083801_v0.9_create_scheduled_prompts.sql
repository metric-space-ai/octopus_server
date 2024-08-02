-- Add migration script here

ALTER TYPE workspaces_types ADD VALUE IF NOT EXISTS 'private_scheduled' AFTER 'private';

CREATE TABLE scheduled_prompts(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chat_id UUID NOT NULL REFERENCES chats ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    desired_schedule VARCHAR(256) NOT NULL,
    job_id UUID,
    prompt TEXT NOT NULL,
    schedule VARCHAR(256),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX scheduled_prompts_chat_id ON scheduled_prompts(chat_id);
CREATE INDEX scheduled_prompts_user_id ON scheduled_prompts(user_id);
CREATE INDEX scheduled_prompts_job_id ON scheduled_prompts(job_id);
CREATE INDEX scheduled_prompts_created_at ON scheduled_prompts(created_at);
CREATE INDEX scheduled_prompts_deleted_at ON scheduled_prompts(deleted_at);
CREATE INDEX scheduled_prompts_updated_at ON scheduled_prompts(updated_at);

ALTER TABLE chat_messages ADD COLUMN scheduled_prompt_id UUID REFERENCES scheduled_prompts ON DELETE SET NULL;

CREATE INDEX chat_messages_scheduled_prompt_id ON chat_messages(scheduled_prompt_id);
