-- Add migration script here

CREATE TYPE chat_types AS ENUM('chat', 'task');

ALTER TABLE chats ADD COLUMN type chat_types NOT NULL DEFAULT 'chat';

CREATE INDEX chats_type ON chats(type);

ALTER TABLE chat_messages ADD COLUMN is_task_description BOOLEAN NOT NULL DEFAULT false;

CREATE TYPE task_statuses AS ENUM('completed', 'not_completed');
CREATE TYPE task_types AS ENUM('normal', 'test');

CREATE TABLE tasks(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    assigned_user_chat_id UUID REFERENCES chats ON DELETE SET NULL,
    assigned_user_id UUID REFERENCES users ON DELETE SET NULL,
    chat_id UUID NOT NULL REFERENCES chats ON DELETE CASCADE,
    existing_task_id UUID REFERENCES tasks ON DELETE SET NULL,
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    workspace_id UUID NOT NULL REFERENCES workspaces ON DELETE CASCADE,
    description TEXT,
    status task_statuses NOT NULL DEFAULT 'not_completed',
    title TEXT,
    type task_types NOT NULL DEFAULT 'normal',
    use_task_book_generation BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX tasks_assigned_user_chat_id ON tasks(assigned_user_chat_id);
CREATE INDEX tasks_assigned_user_id ON tasks(assigned_user_id);
CREATE INDEX tasks_chat_id ON tasks(chat_id);
CREATE INDEX tasks_existing_task_id ON tasks(existing_task_id);
CREATE INDEX tasks_user_id ON tasks(user_id);
CREATE INDEX tasks_workspace_id ON tasks(workspace_id);
CREATE INDEX tasks_status ON tasks(status);
CREATE INDEX tasks_type ON tasks(type);
CREATE INDEX tasks_created_at ON tasks(created_at);
CREATE INDEX tasks_deleted_at ON tasks(deleted_at);

CREATE TABLE task_tests(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id UUID NOT NULL REFERENCES tasks ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    answer TEXT,
    question TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX task_tests_task_id ON task_tests(task_id);
CREATE INDEX task_tests_user_id ON task_tests(user_id);
CREATE INDEX task_tests_created_at ON task_tests(created_at);
CREATE INDEX task_tests_deleted_at ON task_tests(deleted_at);
