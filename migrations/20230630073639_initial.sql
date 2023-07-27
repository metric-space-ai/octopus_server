-- Add migration script here
CREATE TABLE companies(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    address VARCHAR(256),
    name VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE TABLE users(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies ON DELETE CASCADE,
    email VARCHAR(256) NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    pepper_id INT NOT NULL,
    password VARCHAR(256) NOT NULL,
    roles VARCHAR(1024) [] NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    UNIQUE(email)
);

CREATE INDEX users_company_id ON users(company_id);

CREATE TABLE profiles(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    job_title VARCHAR(256),
    language VARCHAR(5) NOT NULL DEFAULT 'en_GB',
    name VARCHAR(256),
    photo_file_name VARCHAR(256),
    text_size INT NOT NULL DEFAULT 16,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    UNIQUE(user_id)
);

CREATE TABLE sessions(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    data TEXT NOT NULL,
    expired_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX sessions_user_id ON sessions(user_id);

CREATE TYPE workspaces_types AS ENUM('private', 'public');

CREATE TABLE workspaces(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    name VARCHAR(256) NOT NULL,
    type workspaces_types NOT NULL DEFAULT 'public',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX workspaces_company_id ON workspaces(company_id);
CREATE INDEX workspaces_type ON workspaces(type);

CREATE TABLE chats(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    workspace_id UUID NOT NULL REFERENCES workspaces ON DELETE CASCADE,
    name TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX chats_user_id ON chats(user_id);
CREATE INDEX chats_workspace_id ON chats(workspace_id);

CREATE TABLE chat_activities(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chat_id UUID NOT NULL REFERENCES chats ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES sessions ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    UNIQUE(chat_id, session_id, user_id)
);

CREATE INDEX chat_activities_updated_at ON chat_activities(updated_at);

CREATE TYPE chat_message_statuses AS ENUM('answered', 'asked');

CREATE TABLE chat_messages(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chat_id UUID NOT NULL REFERENCES chats ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    estimated_response_at TIMESTAMP WITH TIME ZONE NOT NULL,
    message TEXT NOT NULL,
    response TEXT,
    status chat_message_statuses NOT NULL DEFAULT 'asked',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX chat_messages_chat_id ON chat_messages(chat_id);
CREATE INDEX chat_messages_user_id ON chat_messages(user_id);
CREATE INDEX chat_messages_status ON chat_messages(status);
CREATE INDEX chat_messages_created_at ON chat_messages(created_at);
CREATE INDEX chat_messages_updated_at ON chat_messages(updated_at);

CREATE TABLE chat_message_files(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chat_message_id UUID NOT NULL REFERENCES chat_messages ON DELETE CASCADE,
    file_name VARCHAR(256) NOT NULL,
    media_type VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX chat_message_files_chat_message_id ON chat_message_files(chat_message_id);
CREATE INDEX chat_message_files_created_at ON chat_message_files(created_at);

CREATE TABLE chat_message_pictures(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chat_message_id UUID NOT NULL REFERENCES chat_messages ON DELETE CASCADE,
    file_name VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX chat_message_pictures_chat_message_id ON chat_message_pictures(chat_message_id);
CREATE INDEX chat_message_pictures_created_at ON chat_message_pictures(created_at);

CREATE TABLE chat_pictures(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chat_id UUID NOT NULL REFERENCES chats ON DELETE CASCADE,
    file_name VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    UNIQUE(chat_id)
);

CREATE INDEX chat_pictures_chat_id ON chat_pictures(chat_id);

CREATE TABLE example_prompts(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    is_visible BOOLEAN NOT NULL DEFAULT true,
    priority INT NOT NULL DEFAULT 0,
    prompt TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);
