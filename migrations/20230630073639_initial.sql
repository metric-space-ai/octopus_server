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

CREATE TABLE sessions(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    data TEXT NOT NULL,
    expired_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE chats(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    name TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE TYPE chat_message_statuses AS ENUM('answered', 'asked');

CREATE TABLE chat_messages(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chat_id UUID NOT NULL REFERENCES chats ON DELETE CASCADE,
    estimated_response_at TIMESTAMP WITH TIME ZONE NOT NULL,
    message TEXT NOT NULL,
    response TEXT,
    status chat_message_statuses NOT NULL DEFAULT 'asked',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE TABLE chat_message_files(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chat_message_id UUID NOT NULL REFERENCES chat_messages ON DELETE CASCADE,
    file_name VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE TABLE chat_pictures(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chat_id UUID NOT NULL REFERENCES chats ON DELETE CASCADE,
    file_name VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    UNIQUE(chat_id)
);

CREATE TABLE example_prompts(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    is_visible BOOLEAN NOT NULL DEFAULT true,
    priority INT NOT NULL DEFAULT 0,
    prompt TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);
