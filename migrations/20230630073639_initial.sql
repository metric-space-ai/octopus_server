-- Add migration script here
CREATE TABLE companies(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    address VARCHAR(256),
    name VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX companies_deleted_at ON companies(deleted_at);

CREATE TABLE users(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies ON DELETE CASCADE,
    email VARCHAR(256) NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    pepper_id INT NOT NULL,
    password VARCHAR(256) NOT NULL,
    roles VARCHAR(1024) [] NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    UNIQUE(email)
);

CREATE INDEX users_company_id ON users(company_id);
CREATE INDEX users_deleted_at ON users(deleted_at);

CREATE TABLE profiles(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    job_title VARCHAR(256),
    language VARCHAR(5) NOT NULL DEFAULT 'en_GB',
    name VARCHAR(256),
    photo_file_name VARCHAR(256),
    text_size INT NOT NULL DEFAULT 16,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    UNIQUE(user_id)
);

CREATE INDEX profiles_deleted_at ON profiles(deleted_at);

CREATE TABLE sessions(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    data TEXT NOT NULL,
    expired_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX sessions_user_id ON sessions(user_id);

CREATE TYPE ai_functions_health_check_statuses AS ENUM('not_working', 'ok');
CREATE TYPE ai_functions_setup_statuses AS ENUM('not_performed', 'performed');
CREATE TYPE ai_functions_warmup_statuses AS ENUM('not_performed', 'performed');

CREATE TABLE ai_functions(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    base_function_url VARCHAR(256) NOT NULL,
    description TEXT NOT NULL,
    device_map JSON NOT NULL,
    health_check_execution_time INT NOT NULL DEFAULT 0,
    health_check_status ai_functions_health_check_statuses NOT NULL DEFAULT 'not_working',
    health_check_url VARCHAR(256) NOT NULL,
    is_available BOOLEAN NOT NULL DEFAULT false,
    is_enabled BOOLEAN NOT NULL DEFAULT false,
    k8s_configuration TEXT,
    name VARCHAR(256) NOT NULL,
    parameters JSON NOT NULL,
    setup_execution_time INT NOT NULL DEFAULT 0,
    setup_status ai_functions_setup_statuses NOT NULL DEFAULT 'not_performed',
    setup_url VARCHAR(256) NOT NULL,
    warmup_execution_time INT NOT NULL DEFAULT 0,
    warmup_status ai_functions_warmup_statuses NOT NULL DEFAULT 'not_performed',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    health_check_at TIMESTAMP WITH TIME ZONE,
    setup_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    warmup_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(name)
);

CREATE INDEX ai_functions_deleted_at ON ai_functions(deleted_at);
CREATE INDEX ai_functions_health_check_status ON ai_functions(health_check_status);
CREATE INDEX ai_functions_is_available ON ai_functions(is_available);
CREATE INDEX ai_functions_is_enabled ON ai_functions(is_enabled);
CREATE INDEX ai_functions_setup_status ON ai_functions(setup_status);
CREATE INDEX ai_functions_warmup_status ON ai_functions(warmup_status);

CREATE TYPE workspaces_types AS ENUM('private', 'public');

CREATE TABLE workspaces(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    name VARCHAR(256) NOT NULL,
    type workspaces_types NOT NULL DEFAULT 'public',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX workspaces_company_id ON workspaces(company_id);
CREATE INDEX workspaces_type ON workspaces(type);
CREATE INDEX workspaces_deleted_at ON workspaces(deleted_at);

CREATE TABLE chats(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    workspace_id UUID NOT NULL REFERENCES workspaces ON DELETE CASCADE,
    name TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX chats_user_id ON chats(user_id);
CREATE INDEX chats_workspace_id ON chats(workspace_id);
CREATE INDEX chats_deleted_at ON chats(deleted_at);

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
    ai_function_id UUID REFERENCES ai_functions ON DELETE CASCADE,
    chat_id UUID NOT NULL REFERENCES chats ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    bad_reply_comment TEXT,
    bad_reply_is_harmful BOOLEAN NOT NULL DEFAULT false,
    bad_reply_is_not_helpful BOOLEAN NOT NULL DEFAULT false,
    bad_reply_is_not_true BOOLEAN NOT NULL DEFAULT false,
    estimated_response_at TIMESTAMP WITH TIME ZONE NOT NULL,
    message TEXT NOT NULL,
    progress INT NOT NULL DEFAULT 0,
    response TEXT,
    status chat_message_statuses NOT NULL DEFAULT 'asked',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX chat_messages_chat_id ON chat_messages(chat_id);
CREATE INDEX chat_messages_user_id ON chat_messages(user_id);
CREATE INDEX chat_messages_ai_function_id ON chat_messages(ai_function_id);
CREATE INDEX chat_messages_status ON chat_messages(status);
CREATE INDEX chat_messages_created_at ON chat_messages(created_at);
CREATE INDEX chat_messages_deleted_at ON chat_messages(deleted_at);
CREATE INDEX chat_messages_updated_at ON chat_messages(updated_at);

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

CREATE TABLE chat_message_files(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chat_message_id UUID NOT NULL REFERENCES chat_messages ON DELETE CASCADE,
    file_name VARCHAR(256) NOT NULL,
    media_type VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX chat_message_files_chat_message_id ON chat_message_files(chat_message_id);
CREATE INDEX chat_message_files_created_at ON chat_message_files(created_at);
CREATE INDEX chat_message_files_deleted_at ON chat_message_files(deleted_at);

CREATE TABLE chat_message_pictures(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chat_message_id UUID NOT NULL REFERENCES chat_messages ON DELETE CASCADE,
    file_name VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX chat_message_pictures_chat_message_id ON chat_message_pictures(chat_message_id);
CREATE INDEX chat_message_pictures_created_at ON chat_message_pictures(created_at);
CREATE INDEX chat_message_pictures_deleted_at ON chat_message_pictures(deleted_at);

CREATE TABLE chat_pictures(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chat_id UUID NOT NULL REFERENCES chats ON DELETE CASCADE,
    file_name VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    UNIQUE(chat_id)
);

CREATE INDEX chat_pictures_chat_id ON chat_pictures(chat_id);
CREATE INDEX chat_pictures_deleted_at ON chat_pictures(deleted_at);

CREATE TABLE example_prompt_categories(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    description TEXT NOT NULL,
    is_visible BOOLEAN NOT NULL DEFAULT true,
    title VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX example_prompt_categories_deleted_at ON example_prompt_categories(deleted_at);

CREATE TABLE example_prompts(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    example_prompt_category_id UUID NOT NULL REFERENCES example_prompt_categories ON DELETE CASCADE,
    background_file_name VARCHAR(256),
    is_visible BOOLEAN NOT NULL DEFAULT true,
    priority INT NOT NULL DEFAULT 0,
    prompt TEXT NOT NULL,
    title VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX example_prompts_deleted_at ON example_prompts(deleted_at);

CREATE TABLE password_reset_tokens(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    email VARCHAR(256) NOT NULL,
    token VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT (current_timestamp(0) + interval '1 day'),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    UNIQUE(token)
);

CREATE INDEX password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX password_reset_tokens_deleted_at ON password_reset_tokens(deleted_at);
