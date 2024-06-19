-- Add migration script here

CREATE TABLE files(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    file_name VARCHAR(256) NOT NULL,
    media_type VARCHAR(256) NOT NULL,
    original_file_name VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX files_user_id ON files(user_id);
CREATE INDEX files_file_name ON files(file_name);
CREATE INDEX files_original_file_name ON files(original_file_name);
CREATE INDEX files_created_at ON files(created_at);
CREATE INDEX files_updated_at ON files(updated_at);
