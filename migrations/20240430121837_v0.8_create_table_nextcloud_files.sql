-- Add migration script here

CREATE TABLE nextcloud_files(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_name VARCHAR(256) NOT NULL,
    media_type VARCHAR(256) NOT NULL,
    original_file_name VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX nextcloud_files_file_name ON nextcloud_files(file_name);
CREATE INDEX nextcloud_files_original_file_name ON nextcloud_files(original_file_name);
CREATE INDEX nextcloud_files_created_at ON nextcloud_files(created_at);
CREATE INDEX nextcloud_files_updated_at ON nextcloud_files(updated_at);
