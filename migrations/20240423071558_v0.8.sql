-- Add migration script here

CREATE TYPE ollama_models_statuses AS ENUM('initial', 'pulled');

CREATE TABLE ollama_models(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(256) NOT NULL,
    o_name VARCHAR(256),
    o_details_family VARCHAR(256),
    o_details_families VARCHAR(256) [],
    o_details_format VARCHAR(256),
    o_details_parameter_size VARCHAR(256),
    o_details_parent_model VARCHAR(256),
    o_details_quantization_level VARCHAR(256),
    o_digest VARCHAR(256),
    o_model VARCHAR(256),
    o_modified_at VARCHAR(256),
    o_size VARCHAR(256),
    status ollama_models_statuses NOT NULL DEFAULT 'initial',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX ollama_models_deleted_at ON ollama_models(deleted_at);
CREATE INDEX ollama_models_name ON ollama_models(name);

CREATE TABLE cached_files(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cache_key VARCHAR(256) NOT NULL,
    file_name VARCHAR(256) NOT NULL,
    media_type VARCHAR(256) NOT NULL,
    original_file_name VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    expires_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    UNIQUE(cache_key)
);

CREATE INDEX cached_files_expires_at ON cached_files(expires_at);
