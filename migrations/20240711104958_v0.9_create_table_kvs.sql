-- Add migration script here

CREATE TABLE kvs(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    kv_key TEXT NOT NULL,
    kv_value TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    expires_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    UNIQUE(kv_key)
);

CREATE INDEX kvs_user_id ON kvs(user_id);
CREATE INDEX kvs_created_at ON kvs(created_at);
CREATE INDEX kvs_expires_at ON kvs(expires_at);
CREATE INDEX kvs_updated_at ON kvs(updated_at);
