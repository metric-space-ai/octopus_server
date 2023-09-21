-- Add migration script here

CREATE TABLE inspection_disablings(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    content_safety_disabled_until TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    UNIQUE(user_id)
);

CREATE INDEX inspection_disablings_content_safety_disabled_until ON inspection_disablings(content_safety_disabled_until);
