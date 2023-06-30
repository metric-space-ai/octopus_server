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
    roles VARCHAR(256) [] NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    UNIQUE(email)
);
