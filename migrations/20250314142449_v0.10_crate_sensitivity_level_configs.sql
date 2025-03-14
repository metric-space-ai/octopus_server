-- Add migration script here

CREATE TABLE sensitivity_level_configs(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies ON DELETE SET NULL,
    user_id UUID REFERENCES users ON DELETE SET NULL,
    level INT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX sensitivity_level_configs_company_id ON sensitivity_level_configs(company_id);
CREATE INDEX sensitivity_level_configs_user_id ON sensitivity_level_configs(user_id);
CREATE INDEX sensitivity_level_configs_level ON sensitivity_level_configs(level);
CREATE INDEX sensitivity_level_configs_created_at ON sensitivity_level_configs(created_at);
CREATE INDEX sensitivity_level_configs_deleted_at ON sensitivity_level_configs(deleted_at);
