-- Add migration script here

CREATE TABLE llm_router_configs(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies ON DELETE SET NULL,
    user_id UUID REFERENCES users ON DELETE SET NULL,
    complexity INT NOT NULL,
    suggested_llm VARCHAR(256) NOT NULL,
    suggested_model VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0),
    deleted_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp(0)
);

CREATE INDEX llm_router_configs_company_id ON llm_router_configs(company_id);
CREATE INDEX llm_router_configs_user_id ON llm_router_configs(user_id);
CREATE INDEX llm_router_configs_complexity ON llm_router_configs(complexity);
CREATE INDEX llm_router_configs_created_at ON llm_router_configs(created_at);
CREATE INDEX llm_router_configs_deleted_at ON llm_router_configs(deleted_at);

UPDATE parameters SET name = 'MAIN_LLM_ANTHROPIC_PRIMARY_MODEL' WHERE name = 'MAIN_LLM_ANTHROPIC_MODEL';
UPDATE parameters SET name = 'MAIN_LLM_OLLAMA_PRIMARY_MODEL' WHERE name = 'MAIN_LLM_OLLAMA_MODEL';
