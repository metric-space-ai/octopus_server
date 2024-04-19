-- Add migration script here

ALTER TABLE wasp_generators RENAME COLUMN wasp_app_id TO wasp_app_id2;
ALTER TABLE wasp_generators ADD COLUMN wasp_app_id UUID REFERENCES wasp_apps ON DELETE SET NULL;
UPDATE wasp_generators SET wasp_app_id = wasp_app_id2;
ALTER TABLE wasp_generators DROP COLUMN wasp_app_id2;
