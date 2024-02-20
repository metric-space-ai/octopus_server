-- Add migration script here

CREATE TYPE wasp_apps_instance_types AS ENUM('private', 'shared');

ALTER TABLE wasp_apps ADD COLUMN instance_type wasp_apps_instance_types NOT NULL DEFAULT 'shared';

