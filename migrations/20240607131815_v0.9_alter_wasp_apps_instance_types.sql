-- Add migration script here

ALTER TYPE wasp_apps_instance_types ADD VALUE IF NOT EXISTS 'user' AFTER 'shared';
