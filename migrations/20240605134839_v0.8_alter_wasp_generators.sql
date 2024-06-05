-- Add migration script here

DROP INDEX wasp_generators_user_id;

ALTER TABLE wasp_generators RENAME COLUMN user_id TO user_id2;
ALTER TABLE wasp_generators ADD COLUMN user_id UUID NOT NULL REFERENCES users ON DELETE SET NULL;
UPDATE wasp_generators SET user_id = user_id2;
ALTER TABLE wasp_generators DROP COLUMN user_id2;

CREATE INDEX wasp_generators_user_id ON wasp_generators(user_id);
