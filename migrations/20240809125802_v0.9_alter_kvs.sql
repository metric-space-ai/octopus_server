-- Add migration script here

DELETE FROM kvs;

CREATE TYPE kvs_access_types AS ENUM('company', 'owner');

ALTER TABLE kvs ADD COLUMN company_id UUID NOT NULL REFERENCES companies ON DELETE CASCADE;
ALTER TABLE kvs ADD COLUMN access_type kvs_access_types NOT NULL DEFAULT 'owner';

CREATE INDEX kvs_company_id ON kvs(company_id);
CREATE INDEX kvs_access_type ON kvs(access_type);
