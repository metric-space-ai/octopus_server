-- Add migration script here

CREATE TYPE files_access_types AS ENUM('company', 'owner');
CREATE TYPE files_types AS ENUM('document', 'knowledge_book', 'normal', 'task_book');

ALTER TABLE files ADD COLUMN company_id UUID NOT NULL REFERENCES companies ON DELETE CASCADE;
ALTER TABLE files ADD COLUMN access_type files_access_types NOT NULL DEFAULT 'owner';
ALTER TABLE files ADD COLUMN type files_types NOT NULL DEFAULT 'normal';

CREATE INDEX files_company_id ON files(company_id);
CREATE INDEX files_access_type ON files(access_type);
CREATE INDEX files_type ON files(type);
