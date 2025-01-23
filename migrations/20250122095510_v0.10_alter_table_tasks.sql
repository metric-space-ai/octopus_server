-- Add migration script here

ALTER TABLE tasks ADD COLUMN test_result TEXT;

ALTER TABLE task_tests ADD COLUMN answer_is_correct BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX task_tests_answer_is_correct ON task_tests(answer_is_correct);
