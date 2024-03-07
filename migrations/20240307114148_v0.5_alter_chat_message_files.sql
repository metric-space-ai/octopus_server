-- Add migration script here

ALTER TABLE chat_message_files ADD COLUMN original_file_name VARCHAR(256);
