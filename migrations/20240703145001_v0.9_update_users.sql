-- Add migration script here

UPDATE users SET email = LOWER(email);
