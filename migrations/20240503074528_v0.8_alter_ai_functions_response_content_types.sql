-- Add migration script here

ALTER TYPE ai_functions_response_content_types ADD VALUE IF NOT EXISTS 'audio_aac' AFTER 'application_pdf';
