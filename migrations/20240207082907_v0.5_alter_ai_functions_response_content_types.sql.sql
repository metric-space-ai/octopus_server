-- Add migration script here

ALTER TYPE ai_functions_response_content_types ADD VALUE IF NOT EXISTS 'application_pdf' AFTER 'application_json';
ALTER TYPE ai_functions_response_content_types ADD VALUE IF NOT EXISTS 'audio_mpeg' AFTER 'application_pdf';
ALTER TYPE ai_functions_response_content_types ADD VALUE IF NOT EXISTS 'video_mp4';
