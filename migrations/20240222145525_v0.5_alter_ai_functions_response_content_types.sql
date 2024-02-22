-- Add migration script here

ALTER TYPE ai_functions_response_content_types ADD VALUE IF NOT EXISTS 'text_html' AFTER 'image_png';
