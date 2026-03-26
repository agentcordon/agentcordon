-- Add show_advanced column to users table for progressive disclosure.
-- Default to false (beginner/simplified mode) for new users.
ALTER TABLE users ADD COLUMN show_advanced BOOLEAN NOT NULL DEFAULT false;
