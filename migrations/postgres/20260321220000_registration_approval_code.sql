-- Add approval_code column to workspace_registrations (nullable, one-time use)
ALTER TABLE workspace_registrations ADD COLUMN approval_code TEXT;
