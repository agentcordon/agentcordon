-- Add is_system flag to policies table.
-- System policies (default, demo) are managed by the server and should not be deleted by users.
ALTER TABLE policies ADD COLUMN is_system BOOLEAN NOT NULL DEFAULT false;
