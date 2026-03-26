-- Track which admin user approved a workspace registration
ALTER TABLE workspace_registrations ADD COLUMN approved_by TEXT;
