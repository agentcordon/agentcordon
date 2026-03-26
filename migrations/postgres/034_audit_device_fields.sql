-- Add device attribution fields to audit_events
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS device_id UUID;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS device_name TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_device_id ON audit_events(device_id);
