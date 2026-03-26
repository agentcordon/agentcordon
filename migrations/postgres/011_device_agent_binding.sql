-- Migration 011: Device-Agent Binding
-- Adds device_id to agents (FK to devices) for enrollment trust binding.
-- Adds owner_id to devices (FK to users) for device ownership.
-- Adds device_id to enrollment_sessions (FK to devices) for session tracking.

ALTER TABLE agents ADD COLUMN device_id UUID REFERENCES devices(id);

ALTER TABLE devices ADD COLUMN owner_id UUID REFERENCES users(id);

ALTER TABLE enrollment_sessions ADD COLUMN device_id UUID REFERENCES devices(id);
