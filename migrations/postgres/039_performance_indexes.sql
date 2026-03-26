-- Performance indexes for known slow queries.
CREATE INDEX IF NOT EXISTS idx_audit_events_device_id ON audit_events(device_id);
CREATE INDEX IF NOT EXISTS idx_credentials_vault ON credentials(vault);
CREATE INDEX IF NOT EXISTS idx_credentials_created_by ON credentials(created_by_user);
CREATE INDEX IF NOT EXISTS idx_credential_permissions_agent_id ON credential_permissions(agent_id);
CREATE INDEX IF NOT EXISTS idx_agents_device_id ON agents(device_id);
CREATE INDEX IF NOT EXISTS idx_enrollment_sessions_status ON enrollment_sessions(status);
