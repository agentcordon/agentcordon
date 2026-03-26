-- AgentCordon schema: PostgreSQL initial migration
-- All tables, indexes, and constraints for a fresh database.

-- ============================================================
-- Schema Migrations (tracking table)
-- ============================================================
CREATE TABLE IF NOT EXISTS schema_migrations (
    version BIGINT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL
);

-- ============================================================
-- Users
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    is_root BOOLEAN NOT NULL DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- ============================================================
-- Agents
-- ============================================================
CREATE TABLE IF NOT EXISTS agents (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    tags JSONB NOT NULL DEFAULT '[]',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    owner_id UUID REFERENCES users(id),
    last_token_issued_at TIMESTAMPTZ,
    last_token_expires_at TIMESTAMPTZ,
    api_key_prefix TEXT
);

CREATE INDEX IF NOT EXISTS idx_agents_owner_id ON agents(owner_id);

CREATE TABLE IF NOT EXISTS agent_api_keys (
    agent_id UUID PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    key_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

-- ============================================================
-- Sessions
-- ============================================================
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- ============================================================
-- Credentials
-- ============================================================
CREATE TABLE IF NOT EXISTS credentials (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    service TEXT NOT NULL,
    encrypted_value BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    scopes JSONB NOT NULL DEFAULT '[]',
    metadata JSONB NOT NULL DEFAULT '{}',
    created_by UUID REFERENCES agents(id),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    allowed_url_pattern TEXT,
    created_by_user UUID REFERENCES users(id),
    expires_at TIMESTAMPTZ,
    transform_script TEXT,
    transform_name TEXT,
    vault TEXT NOT NULL DEFAULT 'default',
    credential_type TEXT NOT NULL DEFAULT 'generic',
    tags JSONB NOT NULL DEFAULT '[]',
    key_version INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_credentials_service ON credentials(service);
CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_name_unique ON credentials(name);

-- ============================================================
-- Credential Permissions
-- ============================================================
CREATE TABLE IF NOT EXISTS credential_permissions (
    credential_id UUID NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    granted_by UUID REFERENCES agents(id),
    granted_by_user UUID REFERENCES users(id),
    granted_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (credential_id, agent_id, permission)
);

CREATE INDEX IF NOT EXISTS idx_cred_perms_cred ON credential_permissions(credential_id);
CREATE INDEX IF NOT EXISTS idx_cred_perms_agent ON credential_permissions(agent_id);

-- ============================================================
-- Credential Secret History
-- ============================================================
CREATE TABLE IF NOT EXISTS credential_secret_history (
    id UUID PRIMARY KEY,
    credential_id UUID NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    encrypted_value BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL,
    changed_by_user TEXT,
    changed_by_agent TEXT,
    key_version INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_secret_history_credential ON credential_secret_history(credential_id);

-- ============================================================
-- Policies
-- ============================================================
CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    cedar_policy TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

-- ============================================================
-- Audit Events
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    correlation_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    agent_id UUID,
    agent_name TEXT,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    decision TEXT NOT NULL,
    decision_reason TEXT,
    metadata JSONB NOT NULL DEFAULT '{}',
    user_id TEXT,
    user_name TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_correlation ON audit_events(correlation_id);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_events(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_events(user_id);

-- ============================================================
-- Grants
-- ============================================================
CREATE TABLE IF NOT EXISTS grants (
    id UUID PRIMARY KEY,
    agent_id UUID NOT NULL,
    credential_id UUID NOT NULL,
    scopes JSONB NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    redeemed BOOLEAN NOT NULL DEFAULT FALSE,
    redeemed_at TIMESTAMPTZ,
    FOREIGN KEY (agent_id) REFERENCES agents(id),
    FOREIGN KEY (credential_id) REFERENCES credentials(id)
);

CREATE INDEX IF NOT EXISTS idx_grants_agent ON grants(agent_id);
CREATE INDEX IF NOT EXISTS idx_grants_credential ON grants(credential_id);

-- ============================================================
-- Enrollment Sessions (device flow)
-- ============================================================
CREATE TABLE IF NOT EXISTS enrollment_sessions (
    id UUID PRIMARY KEY,
    session_token_hash TEXT NOT NULL,
    approval_ref TEXT NOT NULL UNIQUE,
    approval_code TEXT NOT NULL,
    agent_name TEXT NOT NULL,
    agent_description TEXT,
    agent_tags JSONB NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    claimed_at TIMESTAMPTZ,
    client_ip TEXT,
    api_key_hash TEXT,
    claim_attempts INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_enrollment_session_ref ON enrollment_sessions(approval_ref);
CREATE INDEX IF NOT EXISTS idx_enrollment_session_status ON enrollment_sessions(status);
CREATE INDEX IF NOT EXISTS idx_enrollment_session_token_hash ON enrollment_sessions(session_token_hash);

-- ============================================================
-- Vault Shares
-- ============================================================
CREATE TABLE IF NOT EXISTS vault_shares (
    id TEXT PRIMARY KEY,
    vault_name TEXT NOT NULL,
    shared_with_user_id UUID NOT NULL,
    permission_level TEXT NOT NULL DEFAULT 'read',
    shared_by_user_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE(vault_name, shared_with_user_id)
);

-- ============================================================
-- MCP Servers
-- ============================================================
CREATE TABLE IF NOT EXISTS mcp_servers (
    id UUID PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    upstream_url TEXT NOT NULL,
    transport TEXT NOT NULL DEFAULT 'http',
    credential_bindings JSONB NOT NULL DEFAULT '[]',
    allowed_tools JSONB,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

-- ============================================================
-- OIDC Providers
-- ============================================================
CREATE TABLE IF NOT EXISTS oidc_providers (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    issuer_url TEXT NOT NULL,
    client_id TEXT NOT NULL,
    encrypted_client_secret BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    scopes JSONB NOT NULL DEFAULT '["openid","profile","email"]',
    role_mapping JSONB NOT NULL DEFAULT '{}',
    auto_provision BOOLEAN NOT NULL DEFAULT TRUE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    username_claim TEXT NOT NULL DEFAULT 'preferred_username',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_auth_states (
    state TEXT PRIMARY KEY,
    nonce TEXT NOT NULL,
    provider_id UUID NOT NULL,
    redirect_uri TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oidc_auth_states_expires_at ON oidc_auth_states(expires_at);

-- ============================================================
-- Servers (OAuth Clients)
-- ============================================================
CREATE TABLE IF NOT EXISTS servers (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL UNIQUE,
    client_secret_hash TEXT NOT NULL,
    expected_audience TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    tags JSONB NOT NULL DEFAULT '[]',
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_servers_client_id ON servers(client_id);

-- ============================================================
-- OAuth Authorization Codes
-- ============================================================
CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL DEFAULT 'S256',
    scopes JSONB NOT NULL DEFAULT '[]',
    state TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_oauth_codes_client_id ON oauth_authorization_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_codes_expires ON oauth_authorization_codes(expires_at);

-- ============================================================
-- Sidecars
-- ============================================================
CREATE TABLE IF NOT EXISTS sidecars (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    public_key_jwk JSONB,
    status TEXT NOT NULL DEFAULT 'pending',
    enrollment_token_hash TEXT,
    tags JSONB NOT NULL DEFAULT '[]',
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_authenticated_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS sidecar_used_jtis (
    jti TEXT PRIMARY KEY,
    sidecar_id UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sidecar_jtis_expires ON sidecar_used_jtis(expires_at);
