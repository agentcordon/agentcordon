-- AgentCordon v1 baseline schema
-- This is the canonical schema as of v1.15.0.
-- All future migrations build on this baseline.
-- Previous incremental development migrations were collapsed into this file.

-- ============================================================
-- Users
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    is_root INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    show_advanced BOOLEAN NOT NULL DEFAULT false,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- ============================================================
-- Devices
-- ============================================================
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    public_key_jwk TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    enrollment_token_hash TEXT,
    tags TEXT NOT NULL DEFAULT '[]',
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_authenticated_at TEXT,
    owner_id TEXT REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS device_used_jtis (
    jti TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_jtis_expires ON device_used_jtis(expires_at);

-- ============================================================
-- Agents
-- ============================================================
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    tags TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    owner_id TEXT REFERENCES users(id),
    device_id TEXT REFERENCES devices(id),
    last_token_issued_at TEXT,
    last_token_expires_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_agents_owner_id ON agents(owner_id);
CREATE INDEX IF NOT EXISTS idx_agents_device_id ON agents(device_id);

-- ============================================================
-- Sessions
-- ============================================================
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- ============================================================
-- Credentials
-- ============================================================
CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    service TEXT NOT NULL,
    encrypted_value BLOB NOT NULL,
    nonce BLOB NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]',
    metadata TEXT NOT NULL DEFAULT '{}',
    created_by TEXT REFERENCES agents(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    allowed_url_pattern TEXT,
    created_by_user TEXT REFERENCES users(id),
    expires_at TEXT,
    transform_script TEXT,
    transform_name TEXT,
    vault TEXT NOT NULL DEFAULT 'default',
    credential_type TEXT NOT NULL DEFAULT 'generic',
    tags TEXT NOT NULL DEFAULT '[]',
    key_version INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_credentials_service ON credentials(service);
CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_name_unique ON credentials(name);
CREATE INDEX IF NOT EXISTS idx_credentials_vault ON credentials(vault);
CREATE INDEX IF NOT EXISTS idx_credentials_created_by ON credentials(created_by_user);

-- ============================================================
-- Credential Secret History
-- ============================================================
CREATE TABLE IF NOT EXISTS credential_secret_history (
    id TEXT PRIMARY KEY,
    credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    encrypted_value BLOB NOT NULL,
    nonce BLOB NOT NULL,
    changed_at TEXT NOT NULL,
    changed_by_user TEXT,
    changed_by_agent TEXT,
    key_version INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_secret_history_credential ON credential_secret_history(credential_id);

-- ============================================================
-- Policies
-- ============================================================
CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    cedar_policy TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    is_system BOOLEAN NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- ============================================================
-- Audit Events
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    agent_id TEXT,
    agent_name TEXT,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    decision TEXT NOT NULL,
    decision_reason TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    user_id TEXT,
    user_name TEXT,
    device_id TEXT,
    device_name TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_correlation ON audit_events(correlation_id);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_events(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_events(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_device_id ON audit_events(device_id);

-- ============================================================
-- Enrollment Sessions (device flow)
-- ============================================================
CREATE TABLE IF NOT EXISTS enrollment_sessions (
    id TEXT PRIMARY KEY,
    session_token_hash TEXT NOT NULL,
    approval_ref TEXT NOT NULL UNIQUE,
    approval_code TEXT NOT NULL,
    agent_name TEXT NOT NULL,
    agent_description TEXT,
    agent_tags TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    approved_by TEXT,
    approved_at TEXT,
    claimed_at TEXT,
    client_ip TEXT,
    claim_attempts INTEGER NOT NULL DEFAULT 0,
    device_id TEXT REFERENCES devices(id)
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
    shared_with_user_id TEXT NOT NULL,
    permission_level TEXT NOT NULL DEFAULT 'read',
    shared_by_user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(vault_name, shared_with_user_id)
);

-- ============================================================
-- MCP Servers
-- ============================================================
CREATE TABLE IF NOT EXISTS mcp_servers (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    upstream_url TEXT NOT NULL,
    transport TEXT NOT NULL DEFAULT 'http',
    credential_bindings TEXT NOT NULL DEFAULT '[]',
    allowed_tools TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_by TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    catalog_slug TEXT,
    deployment_mode TEXT,
    tags TEXT NOT NULL DEFAULT '[]',
    command TEXT,
    args TEXT,
    env TEXT,
    required_credentials TEXT,
    UNIQUE(device_id, name)
);

CREATE INDEX IF NOT EXISTS idx_mcp_servers_device_id ON mcp_servers(device_id);

-- ============================================================
-- OIDC Providers
-- ============================================================
CREATE TABLE IF NOT EXISTS oidc_providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    issuer_url TEXT NOT NULL,
    client_id TEXT NOT NULL,
    encrypted_client_secret BLOB NOT NULL,
    nonce BLOB NOT NULL,
    scopes TEXT NOT NULL DEFAULT '["openid","profile","email"]',
    role_mapping TEXT NOT NULL DEFAULT '{}',
    auto_provision INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 1,
    username_claim TEXT NOT NULL DEFAULT 'preferred_username',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_auth_states (
    state TEXT PRIMARY KEY,
    nonce TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oidc_auth_states_expires_at ON oidc_auth_states(expires_at);

-- ============================================================
-- Servers (OAuth Clients)
-- ============================================================
CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL UNIQUE,
    client_secret_hash TEXT NOT NULL,
    expected_audience TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    tags TEXT NOT NULL DEFAULT '[]',
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
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
    scopes TEXT NOT NULL DEFAULT '[]',
    state TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_oauth_codes_client_id ON oauth_authorization_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_codes_expires ON oauth_authorization_codes(expires_at);

-- ============================================================
-- Workspace Identities
-- ============================================================
CREATE TABLE IF NOT EXISTS workspace_identities (
    id TEXT PRIMARY KEY,
    pk_hash TEXT NOT NULL UNIQUE,
    name TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS workspace_registrations (
    pk_hash TEXT PRIMARY KEY,
    code_challenge TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    created_at TEXT NOT NULL
);

-- ============================================================
-- Crypto State (nonce collision tracking)
-- ============================================================
CREATE TABLE IF NOT EXISTS crypto_state (
    key_id TEXT PRIMARY KEY,
    encryption_count INTEGER NOT NULL DEFAULT 0,
    last_updated TEXT NOT NULL
);
