-- AgentCordon baseline schema (squashed)
-- All migrations consolidated into a single canonical schema.

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
-- Workspaces (unified: agent + device + workspace identity)
-- ============================================================
CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'pending',   -- pending | active | revoked
    pk_hash TEXT UNIQUE,                       -- Ed25519 public key hash
    encryption_public_key TEXT,                -- P-256 JWK for ECIES credential vending
    tags TEXT NOT NULL DEFAULT '[]',           -- JSON array
    owner_id TEXT REFERENCES users(id),
    parent_id TEXT REFERENCES workspaces(id) CHECK(parent_id != id),
    tool_name TEXT,                            -- informational: claude-code, cursor, etc.
    enrollment_token_hash TEXT,
    last_authenticated_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_workspaces_owner_id ON workspaces(owner_id);
CREATE INDEX IF NOT EXISTS idx_workspaces_parent_id ON workspaces(parent_id);
CREATE INDEX IF NOT EXISTS idx_workspaces_status ON workspaces(status);
CREATE INDEX IF NOT EXISTS idx_workspaces_pk_hash ON workspaces(pk_hash);

-- ============================================================
-- Workspace JTI Replay Protection
-- ============================================================
CREATE TABLE IF NOT EXISTS workspace_used_jtis (
    jti TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_workspace_jtis_expires ON workspace_used_jtis(expires_at);

-- ============================================================
-- Workspace Registrations (PKCE enrollment flow)
-- ============================================================
CREATE TABLE IF NOT EXISTS workspace_registrations (
    pk_hash TEXT PRIMARY KEY,
    code_challenge TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    approval_code TEXT,
    expires_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    approved_by TEXT,
    created_at TEXT NOT NULL
);

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
    created_by TEXT REFERENCES workspaces(id),
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
    key_version INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    target_identity TEXT
);

CREATE INDEX IF NOT EXISTS idx_credentials_service ON credentials(service);
CREATE INDEX IF NOT EXISTS idx_credentials_vault ON credentials(vault);
CREATE INDEX IF NOT EXISTS idx_credentials_created_by ON credentials(created_by_user);

-- Credential names are NOT unique. Names are human-friendly labels; the UUID
-- primary key is the real identifier. Cedar policies control access.
-- Name-based resolution uses Cedar-filtered matching.

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
-- Policies (Cedar)
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
    device_name TEXT,
    workspace_id TEXT,
    workspace_name TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_correlation ON audit_events(correlation_id);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_events(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_events(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_device_id ON audit_events(device_id);
CREATE INDEX IF NOT EXISTS idx_audit_workspace_id ON audit_events(workspace_id);

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
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    upstream_url TEXT NOT NULL,
    transport TEXT NOT NULL DEFAULT 'http',
    credential_bindings TEXT NOT NULL DEFAULT '[]',
    allowed_tools TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_by TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '[]',
    required_credentials TEXT,
    auth_method TEXT NOT NULL DEFAULT 'none',
    template_key TEXT,
    discovered_tools TEXT,
    UNIQUE(workspace_id, name)
);

CREATE INDEX IF NOT EXISTS idx_mcp_servers_workspace_id ON mcp_servers(workspace_id);

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
-- OAuth 2.0 Authorization Server
-- ============================================================
CREATE TABLE IF NOT EXISTS oauth_clients (
    id TEXT PRIMARY KEY,
    client_id TEXT UNIQUE NOT NULL,
    client_secret_hash TEXT,
    workspace_name TEXT NOT NULL,
    public_key_hash TEXT UNIQUE NOT NULL,
    redirect_uris TEXT NOT NULL,       -- JSON array
    allowed_scopes TEXT NOT NULL,       -- comma-separated
    created_by_user TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS oauth_auth_codes (
    code_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
    user_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL,
    code_challenge TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);

CREATE TABLE IF NOT EXISTS oauth_access_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
    user_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
    user_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    access_token_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS oauth_consents (
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
    user_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    granted_at TEXT NOT NULL,
    PRIMARY KEY (client_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_client ON oauth_access_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_client ON oauth_refresh_tokens(client_id);

-- ============================================================
-- Provisioning Tokens (CI/CD workspace registration)
-- ============================================================
CREATE TABLE IF NOT EXISTS provisioning_tokens (
    token_hash TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
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
