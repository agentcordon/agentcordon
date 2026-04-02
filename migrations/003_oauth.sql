-- OAuth 2.0 Authorization Server tables (v3.0.0)

-- OAuth clients (one per workspace registration)
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

-- Authorization codes (single-use, short-lived)
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

-- Access tokens
CREATE TABLE IF NOT EXISTS oauth_access_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
    user_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);

-- Refresh tokens
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

-- Consent records
CREATE TABLE IF NOT EXISTS oauth_consents (
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
    user_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    granted_at TEXT NOT NULL,
    PRIMARY KEY (client_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_client ON oauth_access_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_client ON oauth_refresh_tokens(client_id);
