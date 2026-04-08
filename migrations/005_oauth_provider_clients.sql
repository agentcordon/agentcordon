-- Rename mcp_oauth_apps -> oauth_provider_clients and restructure.
-- New schema is keyed by authorization_server_url (not template_key).

CREATE TABLE IF NOT EXISTS oauth_provider_clients (
    id TEXT PRIMARY KEY,
    authorization_server_url TEXT NOT NULL UNIQUE,
    issuer TEXT,
    authorize_endpoint TEXT NOT NULL,
    token_endpoint TEXT NOT NULL,
    registration_endpoint TEXT,
    code_challenge_methods_supported TEXT NOT NULL DEFAULT '[]',
    token_endpoint_auth_methods_supported TEXT NOT NULL DEFAULT '[]',
    scopes_supported TEXT NOT NULL DEFAULT '[]',
    client_id TEXT NOT NULL,
    encrypted_client_secret BLOB,
    nonce BLOB,
    requested_scopes TEXT NOT NULL DEFAULT '',
    registration_source TEXT NOT NULL DEFAULT 'manual',
    client_id_issued_at TEXT,
    client_secret_expires_at TEXT,
    registration_access_token_encrypted BLOB,
    registration_access_token_nonce BLOB,
    registration_client_uri TEXT,
    label TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Migrate existing rows (if any) from mcp_oauth_apps. Naive origin extraction
-- from token_url; real normalization happens in code for new inserts.
INSERT OR IGNORE INTO oauth_provider_clients (
    id, authorization_server_url, authorize_endpoint, token_endpoint,
    client_id, encrypted_client_secret, nonce, requested_scopes,
    registration_source, label, enabled, created_at, updated_at
)
SELECT
    id,
    CASE
        WHEN instr(substr(token_url, 9), '/') > 0
            THEN substr(token_url, 1, 8 + instr(substr(token_url, 9), '/') - 1)
        ELSE token_url
    END,
    authorize_url,
    token_url,
    client_id,
    encrypted_client_secret,
    nonce,
    COALESCE(scopes, ''),
    'manual',
    COALESCE(name, template_key),
    enabled,
    created_at,
    updated_at
FROM mcp_oauth_apps
WHERE EXISTS (
    SELECT 1 FROM sqlite_master WHERE type='table' AND name='mcp_oauth_apps'
);

DROP TABLE IF EXISTS mcp_oauth_apps;

-- Add authorization_server_url column to mcp_oauth_states for AS-keyed lookups.
ALTER TABLE mcp_oauth_states ADD COLUMN authorization_server_url TEXT;

-- Rename credential type oauth2_authorization_code -> oauth2_user_authorization
UPDATE credentials SET credential_type = 'oauth2_user_authorization'
WHERE credential_type = 'oauth2_authorization_code';
