-- MCP OAuth app configurations: server-wide admin settings for OAuth2 app
-- registrations (client_id/client_secret) used by MCP marketplace templates.
-- One OAuth app per MCP template (template_key is UNIQUE).
CREATE TABLE IF NOT EXISTS mcp_oauth_apps (
    id TEXT PRIMARY KEY,
    template_key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    client_id TEXT NOT NULL,
    encrypted_client_secret BLOB NOT NULL,
    nonce BLOB NOT NULL,
    authorize_url TEXT NOT NULL,
    token_url TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
