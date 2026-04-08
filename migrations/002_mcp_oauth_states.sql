-- MCP OAuth2 authorization state for the authorization code flow.
-- Each row is single-use: consumed (deleted) after the callback processes it.
CREATE TABLE IF NOT EXISTS mcp_oauth_states (
    state TEXT PRIMARY KEY,
    template_key TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_verifier TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_mcp_oauth_states_expires_at ON mcp_oauth_states(expires_at);
