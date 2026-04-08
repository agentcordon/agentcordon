-- Add user ownership to MCP servers.
-- The created_by_user column tracks which user created/owns the MCP server,
-- enabling per-user duplicate checks and user-scoped server listings.

ALTER TABLE mcp_servers ADD COLUMN created_by_user TEXT;

-- Backfill: set created_by_user from the workspace's owner_id
UPDATE mcp_servers SET created_by_user = (
    SELECT owner_id FROM workspaces WHERE workspaces.id = mcp_servers.workspace_id
) WHERE created_by_user IS NULL;
