-- MCP <-> Workspace M:N junction.
--
-- Moves the MCP-to-workspace relationship from 1:1 to M:N so one MCP record
-- can be bound to multiple workspaces. This junction table is the **single
-- source of truth** for workspace↔MCP routing — every read path (admin
-- list, workspace permissions, broker sync, report-tools) goes through it.
--
-- The old `mcp_servers.workspace_id` column is being phased out per issue
-- #37. Migration 012 makes it nullable, and the application no longer
-- writes it on create/update. Existing rows keep their value as a
-- write-once audit anchor (the workspace the MCP was originally
-- provisioned for) until a future migration drops the column entirely.
--
-- Forward-only per project convention. Rolling back is done by restoring a
-- pre-upgrade database backup; see docs/upgrading.md.

CREATE TABLE IF NOT EXISTS mcp_server_workspaces (
    mcp_server_id   TEXT NOT NULL,
    workspace_id    TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by_user TEXT,
    PRIMARY KEY (mcp_server_id, workspace_id),
    FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id) ON DELETE CASCADE,
    FOREIGN KEY (workspace_id)  REFERENCES workspaces(id)  ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mcp_server_workspaces_workspace
    ON mcp_server_workspaces(workspace_id);

-- Backfill: one junction row per existing MCP using its current
-- `mcp_servers.workspace_id`. ON CONFLICT DO NOTHING keeps the operation
-- idempotent across re-runs and against any rows a future code path may
-- have inserted before this migration lands.
INSERT INTO mcp_server_workspaces (mcp_server_id, workspace_id, created_at, created_by_user)
SELECT id, workspace_id, created_at, created_by_user
FROM mcp_servers
WHERE workspace_id IS NOT NULL
ON CONFLICT (mcp_server_id, workspace_id) DO NOTHING;
