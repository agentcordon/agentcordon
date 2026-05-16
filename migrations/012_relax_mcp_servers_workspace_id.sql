-- Relax `mcp_servers.workspace_id` from NOT NULL to nullable.
--
-- Issue #37: the `mcp_server_workspaces` junction table is now the single
-- source of truth for workspace↔MCP routing (added by migration 010).
-- All server-side read paths have been switched off the legacy column
-- (admin list, workspace permissions, workspace sync, report-tools).
--
-- This migration relaxes the column constraint so the application can
-- start inserting MCPs without a denormalized `workspace_id`. The column
-- is retained (not dropped) so legacy rows keep their provenance trail
-- as a write-once audit anchor; a follow-up migration will drop the
-- column entirely once we are confident nothing in the upgrade path
-- depends on it.
--
-- The `ON DELETE RESTRICT` is replaced with `ON DELETE SET NULL`: a
-- workspace can be deleted while still having MCPs bound to other
-- workspaces via the junction (which uses `ON DELETE CASCADE` per 010),
-- so the legacy anchor must not block workspace deletion.
--
-- SQLite cannot ALTER a column constraint in place; we recreate the
-- table inside this migration's savepoint and copy rows over.

CREATE TABLE mcp_servers_new (
    id TEXT PRIMARY KEY,
    workspace_id TEXT REFERENCES workspaces(id) ON DELETE SET NULL,
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
    created_by_user TEXT,
    UNIQUE(workspace_id, name)
);

INSERT INTO mcp_servers_new
    (id, workspace_id, name, upstream_url, transport, credential_bindings,
     allowed_tools, enabled, created_by, created_at, updated_at, tags,
     required_credentials, auth_method, template_key, discovered_tools,
     created_by_user)
SELECT
    id, workspace_id, name, upstream_url, transport, credential_bindings,
    allowed_tools, enabled, created_by, created_at, updated_at, tags,
    required_credentials, auth_method, template_key, discovered_tools,
    created_by_user
FROM mcp_servers;

DROP TABLE mcp_servers;
ALTER TABLE mcp_servers_new RENAME TO mcp_servers;

CREATE INDEX IF NOT EXISTS idx_mcp_servers_workspace_id ON mcp_servers(workspace_id);
