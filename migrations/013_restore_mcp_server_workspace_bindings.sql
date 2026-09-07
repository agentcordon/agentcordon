-- Restore workspace bindings lost by the original migration 012.
--
-- 012 rebuilt `mcp_servers` with DROP TABLE while foreign-key enforcement
-- was on, so the junction's ON DELETE CASCADE emptied
-- `mcp_server_workspaces` on every install that upgraded from v0.3.2.
-- 012 is now marked to run with enforcement off, but installs that already
-- ran it need their bindings back.
--
-- The only surviving record of the original binding is the legacy
-- `mcp_servers.workspace_id` anchor, so this re-runs the 010 backfill.
-- Shares added after 010 (extra junction rows with no anchor) cannot be
-- recovered and must be re-created by the owner.
--
-- Idempotent: rows that still exist are left alone.

INSERT INTO mcp_server_workspaces (mcp_server_id, workspace_id, created_at, created_by_user)
SELECT m.id, m.workspace_id, m.created_at, m.created_by_user
FROM mcp_servers m
WHERE m.workspace_id IS NOT NULL
  AND EXISTS (SELECT 1 FROM workspaces w WHERE w.id = m.workspace_id)
ON CONFLICT (mcp_server_id, workspace_id) DO NOTHING;
