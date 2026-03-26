-- Migration 041: Device-scoped MCP servers (Postgres version)

-- Step 1: Add device_id column (nullable for migration)
ALTER TABLE mcp_servers ADD COLUMN device_id UUID REFERENCES devices(id) ON DELETE RESTRICT;

-- Step 2: Assign existing MCPs to the oldest active device (preserving original IDs).
UPDATE mcp_servers
SET device_id = (
    SELECT id FROM devices WHERE status = 'active'
    ORDER BY created_at ASC LIMIT 1
)
WHERE device_id IS NULL;

-- Step 3: Duplicate existing MCPs to all OTHER active devices (new IDs).
INSERT INTO mcp_servers (
    id, device_id, name, upstream_url, transport, credential_bindings,
    allowed_tools, enabled, created_by, created_at, updated_at,
    catalog_slug, deployment_mode, tags, command, args, env, required_credentials
)
SELECT
    gen_random_uuid(), d.id, m.name, m.upstream_url, m.transport, m.credential_bindings,
    m.allowed_tools, m.enabled, m.created_by, m.created_at, m.updated_at,
    m.catalog_slug, m.deployment_mode, m.tags, m.command, m.args, m.env, m.required_credentials
FROM mcp_servers m
CROSS JOIN devices d
WHERE d.status = 'active'
  AND d.id != m.device_id
  AND m.device_id IS NOT NULL;

-- Step 4: Delete orphaned MCPs with no device
DELETE FROM mcp_servers WHERE device_id IS NULL;

-- Step 5: Make device_id NOT NULL now that all rows have been assigned.
ALTER TABLE mcp_servers ALTER COLUMN device_id SET NOT NULL;

-- Step 6: Drop old unique constraint on name, add new one on (device_id, name)
ALTER TABLE mcp_servers DROP CONSTRAINT IF EXISTS mcp_servers_name_key;
DROP INDEX IF EXISTS mcp_servers_name_key;
ALTER TABLE mcp_servers ADD CONSTRAINT mcp_servers_device_id_name_key UNIQUE (device_id, name);

-- Step 7: Index for performance
CREATE INDEX IF NOT EXISTS idx_mcp_servers_device_id ON mcp_servers(device_id);
