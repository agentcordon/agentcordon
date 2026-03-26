-- Workspace Unification Migration (v2.0)
-- Collapses agents + devices + workspace_identities into a single workspaces table.
-- Old tables are renamed to *_legacy for one release cycle as a safety net.

-- ============================================================
-- 1. Create workspaces table (union of agent + device + workspace_identity fields)
-- ============================================================
CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'pending',   -- pending | active | revoked
    pk_hash TEXT UNIQUE,                       -- Ed25519 public key hash (from workspace_identities)
    encryption_public_key TEXT,                -- P-256 JWK (from devices.public_key_jwk)
    tags TEXT NOT NULL DEFAULT '[]',           -- JSON array
    owner_id TEXT REFERENCES users(id),
    parent_id TEXT REFERENCES workspaces(id) CHECK(parent_id != id),
    tool_name TEXT,                            -- informational: claude-code, cursor, etc.
    enrollment_token_hash TEXT,                -- carried from devices
    last_authenticated_at TEXT,                -- carried from devices
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_workspaces_owner_id ON workspaces(owner_id);
CREATE INDEX IF NOT EXISTS idx_workspaces_parent_id ON workspaces(parent_id);
CREATE INDEX IF NOT EXISTS idx_workspaces_status ON workspaces(status);
CREATE INDEX IF NOT EXISTS idx_workspaces_pk_hash ON workspaces(pk_hash);

-- ============================================================
-- 2. Migrate agents → workspaces (join with devices and workspace_identities)
-- ============================================================
INSERT INTO workspaces (
    id, name, enabled, status, pk_hash, encryption_public_key,
    tags, owner_id, enrollment_token_hash, last_authenticated_at,
    created_at, updated_at
)
SELECT
    a.id,
    a.name,
    a.enabled,
    COALESCE(wi.status, CASE WHEN a.enabled = 1 THEN 'active' ELSE 'revoked' END),
    wi.pk_hash,
    d.public_key_jwk,
    a.tags,
    a.owner_id,
    d.enrollment_token_hash,
    d.last_authenticated_at,
    a.created_at,
    a.updated_at
FROM agents a
LEFT JOIN devices d ON a.device_id = d.id
LEFT JOIN workspace_identities wi ON wi.id = a.id;

-- ============================================================
-- 3. Orphaned devices (no agent association) → workspaces
-- ============================================================
INSERT INTO workspaces (
    id, name, enabled, status, encryption_public_key,
    tags, owner_id, enrollment_token_hash, last_authenticated_at,
    created_at, updated_at
)
SELECT
    d.id,
    d.name,
    1,  -- devices have no enabled column; default to enabled
    d.status,
    d.public_key_jwk,
    d.tags,
    d.owner_id,
    d.enrollment_token_hash,
    d.last_authenticated_at,
    d.created_at,
    d.updated_at
FROM devices d
WHERE d.id NOT IN (SELECT device_id FROM agents WHERE device_id IS NOT NULL);

-- ============================================================
-- 4. Orphaned workspace_identities (no agent match) → workspaces
-- ============================================================
INSERT OR IGNORE INTO workspaces (
    id, name, enabled, status, pk_hash, tags, created_at, updated_at
)
SELECT
    wi.id,
    COALESCE(wi.name, 'workspace-' || substr(wi.id, 1, 8)),
    CASE WHEN wi.status = 'revoked' THEN 0 ELSE 1 END,
    wi.status,
    wi.pk_hash,
    '[]',
    wi.created_at,
    wi.updated_at
FROM workspace_identities wi
WHERE wi.id NOT IN (SELECT id FROM workspaces);

-- ============================================================
-- 5. Update FK references: mcp_servers
-- ============================================================
-- Recreate mcp_servers with workspace_id replacing device_id.
-- SQLite doesn't support DROP COLUMN or altering FKs, so we recreate.
CREATE TABLE mcp_servers_new (
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
    UNIQUE(workspace_id, name)
);

-- Migrate data: map device_id → workspace_id
-- Priority: agent that owned the device > device itself
INSERT INTO mcp_servers_new (
    id, workspace_id, name, upstream_url, transport, credential_bindings,
    allowed_tools, enabled, created_by, created_at, updated_at, tags, required_credentials
)
SELECT
    m.id,
    COALESCE(
        (SELECT a.id FROM agents a WHERE a.device_id = m.device_id LIMIT 1),
        m.device_id
    ),
    m.name, m.upstream_url, m.transport, m.credential_bindings,
    m.allowed_tools, m.enabled, m.created_by, m.created_at, m.updated_at,
    m.tags, m.required_credentials
FROM mcp_servers m;

DROP TABLE mcp_servers;
ALTER TABLE mcp_servers_new RENAME TO mcp_servers;

CREATE INDEX IF NOT EXISTS idx_mcp_servers_workspace_id ON mcp_servers(workspace_id);

-- ============================================================
-- 6. Update FK references: credentials
-- ============================================================
-- credentials.created_by originally references agents(id). After renaming agents
-- to agents_legacy, the FK breaks. Recreate the table with created_by referencing
-- workspaces(id) instead.
CREATE TABLE credentials_new (
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
    key_version INTEGER NOT NULL DEFAULT 1
);

INSERT INTO credentials_new SELECT
    id, name, service, encrypted_value, nonce, scopes, metadata,
    created_by, created_at, updated_at, allowed_url_pattern,
    created_by_user, expires_at, transform_script, transform_name,
    vault, credential_type, tags, key_version
FROM credentials;

DROP TABLE credentials;
ALTER TABLE credentials_new RENAME TO credentials;

CREATE INDEX IF NOT EXISTS idx_credentials_service ON credentials(service);
CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_name_unique ON credentials(name);
CREATE INDEX IF NOT EXISTS idx_credentials_vault ON credentials(vault);
CREATE INDEX IF NOT EXISTS idx_credentials_created_by ON credentials(created_by_user);

-- ============================================================
-- 7. Update FK references: audit_events
-- ============================================================
ALTER TABLE audit_events ADD COLUMN workspace_id TEXT;
ALTER TABLE audit_events ADD COLUMN workspace_name TEXT;
UPDATE audit_events SET workspace_id = COALESCE(agent_id, device_id);
UPDATE audit_events SET workspace_name = COALESCE(agent_name, device_name);

CREATE INDEX IF NOT EXISTS idx_audit_workspace_id ON audit_events(workspace_id);

-- ============================================================
-- 8. Update FK references: enrollment_sessions
-- ============================================================
ALTER TABLE enrollment_sessions ADD COLUMN workspace_id TEXT REFERENCES workspaces(id);
-- Map existing device_id references to workspaces
-- If the device was bound to an agent, use agent id; otherwise device id
UPDATE enrollment_sessions SET workspace_id = (
    SELECT a.id FROM agents a WHERE a.device_id = enrollment_sessions.device_id LIMIT 1
)
WHERE device_id IS NOT NULL;
UPDATE enrollment_sessions SET workspace_id = device_id
WHERE workspace_id IS NULL AND device_id IS NOT NULL;

-- ============================================================
-- 9. Rename device_used_jtis → workspace_used_jtis
-- ============================================================
ALTER TABLE device_used_jtis RENAME TO workspace_used_jtis;

-- ============================================================
-- 10. Cedar policy text migration
-- ============================================================
-- Replace entity type names in Cedar policies
UPDATE policies SET cedar_policy = REPLACE(
    REPLACE(cedar_policy, 'AgentCordon::Agent', 'AgentCordon::Workspace'),
    'AgentCordon::Device', 'AgentCordon::Workspace'
);
UPDATE policies SET cedar_policy = REPLACE(
    cedar_policy, 'AgentCordon::AgentResource', 'AgentCordon::WorkspaceResource'
);

-- Update grant policy names that reference :agent:
UPDATE policies SET name = REPLACE(name, ':agent:', ':workspace:')
WHERE name LIKE 'grant:%:agent:%';

-- ============================================================
-- 11. Rename workspace_registrations pk_hash column is fine as-is
--     (workspace_registrations already uses workspace terminology)
-- ============================================================

-- ============================================================
-- 12. Rename old tables to *_legacy (safety net for one release cycle)
-- ============================================================
ALTER TABLE agents RENAME TO agents_legacy;
ALTER TABLE devices RENAME TO devices_legacy;
ALTER TABLE workspace_identities RENAME TO workspace_identities_legacy;
