-- Workspace Unification Migration (v2.0) — PostgreSQL
-- Collapses agents + devices (sidecars in PG) + workspace_identities into workspaces.
-- NOTE: The PostgreSQL schema may be behind SQLite. This migration handles both
-- "sidecars" (old PG name) and "devices" (current SQLite name) gracefully.

-- ============================================================
-- 1. Create workspaces table
-- ============================================================
CREATE TABLE IF NOT EXISTS workspaces (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    status TEXT NOT NULL DEFAULT 'pending',
    pk_hash TEXT UNIQUE,
    encryption_public_key JSONB,
    tags JSONB NOT NULL DEFAULT '[]',
    owner_id UUID REFERENCES users(id),
    parent_id UUID REFERENCES workspaces(id) CHECK(parent_id != id),
    tool_name TEXT,
    enrollment_token_hash TEXT,
    last_authenticated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_workspaces_owner_id ON workspaces(owner_id);
CREATE INDEX IF NOT EXISTS idx_workspaces_parent_id ON workspaces(parent_id);
CREATE INDEX IF NOT EXISTS idx_workspaces_status ON workspaces(status);
CREATE INDEX IF NOT EXISTS idx_workspaces_pk_hash ON workspaces(pk_hash);

-- ============================================================
-- 2. Migrate agents → workspaces
-- ============================================================
-- PG schema may have sidecars instead of devices; handle both.
-- Agents may or may not have device_id depending on which PG migrations ran.
INSERT INTO workspaces (id, name, enabled, status, tags, owner_id, created_at, updated_at)
SELECT a.id, a.name, a.enabled,
    CASE WHEN a.enabled THEN 'active' ELSE 'revoked' END,
    a.tags, a.owner_id, a.created_at, a.updated_at
FROM agents a
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- 3. Migrate sidecars/devices → workspaces (orphans only)
-- ============================================================
-- Try sidecars first (PG base schema uses this name)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'sidecars') THEN
        INSERT INTO workspaces (id, name, enabled, status, encryption_public_key, tags, enrollment_token_hash, last_authenticated_at, created_at, updated_at)
        SELECT s.id, s.name, TRUE, s.status, s.public_key_jwk, s.tags, s.enrollment_token_hash, s.last_authenticated_at, s.created_at, s.updated_at
        FROM sidecars s
        WHERE s.id NOT IN (SELECT id FROM workspaces)
        ON CONFLICT (id) DO NOTHING;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'devices') THEN
        INSERT INTO workspaces (id, name, enabled, status, encryption_public_key, tags, enrollment_token_hash, last_authenticated_at, created_at, updated_at)
        SELECT d.id, d.name, TRUE, d.status, d.public_key_jwk::jsonb, d.tags, d.enrollment_token_hash, d.last_authenticated_at, d.created_at, d.updated_at
        FROM devices d
        WHERE d.id NOT IN (SELECT id FROM workspaces)
        ON CONFLICT (id) DO NOTHING;
    END IF;
END $$;

-- ============================================================
-- 4. Update FK references: mcp_servers
-- ============================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'mcp_servers' AND column_name = 'workspace_id') THEN
        ALTER TABLE mcp_servers ADD COLUMN workspace_id UUID REFERENCES workspaces(id);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_mcp_servers_workspace_id ON mcp_servers(workspace_id);

-- ============================================================
-- 5. Update FK references: credentials
-- ============================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'credentials' AND column_name = 'created_by_workspace') THEN
        ALTER TABLE credentials ADD COLUMN created_by_workspace UUID REFERENCES workspaces(id);
    END IF;
END $$;

UPDATE credentials SET created_by_workspace = created_by WHERE created_by IS NOT NULL AND created_by_workspace IS NULL;

-- ============================================================
-- 6. Update FK references: audit_events
-- ============================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'audit_events' AND column_name = 'workspace_id') THEN
        ALTER TABLE audit_events ADD COLUMN workspace_id UUID;
        ALTER TABLE audit_events ADD COLUMN workspace_name TEXT;
    END IF;
END $$;

UPDATE audit_events SET workspace_id = COALESCE(agent_id, device_id::uuid) WHERE workspace_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_audit_workspace_id ON audit_events(workspace_id);

-- ============================================================
-- 7. Update FK references: enrollment_sessions
-- ============================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'enrollment_sessions' AND column_name = 'workspace_id') THEN
        ALTER TABLE enrollment_sessions ADD COLUMN workspace_id UUID REFERENCES workspaces(id);
    END IF;
END $$;

-- ============================================================
-- 8. Rename JTI tracking table
-- ============================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'sidecar_used_jtis') THEN
        ALTER TABLE sidecar_used_jtis RENAME TO workspace_used_jtis;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'device_used_jtis') THEN
        ALTER TABLE device_used_jtis RENAME TO workspace_used_jtis;
    END IF;
END $$;

-- ============================================================
-- 9. Cedar policy text migration
-- ============================================================
UPDATE policies SET cedar_policy = REPLACE(
    REPLACE(cedar_policy, 'AgentCordon::Agent', 'AgentCordon::Workspace'),
    'AgentCordon::Device', 'AgentCordon::Workspace'
);
UPDATE policies SET cedar_policy = REPLACE(
    cedar_policy, 'AgentCordon::AgentResource', 'AgentCordon::WorkspaceResource'
);
UPDATE policies SET name = REPLACE(name, ':agent:', ':workspace:')
WHERE name LIKE 'grant:%:agent:%';

-- ============================================================
-- 10. Rename old tables to *_legacy
-- ============================================================
ALTER TABLE IF EXISTS agents RENAME TO agents_legacy;
ALTER TABLE IF EXISTS sidecars RENAME TO sidecars_legacy;
ALTER TABLE IF EXISTS devices RENAME TO devices_legacy;
