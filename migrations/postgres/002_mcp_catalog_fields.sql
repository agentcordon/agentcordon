-- Add catalog reference and deployment mode to MCP servers.
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS catalog_slug TEXT;
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS deployment_mode TEXT DEFAULT 'proxy';

INSERT INTO schema_migrations (version, applied_at) VALUES (2, NOW()) ON CONFLICT DO NOTHING;
