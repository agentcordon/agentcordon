-- Add tags column to MCP servers (JSONB array, default empty).
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS tags JSONB NOT NULL DEFAULT '[]';

INSERT INTO schema_migrations (version, applied_at) VALUES (3, NOW()) ON CONFLICT DO NOTHING;
