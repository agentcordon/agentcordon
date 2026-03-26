-- Add STDIO transport fields and required_credentials to mcp_servers
ALTER TABLE mcp_servers ADD COLUMN command TEXT;
ALTER TABLE mcp_servers ADD COLUMN args JSONB;
ALTER TABLE mcp_servers ADD COLUMN env JSONB;
ALTER TABLE mcp_servers ADD COLUMN required_credentials JSONB;
