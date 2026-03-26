-- Drop device-local fields from mcp_servers: command, args, env, catalog_slug, deployment_mode
-- These fields belong on the device, not the server.
ALTER TABLE mcp_servers DROP COLUMN command;
ALTER TABLE mcp_servers DROP COLUMN args;
ALTER TABLE mcp_servers DROP COLUMN env;
ALTER TABLE mcp_servers DROP COLUMN catalog_slug;
ALTER TABLE mcp_servers DROP COLUMN deployment_mode;
