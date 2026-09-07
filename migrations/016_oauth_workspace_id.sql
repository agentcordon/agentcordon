-- Bind OAuth clients and tokens to a workspace by id.
--
-- Until now a bearer token reached its workspace by three lookups: token to
-- client, client to public-key hash, hash to workspace. The hash is a
-- property of the key, not of the workspace, so a re-registered or rotated
-- key silently re-pointed every token. Each row now names its workspace
-- directly; existing rows are backfilled through the hash they were issued
-- against. A client whose hash matches no workspace keeps NULL and is
-- refused by the extractor, which is what the missing-workspace path did.

ALTER TABLE oauth_clients ADD COLUMN workspace_id TEXT REFERENCES workspaces(id);

UPDATE oauth_clients
   SET workspace_id = (SELECT w.id FROM workspaces w WHERE w.pk_hash = oauth_clients.public_key_hash)
 WHERE workspace_id IS NULL;

ALTER TABLE oauth_access_tokens ADD COLUMN workspace_id TEXT REFERENCES workspaces(id);

UPDATE oauth_access_tokens
   SET workspace_id = (SELECT c.workspace_id FROM oauth_clients c WHERE c.client_id = oauth_access_tokens.client_id)
 WHERE workspace_id IS NULL;

ALTER TABLE oauth_refresh_tokens ADD COLUMN workspace_id TEXT REFERENCES workspaces(id);

UPDATE oauth_refresh_tokens
   SET workspace_id = (SELECT c.workspace_id FROM oauth_clients c WHERE c.client_id = oauth_refresh_tokens.client_id)
 WHERE workspace_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_oauth_clients_workspace ON oauth_clients(workspace_id);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_workspace ON oauth_access_tokens(workspace_id);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_workspace ON oauth_refresh_tokens(workspace_id);
