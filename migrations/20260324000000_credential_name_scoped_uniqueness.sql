-- Scope credential name uniqueness to per-creator (workspace) instead of global.
-- This allows different workspaces to have credentials with the same name.

-- Drop global unique index
DROP INDEX IF EXISTS idx_credentials_name_unique;

-- Add workspace-scoped unique index (name + created_by)
CREATE UNIQUE INDEX idx_credentials_name_created_by_unique
    ON credentials(name, created_by);

-- Add partial index for NULL created_by (admin-created credentials).
-- SQLite treats NULLs as distinct in UNIQUE indexes, so without this,
-- two admin-created credentials with the same name would both be allowed.
CREATE UNIQUE INDEX idx_credentials_name_admin_unique
    ON credentials(name) WHERE created_by IS NULL;
