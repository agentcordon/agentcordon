-- migration-mode: foreign_keys_off
-- A vault becomes a row.
--
-- Until now a vault was a string in `credentials.vault`: "owning" one meant
-- owning any credential that happened to carry the name, so two users who
-- each called a vault `team` were, to the server, in the same vault. This
-- migration gives every vault an id, a display name with no uniqueness
-- constraint, and an owner.
--
-- The mapping rule is one vault per distinct (name, owning user) pair among
-- the existing credentials. The owning user is the credential's creator;
-- a credential created by a workspace has none, so it takes the workspace's
-- owner, falling back to root. Everything named `default` lands in the one
-- system vault, which has a fixed id and no owner.
--
-- `credentials` and `vault_shares` are both rebuilt (SQLite cannot add a
-- foreign key or drop a column in place), hence the foreign_keys_off marker
-- on the first line: with enforcement on, dropping `credentials` would
-- cascade into `credential_secret_history`.

CREATE TABLE IF NOT EXISTS vaults (
    id TEXT PRIMARY KEY,
    -- Deliberately not unique, on its own or with the owner: a display
    -- label, not an identity.
    name TEXT NOT NULL,
    -- NULL only for the system default vault.
    owner_user_id TEXT REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vaults_owner ON vaults(owner_user_id);

-- The system default vault: fixed id, no owner, cannot be renamed, shared
-- or deleted. Keep this id in step with
-- `agent_cordon_core::domain::vault::DEFAULT_VAULT_ID`.
INSERT OR IGNORE INTO vaults (id, name, owner_user_id, created_at, updated_at)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'default',
    NULL,
    strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z',
    strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'
);

-- Which user each existing credential's vault should belong to.
CREATE TABLE _vault_placement AS
SELECT
    c.id AS credential_id,
    c.vault AS vault_name,
    COALESCE(
        c.created_by_user,
        (SELECT w.owner_id FROM workspaces w WHERE w.id = c.created_by),
        (SELECT u.id FROM users u WHERE u.is_root = 1 ORDER BY u.created_at, u.id LIMIT 1)
    ) AS owner_user_id
FROM credentials c
WHERE c.vault <> 'default';

-- One vault per distinct (name, owner) pair. The id is a random v4 UUID
-- built from `randomblob`, which SQLite re-evaluates per row.
INSERT INTO vaults (id, name, owner_user_id, created_at, updated_at)
SELECT
    lower(hex(randomblob(4))) || '-' ||
    lower(hex(randomblob(2))) || '-4' ||
    substr(lower(hex(randomblob(2))), 2) || '-' ||
    substr('89ab', abs(random()) % 4 + 1, 1) ||
    substr(lower(hex(randomblob(2))), 2) || '-' ||
    lower(hex(randomblob(6))),
    vault_name,
    owner_user_id,
    strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z',
    strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'
FROM (SELECT DISTINCT vault_name, owner_user_id FROM _vault_placement);

-- Rebuild `credentials` with `vault_id` in place of `vault`.
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
    vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001'
        REFERENCES vaults(id),
    credential_type TEXT NOT NULL DEFAULT 'generic',
    tags TEXT NOT NULL DEFAULT '[]',
    key_version INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    target_identity TEXT
);

INSERT INTO credentials_new (
    id, name, service, encrypted_value, nonce, scopes, metadata, created_by,
    created_at, updated_at, allowed_url_pattern, created_by_user, expires_at,
    transform_script, transform_name, vault_id, credential_type, tags,
    key_version, description, target_identity
)
SELECT
    c.id, c.name, c.service, c.encrypted_value, c.nonce, c.scopes, c.metadata,
    c.created_by, c.created_at, c.updated_at, c.allowed_url_pattern,
    c.created_by_user, c.expires_at, c.transform_script, c.transform_name,
    COALESCE(
        (SELECT v.id
           FROM _vault_placement p
           JOIN vaults v
             ON v.name = p.vault_name
            AND v.owner_user_id IS p.owner_user_id
          WHERE p.credential_id = c.id),
        '00000000-0000-0000-0000-000000000001'
    ),
    c.credential_type, c.tags, c.key_version, c.description, c.target_identity
FROM credentials c;

DROP TABLE credentials;
ALTER TABLE credentials_new RENAME TO credentials;

CREATE INDEX IF NOT EXISTS idx_credentials_service ON credentials(service);
CREATE INDEX IF NOT EXISTS idx_credentials_vault ON credentials(vault_id);
CREATE INDEX IF NOT EXISTS idx_credentials_created_by ON credentials(created_by_user);
CREATE INDEX IF NOT EXISTS idx_credentials_name ON credentials(name);

-- Rebuild `vault_shares` on the vault id.
--
-- A share row named its vault by (name, sharer): the sharer had to own a
-- credential in it, so the vault it meant is the one of that name owned by
-- `shared_by_user_id`. A share of `default` is dropped — the system vault
-- is not shareable, and every user already reaches it.
CREATE TABLE vault_shares_new (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    shared_with_user_id TEXT NOT NULL,
    permission_level TEXT NOT NULL DEFAULT 'read',
    shared_by_user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(vault_id, shared_with_user_id)
);

INSERT OR IGNORE INTO vault_shares_new
    (id, vault_id, shared_with_user_id, permission_level, shared_by_user_id, created_at)
SELECT s.id, v.id, s.shared_with_user_id, s.permission_level, s.shared_by_user_id, s.created_at
FROM vault_shares s
JOIN vaults v
  ON v.name = s.vault_name
 AND v.owner_user_id = s.shared_by_user_id
WHERE s.vault_name <> 'default';

DROP TABLE vault_shares;
ALTER TABLE vault_shares_new RENAME TO vault_shares;

CREATE INDEX IF NOT EXISTS idx_vault_shares_user ON vault_shares(shared_with_user_id);

DROP TABLE _vault_placement;
