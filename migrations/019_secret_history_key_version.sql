-- migration-mode: foreign_keys_off
-- History rows carry the master-key version they were sealed under.
--
-- `key_version` now means "which master key encrypted this row" on both
-- `credentials` and `credential_secret_history`, so a rotation can decrypt
-- each row with the right key and `rotate-key` can re-seal every history
-- row under the current one. The consolidated schema (001) already declares
-- the column on `credential_secret_history` but nothing ever wrote it, and
-- an install whose history table predates the consolidation may lack it.
-- SQLite has no ADD COLUMN IF NOT EXISTS, so the table is rebuilt: every
-- row is copied without its old `key_version` and lands on the default of
-- 1, the only version that existed before this migration. Rebuilding drops
-- the table, hence the foreign_keys_off marker on the first line.

CREATE TABLE credential_secret_history_new (
    id TEXT PRIMARY KEY,
    credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    encrypted_value BLOB NOT NULL,
    nonce BLOB NOT NULL,
    changed_at TEXT NOT NULL,
    changed_by_user TEXT,
    changed_by_agent TEXT,
    key_version INTEGER NOT NULL DEFAULT 1
);

INSERT INTO credential_secret_history_new
    (id, credential_id, encrypted_value, nonce, changed_at, changed_by_user, changed_by_agent)
SELECT
    id, credential_id, encrypted_value, nonce, changed_at, changed_by_user, changed_by_agent
FROM credential_secret_history;

DROP TABLE credential_secret_history;
ALTER TABLE credential_secret_history_new RENAME TO credential_secret_history;

CREATE INDEX IF NOT EXISTS idx_secret_history_credential ON credential_secret_history(credential_id);
