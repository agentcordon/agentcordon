-- Enforce unique credential names.
-- Pre-flight: run scripts/migration-007-precheck.sh to detect duplicate names before applying.
--
-- The store layer (crates/core/src/storage/sqlite/credentials/mod.rs) already
-- detects SQLITE_CONSTRAINT_UNIQUE and maps it to StoreError::Conflict (→ 409),
-- and /api/v1/credentials/by-name returns 300 Multiple Choices on duplicates.
-- Both of those imply names are meant to be unique, but the UNIQUE constraint
-- itself was never in the schema, so duplicate creates silently succeeded and
-- lookup by-name returned 300 instead of a single credential.
--
-- This migration closes that gap. Fresh installs get a unique constraint from
-- the start; upgraders whose DB already contains duplicates will hit an error
-- here and must resolve duplicates manually before applying this migration.

CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_name_unique
    ON credentials(name);
