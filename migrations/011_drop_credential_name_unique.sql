-- Drop the global UNIQUE index on credentials.name.
--
-- Migration 007 added a global unique index, but per the v3.1.1 design
-- (see v311_credential_name_scoping.rs and the credential_bugs suite),
-- credential names are NOT unique. Vend-by-name uses Cedar-filtered matching:
-- list candidates by name, evaluate Cedar authorization, return the
-- authorized one (or 300 Multiple Choices if ambiguous).
--
-- The global UNIQUE constraint broke the design: tester A creating
-- "shared-api-key" prevented tester B (a different user) from creating a
-- credential with the same name, leaking the existence of A's credential
-- through a 409 Conflict response.
--
-- The store layer's SQLITE_CONSTRAINT_UNIQUE → 409 mapping stays — it still
-- catches violations from any other unique indexes on the table.

DROP INDEX IF EXISTS idx_credentials_name_unique;
