-- Credentials are looked up by name on every vend-by-name call and on the
-- credential picker; 011 dropped the unique index on name (names are not
-- unique by design) and left the column unindexed.

CREATE INDEX IF NOT EXISTS idx_credentials_name ON credentials(name);
