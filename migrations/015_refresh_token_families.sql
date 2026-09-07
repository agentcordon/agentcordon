-- Refresh-token families for reuse detection.
--
-- Rotation retires a refresh token and issues a successor. If a retired
-- token is presented again, it leaked (or the legitimate client lost the
-- race), and every token descended from the same original grant must die
-- with it. `family_id` names that original grant; a successor inherits its
-- predecessor's family. Existing rows become the root of their own family.

ALTER TABLE oauth_refresh_tokens ADD COLUMN family_id TEXT;

UPDATE oauth_refresh_tokens SET family_id = token_hash WHERE family_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_family
    ON oauth_refresh_tokens(family_id);
