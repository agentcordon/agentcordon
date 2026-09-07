-- Bind OIDC logins to (provider, subject) instead of a username claim.
--
-- The OIDC callback used to resolve the local user by whatever username
-- claim the provider was configured to send, so any identity-provider
-- account with `preferred_username = root` logged in as root. A user is now
-- linked to an identity provider by the provider's stable `sub` claim; the
-- username claim only names a newly provisioned account.
--
-- One row per (provider, subject). A user may hold identities at several
-- providers. Rows go away with their user or provider.

CREATE TABLE IF NOT EXISTS user_oidc_identities (
    provider_id TEXT NOT NULL REFERENCES oidc_providers(id) ON DELETE CASCADE,
    subject     TEXT NOT NULL,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (provider_id, subject)
);

CREATE INDEX IF NOT EXISTS idx_user_oidc_identities_user
    ON user_oidc_identities(user_id);
