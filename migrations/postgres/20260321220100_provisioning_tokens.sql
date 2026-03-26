-- Provisioning tokens for CI/CD workspace registration.
-- The raw token is never stored; only its SHA-256 hash.
CREATE TABLE IF NOT EXISTS provisioning_tokens (
    token_hash TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL
);
