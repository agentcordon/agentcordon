-- RFC 8628 OAuth 2.0 Device Authorization Grant
--
-- Storage for device codes issued via POST /oauth/device/code and the
-- well-known public bootstrap client used for first-time broker registration.

CREATE TABLE IF NOT EXISTS device_codes (
    device_code             TEXT PRIMARY KEY,
    user_code               TEXT NOT NULL UNIQUE,
    client_id               TEXT NOT NULL,
    scopes                  TEXT NOT NULL DEFAULT '',
    status                  TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','approved','denied','expired','consumed')),
    workspace_name_prefill  TEXT,
    approved_user_id        TEXT,
    last_polled_at          TEXT,
    interval_secs           INTEGER NOT NULL DEFAULT 5,
    created_at              TEXT NOT NULL,
    expires_at              TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON device_codes(user_code);
CREATE INDEX IF NOT EXISTS idx_device_codes_status_expires
    ON device_codes(status, expires_at);

-- Seed the well-known public bootstrap client used by the broker / CLI for
-- first-time device-flow registration (locked decision #3 for v0.3.0). This
-- client is a public client (no client_secret) and is never rotated. It owns
-- no workspace, has no redirect_uris, and is permitted only to initiate the
-- device authorization grant via Cedar policy.
INSERT OR IGNORE INTO oauth_clients (
    id,
    client_id,
    client_secret_hash,
    workspace_name,
    public_key_hash,
    redirect_uris,
    allowed_scopes,
    created_by_user,
    created_at,
    revoked_at
) VALUES (
    '00000000-0000-0000-0000-00000000b01d',
    'agentcordon-broker',
    NULL,
    '',
    'agentcordon-broker-public-client',
    '[]',
    'credentials:discover,credentials:vend,mcp:invoke',
    '00000000-0000-0000-0000-000000000000',
    '2026-04-09T00:00:00Z',
    NULL
);
