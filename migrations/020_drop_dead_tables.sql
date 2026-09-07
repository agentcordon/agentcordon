-- Drop the tables of the retired identity model. Nothing reads or writes
-- them any more:
--   workspace_used_jtis      — JTI replay set for the retired workspace-JWT
--                              scheme; bearer tokens are opaque OAuth tokens.
--   workspace_registrations  — PKCE approval-code enrollment, replaced by
--                              the OAuth device flow.
--   provisioning_tokens      — CI/CD pre-shared registration tokens, never
--                              wired to a route.
--   crypto_state             — persisted AES-GCM encryption counter; nonces
--                              are random per encryption and the counter
--                              was never loaded back.
-- No live table references any of them, so plain drops suffice.

DROP INDEX IF EXISTS idx_workspace_jtis_expires;
DROP TABLE IF EXISTS workspace_used_jtis;
DROP TABLE IF EXISTS workspace_registrations;
DROP TABLE IF EXISTS provisioning_tokens;
DROP TABLE IF EXISTS crypto_state;
