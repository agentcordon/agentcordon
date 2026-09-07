# 6. Secrets never leave the server: the broker never calls a provider token endpoint

- **Status:** Accepted
- **Date:** 2026-09-04

## Context

The product's promise is that an agent never sees a raw secret. The broker runs on the user's
machine, which is the least trusted place in the system — it is where a prompt-injected agent
runs — so what the broker holds is what an attacker gets.

The broker held too much. To refresh upstream OAuth tokens on its own it needed, and was sent,
the material to do so:

- MCP sync shipped the upstream OAuth **refresh token** and the provider's **client secret**
  inside the credential envelope, so the broker could run `refresh_token` exchanges itself.
- A vend of an `oauth2_client_credentials` credential returned the **client secret** plus
  token-endpoint metadata for the broker to exchange.

Both are long-lived. A compromised user machine yielded a refresh token good for as long as the
provider allows and a client secret shared across every tenant at that origin. The broker also
carried the machinery to use them: a refresh manager, a rotation callback, a client-credentials
manager, and a `POST /api/v1/workspaces/mcp/rotate-refresh-token` endpoint on the server to
write rotated tokens back.

## Decision

The broker holds only **short-lived access tokens**. Every exchange with a provider happens on
the server.

- The server runs the `refresh_token` and `client_credentials` exchanges itself through the
  shared `OAuth2TokenManager` (`crates/server/src/upstream_token_service.rs`,
  `crates/core/src/oauth2/token_manager.rs`) and seals **only the exchanged access token with
  its `expires_at`** into the envelope.
- A vend of an `oauth2_client_credentials` credential returns the exchanged access token and
  its expiry; the broker injects it as a bearer
  (`crates/server/src/routes/admin_api/credentials/vend.rs`).
- A refresh token rotated by the provider is persisted **on the server**, with a history row and
  a `CredentialSecretRotated` audit event.
- A sync entry whose exchange failed carries a `credential_error` string and no envelope; the
  rest of the sync still lands, so one broken credential does not blank a workspace.
- The broker's refresh manager, rotation callback and client-credentials manager are deleted,
  and `POST /api/v1/workspaces/mcp/rotate-refresh-token` is removed.
- The broker's own staleness handling is re-sync, not refresh: a cached upstream token within
  60s of expiry is refreshed by syncing again, and an upstream MCP 401 triggers one re-sync and
  one retry.
- Upstream token caches are keyed by **workspace key hash and server id**, so one workspace
  cannot be served another's token.

## Consequences

- A compromised user machine yields, at worst, short-lived access tokens for the credentials
  that workspace was already permitted to use — no refresh tokens, no client secrets.
- The server is now on the critical path for every upstream token. `OAuth2TokenManager`'s cache
  therefore matters: it lives behind an `Arc` so that clones of `AppState` share it, rather than
  each request getting a private cache it writes once and drops.
- Brokers and servers must be upgraded together, because the removed route and the changed
  envelope contents have no dual-accept window. See ADR-0010.
- The invariant is asserted from the wire: a `wiremock` standing in for an OAuth provider
  records **zero hits** while a delegated and an app credential are vended, synced and injected
  (`crates/broker/tests/no_provider_grant.rs`).
- A deployment that wanted brokers to hold refresh tokens — for example to survive server
  outages — is not supported. The architecture spec assumed no such deployment and this
  decision commits to that.
