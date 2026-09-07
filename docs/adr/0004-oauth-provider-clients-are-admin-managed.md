# 4. OAuth provider clients are admin-managed under `manage_oauth_provider_clients`

- **Status:** Accepted
- **Date:** 2026-09-04

## Context

An **OAuth provider client** is AgentCordon's registration at one upstream authorization
server: the `client_id` and `client_secret` used to obtain tokens for `oauth2_user_authorization`
credentials and for OAuth2 MCP servers at that origin. It is keyed by the authorization
server's normalised origin, so there is **one row per origin, shared by every tenant** whose
MCP servers and credentials authenticate there. It is either created by Dynamic Client
Registration during an MCP install, or entered by hand.

Creating, editing, deleting and re-registering one was guarded by `manage_mcp_servers`, which
the default policy grants to every operator. An operator could therefore rewrite or remove the
registration that every other tenant's MCP servers at that origin depend on, and their next
token refresh would fail. Deleting a row also silently broke its dependents, because the
`client_id` and `client_secret` their exchange needs live only on that row.

## Decision

Managing an OAuth provider client is an administrative act with its own Cedar action.

- A new action **`manage_oauth_provider_clients`** guards create, update, delete, toggle and
  re-register. The default policy grants it to enabled admins only
  (`crates/server/src/services/identity_providers.rs`, `policies/default.cedar`).
- **Listing stays on `manage_mcp_servers`.** An operator can still see which client an origin
  uses — never its secret — because that is information they need to reason about their own
  MCP servers. The Settings page shows the listing to operators and offers add, edit, toggle,
  re-register and delete to admins only.
- **Dynamic client registration during an MCP install is unaffected.** DCR is the product's
  happy path; requiring an admin for it would break self-service installs. What is admin-gated
  is *editing the registration afterwards*.
- `DELETE /api/v1/oauth-provider-clients/{id}` answers **409 while anything still
  authenticates at that authorization server**, naming both counts: the
  `oauth2_user_authorization` credentials issued against it and the OAuth2 MCP servers using
  them. Updating is still allowed with dependents — that is how a rotated provider secret gets
  in — and writes an audit event naming the changed fields and both dependent counts, never the
  secret value.
- A manually entered client's `authorization_server_url` must be the **bare origin**
  (`scheme://host[:port]`), because discovery looks the row up by the normalised origin of the
  resource metadata's `authorization_servers[0]`.

## Consequences

- An OAuth provider client is explicitly **not** per-tenant. It is shared infrastructure keyed
  by origin, and it is governed like shared infrastructure.
- An operator who needs a manual registration at a new origin must ask an admin. DCR covers
  the case where the provider supports it, which is most of them.
- This is distinct from an **OIDC identity provider**, which is the admin console's own SSO
  login source. The two were easy to confuse — they are both "an OAuth thing in Settings" — and
  the glossary now names them separately.
- Audit event names for these rows are written as `oauth_provider_…`, not serde's default
  `o_auth_provider_…`; rows already on disk under the old spelling still read back.
