# AgentCordon — domain glossary

The vocabulary this codebase uses, as the code uses it today. Every entry names the file or
module where the term lives, and calls out where the admin console or the CLI uses a different
word for the same thing. When your output names a domain concept — an issue title, a test name,
a refactor proposal — use the term as defined here.

Decisions that produced this shape are recorded in [`docs/adr/`](docs/adr/README.md).
`docs/system-architecture.md` describes the design; **the code wins where they differ**, and
this file is written from the code.

---

## The system

**Control plane** — the server: the admin API and console, the OAuth 2.0 authorization server,
the credential vault, the Cedar policy engine. One process, one SQLite database, default port
3140. Crate `agent-cordon-server` (`crates/server/`), binary `agent-cordon-server`.
*Also called* "the server" in the README, docs and code; `crates/server/src/routes/control_plane/`
is specifically the **broker-facing** subset of its routes (MCP sync and MCP authorize), not the
whole server.

**Broker** — the per-user daemon that holds a workspace's OAuth tokens, asks the server to vend
credentials, injects them into outgoing calls, and fronts MCP servers. It runs on the user's
machine and is the least trusted process in the system; it never holds a provider secret
(ADR-0006). Crate `agentcordon-broker` (`crates/broker/`), entry point
`crates/broker/src/daemon.rs`. *"Daemon" is used only for the broker, never for the server.*

**CLI** — the thin client an agent runs. It talks **only** to the broker, never to the server.
Crate `agentcordon-cli` (`crates/cli/`), binary **`agentcordon`** (no suffix).

**Core** — the shared library: storage and migrations, the Cedar policy engine, the key ring,
transforms, the wire types, the SSRF and URL-pattern checks. Crate `agent-cordon-core`
(`crates/core/`).

**Identity crate** — the key file format, the `sha256:` identity string, path-and-query
canonicalisation and the two signed payloads, shared by the CLI and the broker with frozen test
vectors. Crate `agentcordon-identity` (`crates/identity/`).

**Admin API** — the JSON API under `/api/v1`, the authority on what a caller may see and do
(`crates/server/src/routes/admin_api/`).

**Admin console** — the browser UI. Its pages are **shells**: a handler renders the user
context, a CSRF token and an entity id, and the page's script fetches everything from the admin
API (ADR-0011). Routes in `crates/server/src/routes/admin_ui/`, templates in
`crates/server/templates/`. *Also called* "the admin UI".

**Agent** — the AI process that runs `agentcordon`. It is not a domain entity: there is no
agent row, no agent id, and nothing authenticates as one. The entity is the **workspace**.

---

## Workspace and identity

**Workspace** — the unit of agent identity: one project directory, one Ed25519 keypair, one set
of grants. `crates/core/src/domain/workspace.rs` (`Workspace`, `WorkspaceId`). It replaced the
former `Agent`, `Device` and `WorkspaceIdentity` types, whose names survive only as type
aliases and dead audit columns.

**Workspace status** — the single lifecycle field. `WorkspaceStatus` in the same file,
serialized lowercase, with transitions as methods on `Workspace` rather than matches in
handlers:

| Value | Meaning | Transitions |
|---|---|---|
| `pending` | Registered, not yet approved. | `activate()` → active |
| `active` | May authenticate and act. | `disable()`, `revoke()` |
| `disabled` | Switched off by an operator; reversible. | `enable()`, `revoke()` |
| `revoked` | **Final.** Register a new identity instead. | none |

`enable`/`disable` are idempotent; `activate` and `revoke` are not. Any transition out of
`active` revokes the workspace's OAuth clients and every access and refresh token bound to it,
in one store transaction. *The `workspaces.enabled` column still exists and is kept in step by
migration 017, but the server no longer reads it.* *API/UI:* `WorkspaceResponse` returns
`computed_status` (the same string) and `enabled` (`status == active`) for readers of the old
two-field shape; the console shows a title-cased status pill and Enable / Disable / Revoke.

**Workspace identity** — the SHA-256 of the workspace's raw 32-byte Ed25519 public key, as 64
lowercase hex characters, prefixed `sha256:` when displayed. `crates/identity/src/key.rs`
(`IDENTITY_PREFIX`, `pk_hash_of`, `identity_string`).
*Names differ by surface:* the domain field and DB column are **`pk_hash`** (raw hex, no
prefix); the OAuth wire field is **`public_key_hash`** (prefix accepted and stripped); the
activation page labels it **"Device key:"**; `agentcordon init` and `status` print
**`Workspace identity: sha256:…`**; the generated `AGENTS.md` carries it as **`AC_IDENTITY`**,
and only that file does.

**Workspace key file** — `.agentcordon/workspace.key`, the 32-byte Ed25519 seed in hex, mode
0600 inside a 0700 directory, created with `O_EXCL`; `.agentcordon/workspace.pub` beside it.
`crates/identity/src/keyfile.rs`. Written by `agentcordon init`.

**Signed request** — every CLI→broker call carries `X-AC-PublicKey`, `X-AC-Timestamp`,
`X-AC-Nonce` and `X-AC-Signature` over `METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY`. The broker keeps
a bounded seen-set of `(key, nonce)` for the skew window, so a captured request is not
replayable. `crates/identity/src/request.rs`, `crates/broker/src/auth.rs`.

**Broker key pin** — the broker publishes `encryption_public_key` and `key_fingerprint` on
`GET /health`; `agentcordon register` writes `.agentcordon/broker.fingerprint` and every later
connection refuses a broker whose fingerprint differs. `crates/cli/src/pin.rs`.

**Device-code enrollment** — the one way a workspace comes into existence: RFC 8628 device
authorization grant. The broker requests a device code, the CLI prints a user code and an
activation URL, a signed-in human approves it in a browser, and the server provisions the
workspace and its OAuth client. `crates/server/src/routes/oauth/device.rs`,
`crates/server/src/services/device_codes.rs`, `crates/server/src/services/oauth.rs`.
*Four words for four parts of it, and they are not interchangeable:* **enrollment** is the docs'
word for the whole story (`docs/workspace-enrollment.md`); **registration** is what the CLI and
the broker do (`agentcordon register`, `POST /register`, `WorkspaceStatus::Pending`);
**activation** is the server-side approval surface (`/activate`, `Workspace::activate()`);
**device flow** / **device code** is the RFC 8628 machinery.

**Device code** — the row backing one enrollment attempt: `device_code`, `user_code`, and the
`pk_hash_prefill` / `workspace_name_prefill` the broker supplied. Status is one of `pending`,
`approved`, `denied`, `expired`, `consumed`. `crates/core/src/oauth2/types.rs`. The approving
human is shown the key hash the code will bind, and told when it already belongs to a workspace.

**Access token / refresh token** — opaque OAuth 2.0 tokens issued to a workspace's client and
bound to the workspace by id (migration 016), not by key hash. Refresh tokens carry a
`family_id` (migration 015); presenting an already-rotated token revokes the whole family and
writes an `oauth_refresh_token_reuse_detected` audit event. `crates/server/src/routes/oauth/token.rs`.
**There is no JWT anywhere a client can verify** — the ES256 issuer, its JWKS route and the
permissions-token endpoint were removed in 0.4.0.

---

## Credentials

**Credential** — a secret plus everything needed to inject it: a type, an optional transform,
an optional URL fence, metadata, a vault, tags, and an owner. Stored AES-256-GCM encrypted with
the credential's own UUID as associated data. `crates/core/src/domain/credential.rs`
(`StoredCredential`, `CredentialSummary`), service in `crates/server/src/services/credentials.rs`.

**Credential type** — a bare string, validated against `KNOWN_CREDENTIAL_TYPES`
(`crates/server/src/services/credentials.rs`). Six values; the type decides *where* the secret
goes and what else must be present:

| `credential_type` | What it holds | Placement | Console gloss |
|---|---|---|---|
| `generic` | any secret | whatever the transform does (default `bearer`) | *bearer token or any secret* |
| `api_key_header` | an API key | a custom header, named by `metadata.header_name` (required) | *custom header* |
| `api_key_query` | an API key | a query parameter, named by `metadata.param_name` (required) | *query parameter* |
| `aws` | an access key pair, optionally a session token | AWS SigV4 signature | *SigV4* |
| `oauth2_client_credentials` | a provider **client secret** | exchanged server-side, injected as a bearer | *application* |
| `oauth2_user_authorization` | a provider **refresh token** | exchanged server-side, injected as a bearer | *delegated* |

The two `oauth2_*` types are the **upstream OAuth** types: their stored secret never leaves the
server (ADR-0006). `oauth2_user_authorization` is the only type with rotation semantics and a
provider-client dependency, and it is created for you by an OAuth2 MCP install rather than
offered on the form. *UI/CLI:* the console and the CLI print the raw `credential_type` string —
the name **is** the label, with the gloss shown beside it.

**Transform** — how a credential's value becomes an outgoing header. Four built-ins, and only
four: `identity` (send unchanged), `bearer` (`Authorization: Bearer …`), `basic-auth`
(`Authorization: Basic base64(…)`) and `aws-sigv4`. `BUILTIN_TRANSFORM_NAMES` and
`resolve_transform` in `crates/core/src/transform/rhai_engine.rs`, implementations in
`crates/core/src/transform/builtins/`. *UI:* a Transform select appears **only for the `generic`
type**, offering `bearer` / `basic-auth` / `identity`; `aws-sigv4` is never selectable and is
inferred from the `aws` type. A `generic` credential is displayed as `generic · bearer`, because
the transform is the only thing distinguishing it from a basic-auth one.

**Transform script** — an optional Rhai script (`transform_script`, max 64 KiB) that overrides
the named transform. Sandboxed with tight operation, string and depth limits; error messages are
scrubbed of the secret. `crates/core/src/transform/`. Precedence: script, then name, then
`identity`.

**Vend** — the single operation that releases a credential to a broker: authorize, decrypt,
re-seal for that broker, audit. `POST /api/v1/credentials/{id}/vend` and
`POST /api/v1/credentials/vend-device/{name}`; `CredentialService` in
`crates/server/src/services/credentials.rs`. Distinct from **reveal**, which shows a secret to a
human in the console and is refused to a workspace by policy.

**Target-bound vend** — a vend that names where the credential is going: the request carries
`method` and `target_url`, the target goes into the Cedar context and the audit row, and the
response carries the credential's `allowed_url_pattern` back so the broker can check again
before injecting (ADR-0007). `crates/core/src/wire/credentials.rs`,
`crates/server/src/routes/admin_api/credentials/vend.rs`, `crates/broker/src/routes/proxy.rs`.

**`allowed_url_pattern`** — the URL fence on a credential, matched **structurally**: scheme,
host and port compared as parsed values, a `*` in the host standing for exactly one label, and a
glob over path and query only. `crates/core/src/proxy/url_match.rs` (`url_matches_pattern`,
`validate_url_pattern`, `URL_PATTERN_GRAMMAR`). Validated when written, enforced at vend time on
the server and again at injection time in the broker; a mismatch is **403 `url_pattern_denied`**
naming the pattern and the target, and writes a `credential_vend_denied` audit row.
*UI:* "Allowed URL pattern" on the credential form; *CLI:* `--allowed-url-pattern`, and the
success line says whether the credential is fenced or unrestricted.

**Envelope** — the ECIES-sealed payload a vend or a sync hands the broker:
P-256 + HKDF-SHA256 + AES-256-GCM, version 1, with associated data
`workspace_id||credential_id||vend_id||timestamp`. `crates/core/src/crypto/ecies/`,
`crates/server/src/crypto_helpers.rs`. The broker rejects an envelope whose associated data is
not the one it asked for.

**Secret history** — every rotation, restore and provider-driven refresh-token rotation archives
the previous ciphertext with its `key_version`. Restore is scoped to the credential in the URL.
`crates/server/src/routes/admin_api/credentials/history.rs`.

**Credential permission (grant)** — what a workspace may do with a credential, stored as a
generated Cedar policy row (see *generated grant row*). The permission names are `read`,
`write`, `delete`, `access`, `list`, `update` and **`delegated_use`**, which the templates map to
the Cedar action `vend_credential`. `crates/core/src/policy/templates.rs`.
*Note:* `delegated_use` is a **permission name, not a Cedar action** — it does not appear in the
schema. *UI:* "Delegated Use".

---

## Vaults

**Vault** — a named container for credentials, with an id and an owner. `id` is a UUID string,
`name` is a display label with no schema uniqueness, `owner_user_id` is `NULL` only for the
system default. `crates/core/src/domain/vault.rs`, `migrations/021_vaults_table.sql`, service in
`crates/server/src/services/vaults.rs`. A vault name is **unique per owner and free across
owners**, enforced in the service with a 409 (ADR-0002). Deleting a non-empty vault is a 409.
*UI:* **Settings → Vaults**; the credential form's field is just "Vault", a select submitting
`vault_id`. *CLI:* `agentcordon credentials` prints a `VAULT` column carrying the **name**.

**Default vault** — the one system vault, id `00000000-0000-0000-0000-000000000001`, name
`default`, no owner. It takes any credential whose creator names no vault, and cannot be
renamed, shared or deleted.

**Vault share** — a row granting one other user visibility of a vault's credentials. **`read` is
the only permission level**; `write` and `admin` are refused with 400 rather than stored as a
promise nothing keeps. Only the vault's **owner** (or root) may grant one — `manage_vaults` does
not (ADR-0003); a `manage_vaults` holder may read any share list and revoke any share.
`crates/server/src/services/vaults.rs`.

**Credential access** — how a caller reaches a credential in a response: `full` (their own, or
permitted by policy) or `shared_read` (visible only through a vault read share).
`CredentialAccess` in `crates/core/src/domain/credential.rs`. **Absent means the question was
not asked** and must be read as unrestricted, not restricted. A `shared_read` credential shows
name and detail only — no reveal, no edit, no delete, no re-share, no grant to a workspace.

---

## Authorization

**Cedar policy engine** — the authorization engine. Deny by default, namespace `AgentCordon`,
schema at `policies/schema.cedarschema.json`. `crates/core/src/policy/cedar/`. A permit
accompanied by any evaluation error is returned as **Forbid** with reason `evaluation_error`,
because Cedar would otherwise skip the failing policy and decide from the rest.

**Authz seam** — `Authz::authorize(caller, action, resource)` in `crates/server/src/authz/`, the
one way a route answers "is this allowed"; `Authz::request(...)` is the fluent form for routes
that add context claims, and `Authz::filter(...)` evaluates a list, silently dropping what is
denied and writing **one** audit row for the batch.

**Resource** — what an action is evaluated against: `PolicyResource::{Credential, WorkspaceResource,
McpServer, PolicyAdmin, System}` (`crates/core/src/policy/mod.rs`). `System` is for actions with
no concrete resource. Users, vaults, OIDC providers, OAuth provider clients and audit entries
have **no resource form yet** — `User` exists in the schema as a principal type only, and there
is no `Vault` type at all — so their per-entity rules live in their services; see ADR-0012.

**Action** — one of the 23 names in `policies/schema.cedarschema.json`, mirrored as constants in
`crates/core/src/policy/actions.rs`, the single source of truth (plus two back-compat aliases,
`MANAGE_AGENTS` and `MANAGE_DEVICES`, both equal to `MANAGE_WORKSPACES`).
The `manage_*` family is `manage_policies`, `manage_permissions`, `manage_users`,
`manage_workspaces`, `manage_consents`, `manage_oidc_providers`,
`manage_oauth_provider_clients`, `manage_vaults`, `manage_mcp_servers`, `manage_tags`. Only
`manage_workspaces` and `manage_mcp_servers` have both a `System` form (create, list, approve)
and a per-entity form. **A `manage_*` grant is oversight — read, audit, revoke — and is not a
substitute for ownership when an operation widens access** (ADR-0003).

**Policy** — an authored Cedar source stored as a row (`StoredPolicy`: name, description,
`cedar_policy` text, `enabled`, `is_system`). The database is the source of truth; the engine
caches the enabled set and every mutation reloads it. `crates/server/src/services/policies.rs`.
*UI:* the nav item and the pages say **"Policies"**; the route is **`/security`**, and
`/policies` redirects to it.

**Generated grant row** — a per-credential or per-MCP-server permission, written as a policy row
whose **name is prefixed `grant:` or `deny:`** (`is_generated_grant`). Its Cedar text comes from
`crates/core/src/policy/templates.rs` and always names a `Workspace` principal. These are
machinery, not authored policy, and the console's type filter separates them.

**Default policy** — the row named `default`, seeded from `policies/default.cedar` on first boot
only (when nothing is enabled). Its numbered rules are the shipped role model: 1a–1d for
workspaces, 2a–2g for users, 3a for MCP, 4a–4b forbids, 5a–5b for consents.
`policies/shared-tag-access.cedar` is a **sample**, not seeded and not loaded.

**Last-enabled-policy guard** — three rules that stop an install locking itself out
(`crates/server/src/services/policies.rs`): the `default` row can never be **deleted**; any
policy that is the last enabled one can be neither deleted nor disabled (409, with the
consequence spelled out); and **generated `grant:`/`deny:` rows do not count** as "another
policy", because a hundred grants and no authored policy refuses every operator and viewer
exactly as an empty set does.

**Role** — `admin`, `operator` or `viewer` (`UserRole` in `crates/core/src/domain/user.rs`).
*UI:* a lowercase pill next to the signed-in name.

**Root** — a **flag, not a role**: `users.is_root`. `User::is_admin()` is `is_root || role ==
Admin`, the one definition of administrative privilege in the server.

**Root bypass** — the policy engine returns Permit immediately, with reason **`root_bypass`**,
for a `PolicyPrincipal::User` whose `is_root` is set, before any entity is built or policy read
(`crates/core/src/policy/cedar/mod.rs`). It exists nowhere else — there are no inline
`role == Admin || is_root` checks — and it applies only to users, never to a workspace.
`policies/default.cedar` documents it and contains no root rule.

**Policy tester** — the console page (`/security/tester`) that evaluates a hypothetical
principal, action and resource and shows the contributing rules.

---

## MCP

**MCP server** — a registered upstream Model Context Protocol endpoint. `crates/core/src/domain/mcp.rs`
(`McpServer`, `McpServerId`), service in `crates/server/src/services/mcp_servers.rs`. Its
`transport` is `http` or `sse` — **there is no `stdio`** — and its `auth_method` is `none`,
`api_key` or `oauth2`. `enabled` is the documented immediate-revocation switch: a disabled
server drops out of broker sync and Cedar refuses its tool calls. Only `name` and `enabled` are
editable after creation. *UI:* the enabled state renders as **Active / Disabled**.
*Beware:* "server" means the control plane, an MCP server, or `PolicyServer` (a Cedar principal
for an OAuth client) depending on context.

**Binding** — the row in `mcp_server_workspaces` joining an MCP server to a workspace. It is the
**single source of truth for workspace↔MCP routing**; `mcp_servers.workspace_id` is a legacy
audit anchor, nullable, and left `None` on new records. `migrations/010_mcp_server_workspaces.sql`.
*Three names for it:* the API field is `installed_workspaces`, the route segment is
`/mcp-servers/{id}/workspaces`, the console column is **"Workspaces"**, the marketplace calls
creating one **"Install"**, and Settings prose calls it **sharing**.

**Tool** — `McpTool { name, description, input_schema }` (`crates/core/src/domain/mcp.rs`). The
MCP spec sends `inputSchema`; AgentCordon reads it through a serde alias and emits `input_schema`
on its own wire. **`discovered_tools`** holds the full metadata from a probe;
**`allowed_tools`** is the name-only projection written at the same moment.

**Tool discovery** — the server's `tools/list` probe against an upstream, run on install and
re-runnable from `POST /api/v1/mcp-servers/{id}/discover-tools`. It presents the credential the
broker would present, passes the resolving SSRF check, and a failure is reported in the install
response and audited as `mcp_tool_discovery_failed` rather than rolled back. *UI:* "Rediscover
tools".

**Marketplace template** — a catalogue entry describing an installable MCP server:
`key`, `name`, `upstream_url` and `auth_method` are required; `description`, `transport`,
`category`, `tags`, `icon` and `sort_order` default. `crates/server/src/templates/mcp.rs`; the
built-in catalogue is `data/mcp-templates/` embedded at compile time, merged by `key` with
`.json` files under `AGTCRDN_MCP_TEMPLATES_DIR` at startup (runtime wins; restart required).
*UI:* the page is `/mcp-servers/marketplace`, titled **"Add an MCP Server"** with the heading
**"Add a server"** — **the console never says "template" to the user**; a template already
installed shows a **Connected** pill.

**Sync** — the broker's periodic and on-demand read of the MCP servers and tools bound to its
workspace, optionally with ECIES credential envelopes.
`crates/server/src/routes/control_plane/workspace_sync.rs`, wire types in
`crates/core/src/wire/mcp.rs`, broker side in `crates/broker/src/mcp_sync.rs`. The interval is
`--mcp-sync-interval` / `AGTCRDN_MCP_SYNC_INTERVAL`, **default 60 seconds**; a sync also runs on
demand when the cache is cold, a credential is missing, or a cached upstream token is near
expiry. A per-server exchange failure lands as `credential_error` and the rest of the sync still
applies.

**MCP authorize** — `POST /api/v1/workspaces/mcp-authorize`, the server's permit/forbid answer
for one tool call. It returns a decision and a correlation id and **deliberately no policy
reasons**, so a workspace cannot enumerate the policy graph; the reasons are in the
`policy_evaluated` audit row.

---

## Upstream OAuth

**OAuth provider client** — AgentCordon's own registration at one upstream authorization server:
the `client_id` and encrypted `client_secret` used to obtain tokens for
`oauth2_user_authorization` credentials and OAuth2 MCP servers. **One row per authorization-server
origin, shared by every tenant there**, keyed on `authorization_server_url` normalised to a bare
`scheme://host[:port]`. `crates/core/src/domain/oauth_provider_client.rs`, service in
`crates/server/src/services/identity_providers.rs`. Created by **DCR** or entered **manually**
(`RegistrationSource::{Dcr, Manual}`). Managing one requires
`manage_oauth_provider_clients` (admins); listing stays on `manage_mcp_servers` (ADR-0004).
Deleting one with dependents is a 409 naming both counts. *UI:* **Settings → MCP Identity →
"OAuth Provider Clients"**.

**OIDC identity provider** — a completely different thing with a confusingly similar name: the
SSO source that signs a **human** into the admin console. `crates/core/src/domain/oidc.rs`,
routes under `/api/v1/oidc-providers` and `/api/v1/auth/oidc/`. Logins are bound to
`(provider, subject)` through `user_oidc_identities` (migration 014), never to a username claim.
*UI:* **Settings → Sign-in (SSO)**.
*In one line:* an **OIDC identity provider** signs a human **in**; an **OAuth provider client**
is who AgentCordon is when it goes **out**. They share `IdentityProviderService` for plumbing
reasons only.

**DCR** — Dynamic Client Registration, RFC 7591, with RFC 7592 for rotating a registration.
`crates/server/src/oauth_discovery/registration.rs`.

**OAuth discovery** — finding an MCP server's authorization server and endpoints: RFC 9728
protected-resource metadata (including the `resource_metadata` hint on a 401 challenge), then
RFC 8414 authorization-server metadata. `crates/server/src/oauth_discovery/`. **The origin rule:**
the authorization server may live anywhere the resource names, but its `issuer` must identify
the URL its metadata came from, and every endpoint it advertises must be same-origin with that
issuer.

**Upstream token** — a short-lived access token the **server** obtains from a provider by
running the `refresh_token` or `client_credentials` grant, and seals into an envelope with its
expiry. The refresh token and client secret that drive the exchange never leave the server
(ADR-0006). `crates/server/src/services/upstream_tokens.rs`,
`crates/core/src/oauth2/token_manager.rs` (`OAuth2TokenManager` — cache keyed by
`CredentialId`, single-flight per credential, 30-second expiry buffer).

---

## Keys and encryption

**Master secret** — `AGTCRDN_MASTER_SECRET`, the input from which the credential encryption key
is derived. `crates/core/src/crypto/master_secret.rs`. A secret with at least 32 bytes of
material at 4+ bits of entropy per byte is used directly; anything weaker is **stretched with
Argon2id** against a random 16-byte salt persisted at `<db dir>/.master-salt` (0600, created
once). An existing install with a weak secret keeps its legacy derivation and gets a startup
warning, so an upgrade never renders the store unreadable.

**Key ring** — the versioned encryptor. `AGTCRDN_MASTER_KEY_VERSION` names the current secret and
`AGTCRDN_PREVIOUS_MASTER_SECRET` loads the one it replaced for the rollover window; the ring
holds at most two keys and the server refuses to start if the two secrets are equal.
`crates/core/src/crypto/key_ring.rs`.

**Key version** — the `key_version` column on `credentials` and `credential_secret_history`:
**which master key sealed this row**. It was a re-encryption counter before 0.4.0, which is why
decrypt falls back across the ring for older rows. Migration 019 adds it to history and
backfills to 1.

**Re-seal** — `POST /api/v1/admin/rotate-key`: open every credential and every history row with
the key its version names and write it back under the current version, reporting counts and
errors. Idempotent, and the errors count is the gate that says the previous secret can be
dropped. Cedar action `rotate_encryption_key` on `System`; audit event **`master_key_resealed`**,
deliberately not `credential_secret_rotated` — no secret changed value, only the key it is
sealed under. *UI:* the admin-only **Master Key** card in Settings, button **"Re-seal
credentials"**. Runbook: `docs/master-key.md`.

---

## Guards

**SSRF guard** — one resolving check in front of every outbound call:
`validate_proxy_target_resolved` in `crates/core/src/proxy/url_safety.rs`. It refuses non-HTTP
schemes, `localhost` and any `*.localhost` name **before DNS**, and any address in the full
reserved set — IPv4 `0/8`, `10/8`, `100.64/10`, `127/8`, `169.254/16`, `172.16/12`, `192.0.0/24`,
the TEST-NETs, `198.18/15`, `224/4`, `240/4`; IPv6 unique-local, link-local, site-local and
multicast — unwrapping IPv4-mapped, NAT64 and 6to4 forms first. A hostname resolving to any
reserved address is refused. **It is all-or-nothing**: `AGTCRDN_PROXY_ALLOW_LOOPBACK` (and the
broker's `--proxy-allow-loopback`) turns the whole guard off, not just the loopback rule, and
there is no allow-list form. *Which process:* the **broker** enforces it for `proxy` and
`mcp-call`; the **server** enforces it for MCP tool discovery and OAuth discovery. A private
upstream needs the variable set on both. *Error code:* `ssrf_blocked` from the broker's MCP
route (naming the server), `bad_request` from the broker's proxy route; both carry the sentence
"Blocked by SSRF protection".

**Leak scanner** — scrubs every injected value out of what comes back, so an upstream that
echoes its own credential cannot put it in an agent's context.
`crates/core/src/proxy/leak_scanner.rs` (`LeakScanner`, `REDACTED = "[REDACTED]"`).
`injected_needles` is the **one place that decides what counts as secret**: the credential value,
the secret-named fields inside a JSON credential, every injected header except the publicly
derived `host`, `x-amz-date` and `x-amz-content-sha256`, and every injected query value —
anything unrecognised is treated as secret, so a custom transform fails safe. Each needle is
searched for in six forms: raw, standard and URL-safe base64 (padded and not), and
percent-encoding. Applied to proxy response bodies and headers and to MCP tool results and
discovery probes.

**Outbound client** — the dedicated client for proxied and MCP calls: never follows a 3xx (the
status and headers go back to the caller), times out, caps the response at 10 MiB, strips
hop-by-hop headers both ways, and forwards request bodies byte for byte.
`crates/broker/src/upstream.rs`.

**Single-instance guards** — the server takes an advisory `flock` on `<db path>.lock` before
migrations and holds it for the process lifetime (`AGTCRDN_REPLICA_MODE=unsafe-shared` opts
out); the broker takes one on `broker.lock` in its data directory. Two processes over one store
would each keep their own policy cache, rate limiters and event bus.

---

## Audit

**Audit event** — an append-only row describing something that happened.
`crates/core/src/domain/audit.rs` (`AuditEvent`, `AuditEventType` — around 90 variants,
serialized snake_case; the `OAuthProviderClient*` variants are explicitly renamed
`oauth_provider_…` because the default rule would split the acronym, with the old spelling kept
as a read alias).

**Decision** — `permit`, `forbid`, `error` or `not_applicable` (`AuditDecision`).

**Principal** — **not a stored field**. A row carries four actor columns (`workspace_id`,
`workspace_name`, `user_id`, `user_name`) and the principal is derived, once, by `eventPrincipal`
in `crates/server/templates/base.html`: **workspace name, else user name, else `system`**. The
workspace wins whenever there is one, because a vend the broker made on an agent's behalf names
the agent, not the human who happens to own the credential; a user is the principal for anything
done in the console; neither means the server acted on its own. Server-side, `extract_actor` in
`crates/server/src/authz/` fills the same four fields from `PolicyPrincipal::{User, Workspace,
Server}`. A guard test fails any template that re-derives the principal inline, because the
Dashboard and the Audit page once disagreed.

**Event label** — the console never prints a raw wire event name; `eventTypeLabel` in
`base.html` is the one derivation, and a guard test enforces it.

**`policy_evaluated`** — the audit row every `Authz` call writes: the action, the resource type
and id, the decision, the contributing Cedar policy ids as `decision_reason` (or `root_bypass`,
or `evaluation_error`), the correlation id and the actor. A `filter` call writes one row for the
batch, recording how many items were evaluated, permitted and denied and their ids, capped at
200 per outcome.

**Correlation id** — threads one request's decisions together across audit rows; it is what an
MCP authorize response returns in place of policy reasons.

---

## Words we avoid

| Don't say | Say | Why |
|---|---|---|
| agent, device (as an entity) | **workspace** | `Agent`/`Device` are back-compat aliases; the columns `agent_id`, `device_id` are dead. |
| gateway | **broker** | The crate was split into `broker` and `cli` in v0.3.0. |
| JWT, signed permissions token | **access token** | Tokens are opaque; the ES256 issuer and JWKS were removed. |
| vault (as a name string) | **vault id** | A vault is a row; the name is a display label (ADR-0002). |
| MCP OAuth app | **OAuth provider client** | Old Settings label, no longer in the UI. |
| Postgres, `AGTCRDN_DB_TYPE` | **SQLite**, `AGTCRDN_DB_PATH` | One backend; setting the old variables refuses boot (ADR-0001). |
| `mcp-serve`, stdio MCP | — | No such subcommand and no stdio transport. |
| "Security" (the nav item) | **Policies** | Only the URL says `/security`. |
| `delegated_use` (as an action) | `delegated_use` **permission**, `vend_credential` **action** | The permission name maps to the action. |
