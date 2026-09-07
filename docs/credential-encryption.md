> [Home](index.md) > Credential Encryption

# Credential Encryption

Credentials in AgentCordon are **encrypted at rest** with AES-256-GCM and **vended to workspaces** via ECIES (Elliptic Curve Integrated Encryption Scheme). Agents never hold long-lived credentials -- they receive per-request, envelope-encrypted copies that only their broker's private key can decrypt.

---

**On this page:**
[Data Model](#credential-data-model) | [Vaults](#vaults) | [Encryption at Rest](#encryption-at-rest) | [Nonce Safety](#nonce-exhaustion-safety) | [ECIES Vending](#credential-vending-ecies) | [Credential Material](#credential-material) | [Transforms](#credential-transforms) | [Proxy Flow](#proxy-flow) | [Credential Types](#credential-types) | [Expiration & Rotation](#expiration-and-rotation) | [Audit Trail](#audit-trail)

---

## Credential Data Model

The `StoredCredential` struct (`crates/core/src/domain/credential.rs`) stores:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `CredentialId(Uuid)` | Unique credential identifier |
| `name` | `String` | Human-readable name |
| `service` | `String` | Target service name |
| `encrypted_value` | `Vec<u8>` | AES-256-GCM ciphertext |
| `nonce` | `Vec<u8>` | 12-byte AES-GCM initialization vector |
| `scopes` | `Vec<String>` | Access scopes |
| `metadata` | `serde_json::Value` | Arbitrary JSON metadata |
| `created_by` | `Option<AgentId>` | Agent that created this credential (legacy/agent-created) |
| `created_by_user` | `Option<UserId>` | User that created this credential |
| `created_at` | `DateTime<Utc>` | Creation timestamp |
| `updated_at` | `DateTime<Utc>` | Last update timestamp |
| `allowed_url_pattern` | `Option<String>` | SSRF mitigation -- restricts which URLs this credential can be used against |
| `expires_at` | `Option<DateTime<Utc>>` | Optional TTL |
| `transform_script` | `Option<String>` | Custom Rhai script for credential injection |
| `transform_name` | `Option<String>` | Built-in transform name override |
| `vault_id` | `String` | The id of the [vault](#vaults) this credential lives in. Omitted on create means the system default vault, `00000000-0000-0000-0000-000000000001` |
| `vault_name` | `String` | The vault's display name, read back with the row. Denormalized for display only -- `vault_id` is what names the vault |
| `credential_type` | `String` | One of `"generic"`, `"aws"`, `"api_key_header"`, `"api_key_query"`, `"oauth2_client_credentials"`, `"oauth2_user_authorization"` (`KNOWN_CREDENTIAL_TYPES`, `crates/server/src/services/credentials.rs`). Anything else is a `400` from `POST /api/v1/credentials`. |
| `tags` | `Vec<String>` | User-defined tags for categorization and policy matching |
| `description` | `Option<String>` | Free-form description to help agents select the right credential |
| `target_identity` | `Option<String>` | Unique identifier of the credential's target identity (e.g., AWS role ARN) |
| `key_version` | `i64` | Tracks which encryption key version was used |

---

## Vaults

A **vault** groups credentials. It is a row -- an id, a display name and an owner -- not a
string on the credential: the id is the identity and the name is only a label.

**A display name is unique per owner, and free across owners.** Two users may each call a
vault `team` without sharing anything or learning of each other. Your own second `team` is
refused: `POST /api/v1/vaults` and the rename answer `409` with *"you already have a vault
named 'team'; pick another name or rename the existing one"*. The name is all the credential
form's vault picker shows, so two of your own vaults called `team` would make it a guess.
The rule is enforced in the service, not by a unique index -- installs predating it may
already hold duplicates, which are left alone.

One vault is special. The **system default vault** has the fixed id
`00000000-0000-0000-0000-000000000001`, has no owner, takes every credential whose creator
named no vault, and cannot be renamed, shared or deleted.

| Field | Type | Description |
|-------|------|-------------|
| `id` | `String` (UUID) | What names the vault everywhere |
| `name` | `String` | Display name, 1-100 characters. Unique among the vaults you own; free across owners |
| `owner_user_id` | `String \| null` | The owner; `null` for the system default |
| `is_default` | `bool` | `true` for the one vault everybody uses |
| `shared_by` | `String` | Present only when you see this vault through a share: the username of whoever shared it |
| `permission` | `String` | Present only on a shared vault; always `read` |

### Managing vaults in the admin UI

Vaults live on **Settings -> Vaults**, which every role can reach.

| To | Do this |
|----|---------|
| Create a vault | Type a name in **New vault name** and press **Create vault**. Or, while storing a credential, press **New vault** next to the Vault select on **Credentials -> Add Credential** |
| Put a credential in a vault | Pick it from the **Vault** select on **Credentials -> Add Credential**. Leave it on `default` if you are not sure |
| Move a credential | Open the credential's page at `/credentials/{id}`, press **Edit**, choose another vault from the **Vault** select, then **Save** |
| See what is in a vault | **Credentials** -> the **Vault:** select in the filter row above the table |
| Rename a vault | **Rename** on its row in Settings -> Vaults |
| Share a vault, read-only | **Share** on its row, pick the user, press **Share**. The user must already exist -- an administrator creates one with **Add User** in the **User Management** section of Settings, which opens the new-user form at `/settings/users/new` |
| Stop sharing | **Revoke** next to that user in the vault's share list |
| Delete a vault | **Delete**, in the row's overflow menu (the **&hellip;** button at the end of the row). It is disabled while the vault still holds credentials, and says so -- move them out first |

### Who may do what

| Act | Who |
|-----|-----|
| Create a vault | Anyone the policy engine lets create credentials (admins and operators; not viewers) |
| Rename, delete | The vault's owner, or root |
| **Share** | The vault's owner, or root -- **at any role**, and nobody else. An administrator cannot share a vault they do not own: that would hand another user's credentials on |
| Read any vault's share list, and **revoke** any share | The owner, or a holder of `manage_vaults` (admins, by the default policy) |
| See a shared vault's credentials | The user it was shared with |

A `read` share makes the vault's credentials **visible** in the recipient's credential list
and detail -- name, service, type, tags. It grants nothing else: no secret reveal, no edit,
no delete, no re-share, and no vending the credential to a workspace.

### Vault API

| Route | Does |
|-------|------|
| `POST /api/v1/vaults` `{name}` | Create a vault owned by the caller. `409` if the caller already owns a vault with that name |
| `GET /api/v1/vaults` | The caller's own vaults, the system default, the vaults shared with them (each naming `shared_by`), and -- for a `manage_vaults` holder -- every vault |
| `PATCH /api/v1/vaults/{id}` `{name}` | Rename. Owner or root; `403` on the default vault, `409` on a name the owner already uses |
| `DELETE /api/v1/vaults/{id}` | Delete an empty vault. `409` while it still holds credentials -- deleting would take them with it, which is never what "remove this grouping" meant |
| `GET /api/v1/vaults/{id}/credentials` | The credentials in this vault the caller may see |
| `POST /api/v1/vaults/{id}/shares` `{user_id, permission: "read"}` | Share. Owner or root only; `read` is the only level -- `write` and `admin` answer `400` |
| `GET /api/v1/vaults/{id}/shares` | The share list. Owner, root, or a `manage_vaults` holder; a signed-in stranger gets `403`, not the roster |
| `DELETE /api/v1/vaults/{id}/shares/{user_id}` | Revoke |

Placing a credential in a vault you do not own is refused:

```bash
# In a vault of your own, by id.
curl -X POST https://cordon.example.com/api/v1/credentials \
  -H 'Content-Type: application/json' \
  -d '{"name":"github-token","service":"github","secret_value":"ghp_...",
       "vault_id":"6f1c8d2e-9a3b-4c5d-8e7f-0a1b2c3d4e5f"}'

# Omit vault_id and the credential lands in the system default vault.
curl -X POST https://cordon.example.com/api/v1/credentials \
  -H 'Content-Type: application/json' \
  -d '{"name":"github-token","service":"github","secret_value":"ghp_..."}'

# Move it later.
curl -X PUT https://cordon.example.com/api/v1/credentials/{id} \
  -H 'Content-Type: application/json' \
  -d '{"vault_id":"00000000-0000-0000-0000-000000000001"}'
```

Every vault state change emits an audit event naming the vault by id:
`vault_created`, `vault_renamed`, `vault_deleted`, `vault_shared`,
`vault_unshared`.

---

## Encryption at Rest

When a credential is created, the secret value is encrypted in the route handler (crypto operations remain in route handlers, not the service layer):

```
encrypt_secret(encryptor, secret, credential_id):
  1. plaintext  = secret.as_bytes()
  2. aad        = credential_id.to_string().as_bytes()   # prevents credential swapping
  3. nonce      = OsRng.fill_bytes(12)                   # random 12-byte IV
  4. ciphertext = AES-256-GCM.encrypt(key, nonce, plaintext, aad)
  5. Store (ciphertext, nonce, key_version) in database
```

The encryption key is derived from the master secret via HKDF-SHA256 with info label `agentcordon:encryption-v2` (see `crates/core/src/crypto/key_derivation.rs`):

```
derive_master_key(master_secret, salt):
  hk       = HKDF-SHA256(ikm: master_secret, salt: salt)
  key[32]  = hk.expand(info: "agentcordon:encryption-v2")
```

The master secret is resolved via a three-tier fallback (`crates/server/src/config.rs`):
1. `AGTCRDN_MASTER_SECRET` environment variable (must be >= 16 characters)
2. Persisted `.secret` file next to the database
3. Auto-generated 32-byte random secret (base64url-encoded, persisted to `.secret`)

The KDF salt is resolved as:
1. `AGTCRDN_KDF_SALT` environment variable
2. Derived from the master secret via `HKDF-SHA256(ikm: master_secret, info: "agentcordon:default-kdf-salt-v1")` (see `crates/core/src/crypto/kdf.rs`)

The derived key is wrapped in `Zeroizing<[u8; 32]>` and automatically zeroed on drop.

> **AAD (Additional Authenticated Data):** The credential UUID is bound to the ciphertext. Decryption with a different credential ID fails -- this prevents credential swapping attacks where an attacker substitutes one encrypted blob for another.

---

## Nonce Exhaustion Safety

The `AesGcmEncryptor` (`crates/core/src/crypto/aes_gcm.rs`) tracks the number of encryptions performed with each key using an atomic counter:

- **Warning at 2^31 encryptions** -- logs a recommendation to rotate the key
- **Hard failure at 2^32 encryptions** -- refuses to encrypt, returns `CryptoError::NonceExhaustion`

This guards against the theoretical nonce collision risk inherent in random 96-bit nonces with AES-GCM. Key rotation (see below) resets the counter.

---

## Credential Vending (ECIES)

When a workspace requests a credential, the server **decrypts** it (AES-GCM) and **re-encrypts** it using the broker's P-256 public key via ECIES. Credentials are never transmitted in plaintext -- only the broker's private key can decrypt them.

### Construction: ECIES-P256-HKDF-SHA256-AES256GCM

**Server-side re-encryption** (`crates/server/src/crypto_helpers.rs`, using `crates/core/src/crypto/ecies/mod.rs`):

```
reencrypt_credential_for_device(encryptor, cred, workspace_id, broker_pub_key):
  1. AES-GCM decrypt credential with server master key + credential_id AAD
  2. Wrap plaintext in JSON: {"value": "<secret>"}
  3. Generate ephemeral P-256 keypair (consumed by ECDH)
  4. shared_secret = ECDH(ephemeral_private, broker_public_key)
  5. derived_key   = HKDF-SHA256(shared_secret, salt: empty, info: "agentcordon:ecies-credential-v1")
  6. aad           = workspace_id || "||" || credential_id || "||" || vend_id || "||" || timestamp
  7. ciphertext    = AES-256-GCM.encrypt(derived_key, random_nonce, credential_json, aad)
  8. Return VendEnvelopeResponse {
       version: 0x01,
       ephemeral_public_key: base64(uncompressed P-256, 65 bytes),
       ciphertext: base64(encrypted material),
       nonce: base64(12 random bytes),
       aad: base64(bound identifiers)
     }
```

Note: All base64 encoding in the ECIES envelope uses **standard Base64** (RFC 4648 Section 4, with `+` and `/`), not base64url.

**Broker-side decryption** (`crates/broker/src/vend.rs`):

```
decrypt_vend_envelope(envelope, broker_private_key):
  1. Base64-decode ephemeral_public_key, ciphertext, nonce, aad from envelope
  2. shared_secret = ECDH(broker_private_key, ephemeral_public)
  3. derived_key   = HKDF-SHA256(shared_secret, salt: empty, info: "agentcordon:ecies-credential-v1")
  4. plaintext     = AES-256-GCM.decrypt(derived_key, nonce, ciphertext, aad)
  5. Parse JSON -> VendedCredential { credential_type, value, username, metadata }
```

> **Zeroization:** Ephemeral secrets, shared secrets, and derived keys are all wrapped in `Zeroizing<T>` and auto-zeroed on drop.

---

## Credential Material

After decryption, the broker receives a `VendedCredential` struct (`crates/broker/src/vend.rs`):

```rust
pub struct VendedCredential {
    pub credential_type: Option<String>,       // "bearer", "basic", "api_key_header", etc.
    pub value: String,                         // The secret value
    pub username: Option<String>,              // For basic auth
    pub metadata: HashMap<String, String>,     // e.g., header_name, param_name
}
```

This is then mapped to a `CredentialMaterial` struct (`crates/broker/src/credential_transform.rs`) for transform application. The `CredentialMaterial` Debug impl redacts the `value` field to prevent secret leakage to logs.

---

## Credential Transforms

The transform engine (`crates/broker/src/credential_transform.rs`) injects credentials into
HTTP requests. **What happens** follows from the credential's type; **what you may set** in
`transform_name` is a separate, much shorter list. Keep the two apart -- the type names and
the transform names overlap only partly, and picking a type name as a `transform_name` is a
400.

### What each type does

| Credential Type | Injection | HTTP Output |
|----------------|-----------|-------------|
| `generic` | Bearer token (the `bearer` transform) | `Authorization: Bearer {value}` |
| `oauth2_client_credentials` / `oauth2_user_authorization` | Bearer token — the value is the short-lived upstream access token the **server** obtained; the refresh token and client secret never reach the broker | `Authorization: Bearer {value}` |
| `aws` | AWS SigV4 (the `aws-sigv4` transform) | `Authorization` + `x-amz-date` headers; `x-amz-content-sha256` for S3-family services; `x-amz-security-token` when a session token is present |
| `api_key_header` | Custom header — a property of the **type**, not a transform | `{metadata.header_name}: {value}` |
| `api_key_query` | Query parameter — a property of the **type**, not a transform | `?{metadata.param_name}={value}` |

If no `credential_type` is set, the injection defaults to `bearer`.

### What `transform_name` may be set to

There are exactly four built-in transforms. Any other value is refused at create and update
time with `unknown transform_name '<name>'; expected one of: identity, basic-auth, bearer,
aws-sigv4`.

| `transform_name` | Effect | Set it when |
|------------------|--------|-------------|
| `bearer` | `Authorization: Bearer {value}` | The default for `generic`; setting it is explicit rather than necessary |
| `basic-auth` | `Authorization: Basic {base64(value)}` | The upstream wants HTTP Basic. Store `user:password` as the secret |
| `identity` | The value is passed through untouched | A transform script or the upstream does the framing |
| `aws-sigv4` | AWS SigV4 signing | Implied by the `aws` type; you never need to name it |

**There is no custom-header or query-parameter transform.** Those placements come from the
`api_key_header` and `api_key_query` **types**, which carry the name in
`metadata.header_name` / `metadata.param_name`.

Set it in the admin UI under **Credentials -> Add Credential -> Transform** (offered for the
`generic` type, which is the only type with a choice to make) or on **Edit** of an existing
`generic` credential; over the API it is the `transform_name` field of
`POST`/`PUT /api/v1/credentials`.

Custom Rhai transform scripts are also supported via the core transform engine
(`crates/core/src/transform/rhai_engine.rs`); a `transform_name` overrides the type-based
default, and a `transform_script` overrides both.

---

## Proxy Flow

The broker's proxy endpoint (`crates/broker/src/routes/proxy.rs`) orchestrates credential injection:

```
POST /proxy  (broker endpoint)

1. Authenticate       -> workspace auth check
2. Scope check        -> verify workspace has required scope
3. Vend credential    -> POST /api/v1/credentials/vend/{credential_name} (to server)
4. ECIES decrypt      -> VendedCredential { type: "bearer", value: "ghp_..." }
5. SSRF validation    -> validate_proxy_target_resolved(url)
6. Apply transform    -> Authorization: Bearer ghp_...
7. Upstream request   -> e.g., GET https://api.github.com/user
8. Return response    -> status, headers, body
```

> **SSRF Protection:** By default every loopback, private and reserved address is blocked, and the check runs against the **resolved** address, not just the URL text. `AGTCRDN_PROXY_ALLOW_LOOPBACK=true` does not narrow that rule — it switches the guard off entirely, making RFC 1918, CGNAT, link-local, 0/8, 192.0.0/24, 198.18/15, the TEST-NETs, multicast, 240/4, NAT64 and 6to4 all reachable. Development only.

---

## Credential Types

`credential_type` is one of six values. Any other value is rejected with `400 unknown
credential_type`.

### Generic

- **Field:** `secret_value: String`
- **Default transform:** `bearer`

### AWS

- **Fields:** `aws_access_key_id`, `aws_secret_access_key`, `aws_region`, `aws_service`
  (or a `secret_value` holding the equivalent JSON: `access_key_id`, `secret_access_key`,
  and optionally `region`, `service`, `session_token`)
- **Default transform:** `aws-sigv4`
- **Auto-default `allowed_url_pattern`:** `https://**.amazonaws.com/*` (`**` is one or more DNS
  labels, so it covers both `sts.amazonaws.com` and `ssm.us-east-1.amazonaws.com`; a single `*`
  covers only the first, because it stands for exactly one label)

> [!IMPORTANT]
> **`aws_region` and `aws_service` are only optional for `**.amazonaws.com` targets.** The
> signer infers them from the hostname (`infer_aws_region_service`,
> `crates/core/src/transform/builtins/aws_sigv4.rs`) and that inference works only when the
> target host ends in `.amazonaws.com`. Against a VPC endpoint, an S3-compatible store,
> LocalStack, or a gateway behind a custom domain, a credential stored without both fields
> fails at **proxy** time, not at create time. Fill both in whenever you also widen
> `allowed_url_pattern` past `https://**.amazonaws.com/*`.

A credential carrying `session_token` (or `aws_session_token`) — STS or assumed-role keys —
is signed with `x-amz-security-token`. `x-amz-content-sha256` is sent for S3-family services
only, which is why a correct `execute-api` request does not carry it.

### API Key (Header)

- **`credential_type`:** `api_key_header`
- **Field:** `secret_value` -- the key itself
- **Metadata:** `header_name`, **required and non-empty** (e.g. `"X-Api-Key"`)
- Injects as a custom request header: `{metadata.header_name}: {value}`

### API Key (Query)

- **`credential_type`:** `api_key_query`
- **Field:** `secret_value` -- the key itself
- **Metadata:** `param_name`, **required and non-empty** (e.g. `"api_key"`)
- Appends to the target URL: `?{metadata.param_name}={value}`

Both are creatable through `POST /api/v1/credentials` and through the admin UI's credential
form. The metadata key is validated at create time -- `POST` without it answers
`400 credential_type 'api_key_header' requires a non-empty metadata.header_name` rather than
letting the broker discover at first call that it has nothing to name the header with.

```bash
curl -X POST "$S/api/v1/credentials" \
  -H "Content-Type: application/json" \
  -H "Cookie: $COOKIE" -H "X-CSRF-Token: $CSRF" \
  -d '{
    "name": "acme-api-key",
    "service": "acme",
    "credential_type": "api_key_header",
    "secret_value": "sk-...",
    "metadata": { "header_name": "X-API-Key" },
    "allowed_url_pattern": "https://api.acme.example/*"
  }'
```

Only the string-valued entries of `metadata` travel to the broker in the vend envelope, so
`header_name` and `param_name` must be strings.

> **Integrating an MCP server that needs a custom header.** Create the `api_key_header`
> credential first, then install the MCP from the marketplace choosing **Use existing
> credential** and picking it (API: `POST /api/v1/mcp-servers/provision` with
> `credential_id`). Provisioning a marketplace `api_key` template by *pasting a raw secret*
> creates a `generic` credential and injects `Authorization: Bearer <key>`; that is the
> right shape for most vendors and the wrong one for an upstream that wants
> `X-API-Key`.

### OAuth2 Client Credentials

An **application** credential: AgentCordon holds a client id and client secret and exchanges
them for an access token itself.

- **`credential_type`:** `oauth2_client_credentials`
- **Stored secret:** the client secret. It is never returned by any API response.
- **Metadata:** `oauth2_token_endpoint` (required), `oauth2_client_id` (required),
  `oauth2_scopes` (optional, space-delimited)
- **Grant:** the **server** runs the `client_credentials` grant at vend time and at MCP sync
  time and seals only the resulting short-lived access token into the envelope. The broker
  never sees the client secret and never calls a token endpoint.
- **Injection:** `Authorization: Bearer <access_token>`

> [!IMPORTANT]
> **The token endpoint must be HTTPS, with exactly three exceptions.** `http://` is accepted
> only when the host string is literally `localhost`, `127.0.0.1` or `::1`
> (`crates/server/src/routes/admin_api/credentials/create.rs`). A provider on a private
> network, a Docker service name, or any other internal hostname over plain HTTP is refused
> at create time with `oauth2_token_endpoint must use HTTPS`, and the message does not
> mention that a loopback exemption exists. For a development provider, reach it on
> loopback from the server's own network namespace, or give it a certificate.
>
> **Under Docker, that means running the provider in the server's network namespace** --
> not on the same bridge network. `http://idp:9400`, the shape a Docker network invites, is
> a hostname and is refused; the exemption is evaluated from inside the server's own
> namespace, so the provider has to *be* `127.0.0.1` there:
>
> ```bash
> docker run -d --name idp --network "container:agentcordon" my-idp
> # token endpoint: http://127.0.0.1:9400/token
> ```
>
> `--network container:<server>` gives the two containers one network stack, so the
> provider's port is literally loopback to the server and the check passes.
> `uat/oauth-topology.sh` starts its mock provider exactly this way.

### OAuth2 User Authorization (delegated)

A **delegated** credential: a human consented at the provider in a browser, and AgentCordon
holds the resulting refresh token on their behalf. This is what every OAuth2 MCP install
creates, and it is the only credential type with rotation semantics and a dependency on a
separate provider-client row.

- **`credential_type`:** `oauth2_user_authorization`
- **Stored secret:** the **refresh token**. Never returned by any API response.
- **Metadata:** `oauth2_token_url` (the provider's token endpoint), `oauth2_client_id`,
  `authorization_server_url` (the normalised `scheme://host[:port]` origin of the
  authorization server), `template_key` (the marketplace template it came from)
- **Client secret:** *not* on this credential. It lives on an `oauth_provider_clients` row
  keyed by `authorization_server_url`, so every credential obtained from one authorization
  server shares one client registration. See
  [Granting MCP Server Access -- OAuth provider clients](granting-mcp-server-access.md#oauth-provider-clients).
- **Grant:** the **server** runs the `refresh_token` grant and seals only the resulting
  access token and its `expires_at` into the envelope.
- **Rotation:** a provider that rotates the refresh token has the new value persisted
  server-side inside the same transaction, with a `credential_secret_history` row and a
  `CredentialSecretRotated` / `oauth2_refresh_token_rotated` audit event. If that persist
  fails the request fails rather than handing out a token whose successor was lost.
- **`allowed_url_pattern`:** defaulted to the MCP template's `upstream_url` plus `*`.
- **Injection:** `Authorization: Bearer <access_token>`

> **Metadata key asymmetry, worth knowing before you read a row:**
> `oauth2_client_credentials` stores its endpoint under **`oauth2_token_endpoint`**;
> `oauth2_user_authorization` stores it under **`oauth2_token_url`**.

## Expiration and Rotation

- **Expiration** -- optional `expires_at` field. Checked before vending -- expired credentials return `403` with an audit event.
- **Key rotation** -- `POST /api/v1/admin/rotate-key` re-encrypts all credentials under the current key with fresh nonces and incremented `key_version`. Requires admin user with Cedar `rotate_encryption_key` permission on the System resource. The response reports `re_encrypted_count`, `total_credentials`, and any `errors`.
- **Secret history** -- when a credential's secret value is changed, the previous encrypted value and nonce are stored in the `credential_secret_history` table for audit purposes (`crates/core/src/storage/traits/secret_history_store.rs`). Individual history entries can be retrieved by ID.

---

## Audit Trail

Every credential operation emits an audit event. The name below is the
`event_type` string `GET /api/v1/audit` returns and the value an
`event_type=` filter takes -- write it exactly as printed:

| Event | When |
|-------|------|
| `credential_created` | Credential added |
| `credential_stored` | Credential stored in vault |
| `credential_vended` | Credential decrypted and sent to workspace |
| `credential_vend_denied` | Cedar policy denied vending |
| `credential_expired` | Vend attempted on expired credential |
| `credential_secret_viewed` | User reveals secret via admin UI |
| `credential_secret_rotated` | The credential's secret was replaced (a rotation, or a provider-rotated refresh token) |
| `credential_secret_restored` | Secret restored from history |
| `master_key_resealed` | `POST /api/v1/admin/rotate-key` re-sealed every credential and history row under the current master-key version. No secret changed value; the row carries `key_version`, `re_encrypted_count`, `history_re_encrypted_count` and `error_count`, and its resource is `system`. See [Master Key](master-key.md#post-apiv1adminrotate-key) |

The OAuth provider client events are `oauth_provider_client_created`,
`oauth_provider_client_updated`, `oauth_provider_client_deleted`,
`oauth_provider_client_rotated` and `oauth_provider_discovery_failed`. Rows
written before v0.4.0 carry the older `o_auth_provider_…` spelling on disk; the
server reads both and always writes the name above.

> Audit events include `workspace_id`, `credential_name`, `vend_id` (correlation), and decision reason -- but **never the secret value itself**.

---

> **See also:** [Master Key](master-key.md) | [Authorization & Cedar Policy](authorization-and-cedar-policy.md) | [CLI Reference](cli-reference.md)
