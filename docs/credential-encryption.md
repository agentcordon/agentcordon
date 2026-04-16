> [Home](index.md) > Credential Encryption

# Credential Encryption

Credentials in AgentCordon are **encrypted at rest** with AES-256-GCM and **vended to workspaces** via ECIES (Elliptic Curve Integrated Encryption Scheme). Agents never hold long-lived credentials -- they receive per-request, envelope-encrypted copies that only their broker's private key can decrypt.

---

**On this page:**
[Data Model](#credential-data-model) | [Encryption at Rest](#encryption-at-rest) | [Nonce Safety](#nonce-exhaustion-safety) | [ECIES Vending](#credential-vending-ecies) | [Credential Material](#credential-material) | [Transforms](#credential-transforms) | [Proxy Flow](#proxy-flow) | [Credential Types](#credential-types) | [Expiration & Rotation](#expiration-and-rotation) | [Audit Trail](#audit-trail)

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
| `vault` | `String` | Vault grouping (defaults to `"default"`) |
| `credential_type` | `String` | `"generic"`, `"aws"`, `"api_key_header"`, `"api_key_query"`, `"oauth2_client_credentials"` |
| `tags` | `Vec<String>` | User-defined tags for categorization and policy matching |
| `description` | `Option<String>` | Free-form description to help agents select the right credential |
| `target_identity` | `Option<String>` | Unique identifier of the credential's target identity (e.g., AWS role ARN) |
| `key_version` | `i64` | Tracks which encryption key version was used |

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
- **Counter persistence** -- flushed to storage every 100 encryptions (configurable via `FLUSH_INTERVAL`)

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

The transform engine (`crates/broker/src/credential_transform.rs`) injects credentials into HTTP requests based on type:

| Credential Type | Transform | HTTP Output |
|----------------|-----------|-------------|
| `bearer` / `generic` / `oauth2_client_credentials` / `oauth2_user_authorization` | Bearer token | `Authorization: Bearer {value}` |
| `basic` | Base64 encode (via `basic-auth` transform) | `Authorization: Basic {base64(value)}` |
| `aws` | AWS SigV4 (via `aws-sigv4` transform) | `Authorization` + `x-amz-date` + `x-amz-content-sha256` headers |
| `api_key_header` | Custom header | `{metadata.header_name}: {value}` |
| `api_key_query` | Query parameter | `?{metadata.param_name}={value}` |

If no `credential_type` is set, the transform defaults to `bearer`.

If a credential has a `transform_name` set, it overrides the type-based default. Custom Rhai transform scripts are also supported via the core transform engine (`crates/core/src/transform/rhai_engine.rs`).

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

> **SSRF Protection:** By default, loopback and private network URLs are blocked. Set `AGTCRDN_PROXY_ALLOW_LOOPBACK=true` for local development.

---

## Credential Types

### Generic
- **Field:** `secret_value: String`
- **Default transform:** `bearer`

### AWS
- **Fields:** `aws_access_key_id`, `aws_secret_access_key`, optional `aws_region`, `aws_service`
- **Default transform:** `aws-sigv4`
- **Auto-default `allowed_url_pattern`:** `https://*.amazonaws.com/*`

### OAuth2 Client Credentials
- **Fields:** `oauth2_client_id`, `oauth2_token_endpoint`, optional `oauth2_scopes`
- Validates token endpoint is HTTPS (except localhost in dev)
- Performs `client_credentials` grant at vend time

### API Key (Header)
- **Metadata:** `header_name` (required, e.g., `"X-Api-Key"`)
- Injects as custom header

### API Key (Query)
- **Metadata:** `param_name` (required, e.g., `"api_key"`)
- Appends as URL query parameter

---

## Expiration and Rotation

- **Expiration** -- optional `expires_at` field. Checked before vending -- expired credentials return `403` with an audit event.
- **Key rotation** -- `POST /api/v1/admin/rotate-key` re-encrypts all credentials under the current key with fresh nonces and incremented `key_version`. Requires admin user with Cedar `rotate_encryption_key` permission on the System resource. The response reports `re_encrypted_count`, `total_credentials`, and any `errors`.
- **Secret history** -- when a credential's secret value is changed, the previous encrypted value and nonce are stored in the `credential_secret_history` table for audit purposes (`crates/core/src/storage/traits/secret_history_store.rs`). Individual history entries can be retrieved by ID.

---

## Audit Trail

Every credential operation emits an audit event:

| Event | When |
|-------|------|
| `CredentialCreated` | Credential added |
| `CredentialStored` | Credential stored in vault |
| `CredentialVended` | Credential decrypted and sent to workspace |
| `CredentialVendDenied` | Cedar policy denied vending |
| `CredentialExpired` | Vend attempted on expired credential |
| `CredentialSecretViewed` | User reveals secret via admin UI |
| `CredentialSecretRotated` | Admin rotates encryption key |
| `CredentialSecretRestored` | Secret restored from history |

> Audit events include `workspace_id`, `credential_name`, `vend_id` (correlation), and decision reason -- but **never the secret value itself**.

---

> **See also:** [Master Key](master-key.md) | [Authorization & Cedar Policy](authorization-and-cedar-policy.md) | [CLI Reference](cli-reference.md)
