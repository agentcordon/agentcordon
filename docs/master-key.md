> [Home](index.md) / Master Key

# Master Key

The **master key** is the root secret from which all server-side cryptographic keys are derived. It protects credentials at rest and signs identity tokens.

> [!CAUTION]
> The `.secret` file contains your root encryption key. Never commit it to version control. If lost, all encrypted credentials become unrecoverable.

---

**On this page:**
[Key Resolution](#key-resolution) · [Key Derivation](#key-derivation) · [Zeroization](#zeroization) · [Server Initialization](#server-initialization) · [Nonce Safety](#nonce-safety) · [Key Rotation](#key-rotation) · [Environment Variables](#environment-variables) · [Security Properties](#security-properties)

---

## Key Resolution

On startup, the server resolves the master secret via a **three-tier hierarchy** (`crates/server/src/config.rs`):

| Priority | Source | Details |
|:--------:|--------|---------|
| 1 (highest) | `AGTCRDN_MASTER_SECRET` env var | Must be at least 16 characters |
| 2 | `.secret` file | Read from `{AGTCRDN_DB_PATH}/../.secret` (must also be at least 16 characters) |
| 3 (fallback) | Auto-generated | 32 random bytes, base64url-encoded (43 chars, no padding), written to `.secret` with `0600` permissions |

> [!TIP]
> For production, set `AGTCRDN_MASTER_SECRET` via your secret manager (e.g., Vault, AWS Secrets Manager) rather than relying on the file-based fallback.

---

## Key Derivation

A single master secret produces **domain-separated keys** via **HKDF-SHA256** (`crates/core/src/crypto/key_derivation.rs`). The server derives three keys at startup; a fourth label is available as a library function:

| Derived Key | HKDF Info Label | Purpose | Used at startup |
|-------------|-----------------|---------|:---------------:|
| AES-256 Encryption Key | `agentcordon:encryption-v2` | Credential encryption at rest | Yes |
| ES256 JWT Signing Keypair | `agentcordon:jwt-es256-v1` | Workspace identity JWT signing (P-256/ECDSA) | Yes |
| Session Hash Key | `agentcordon:session-hash-v2` | HMAC-SHA256 session token hashing | Yes |
| Device ID | `agentcordon:device-id-v1` | Deterministic device UUID generation (library only) | No |

Each label is unique -- tests at `key_derivation.rs:304-352` verify no label collisions and confirm that every derivation function produces distinct output for the same (secret, salt) input.

### KDF Salt

The HKDF salt is resolved separately (`crates/server/src/config.rs`):

1. `AGTCRDN_KDF_SALT` env var (if set)
2. Auto-derived via HKDF-SHA256 on the master secret with label `agentcordon:default-kdf-salt-v1` (output is hex-encoded, 64 chars)

A legacy hardcoded default (`"agent-cordon-default-salt-change-me"`) is no longer used as a fallback. The constant is retained only for detection: if a database was initialized with the old default, `is_default_salt()` returns `true` and the server logs a startup warning recommending migration.

---

## Zeroization

All derived keys are wrapped in `Zeroizing<[u8; 32]>` from the `zeroize` crate. Memory is **automatically zeroed** when the key is dropped, preventing leakage in memory dumps.

---

## Server Initialization

At startup (`crates/server/src/main.rs`), the derived keys are initialized in this order:

```
AppConfig::from_env()
  ├── resolve_master_secret()      # env var / .secret file / auto-generate
  └── resolve KDF salt             # env var / auto-derive from master secret

init_crypto(&config)
  ├── derive_master_key()          # → AesGcmEncryptor (Arc-wrapped, immutable)
  ├── derive_jwt_signing_keypair() # → JwtIssuer (Arc-wrapped)
  └── derive_session_hash_key()    # → [u8; 32] copied into AppState
```

The `AppState` struct (`crates/server/src/state.rs`) holds the encryptor, JWT issuer, and session hash key as shared, immutable references. The intermediate `CryptoKeys` struct groups these three values before they are moved into `AppState`.

---

## Nonce Safety

The `AesGcmEncryptor` (`crates/core/src/crypto/aes_gcm.rs`) tracks an atomic 64-bit counter of encryptions:

| Threshold | Value | Behavior |
|-----------|:-----:|----------|
| Warning | 2^31 | Logs a one-time warning (fires exactly once, when the counter crosses the threshold) |
| Hard failure | 2^32 | Refuses further encryptions (`CryptoError::NonceExhaustion`) |

Each encryption generates a **random 12-byte nonce** via `OsRng`. The counter is a defense-in-depth measure against nonce reuse. The counter uses atomic `fetch_add` to prevent TOCTOU races in concurrent encryption, and is flushed to persistent storage every 100 encryptions.

---

## Key Rotation

The `POST /api/v1/admin/rotate-key` endpoint re-encrypts all credentials under the current encryption key with fresh nonces:

1. Every credential tracks a `key_version: i64` field
2. On rotation, each credential is decrypted with the current key and re-encrypted with the same key (generating a new random nonce)
3. The `key_version` is incremented on each credential, providing an audit trail of how many times it has been re-encrypted

This endpoint is intended to be called **after** the master secret has been changed externally (e.g., updating `AGTCRDN_MASTER_SECRET` and restarting the server). The typical rotation workflow is:

1. Set a new `AGTCRDN_MASTER_SECRET` value
2. Restart the server (which derives new encryption keys from the new secret)
3. Call `POST /api/v1/admin/rotate-key` to re-encrypt all credentials under the new key

Historical encrypted values are preserved in the `credential_secret_history` table.

> [!IMPORTANT]
> If the master secret is changed without re-encrypting credentials, existing credentials become undecryptable. Always run the rotate-key endpoint immediately after a secret change.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AGTCRDN_MASTER_SECRET` | Auto-generated | Master secret (min 16 chars) |
| `AGTCRDN_KDF_SALT` | Auto-derived from master secret | HKDF salt override |
| `AGTCRDN_DB_PATH` | `./data/agent-cordon.db` | Database location (`.secret` file stored in the same parent directory) |

---

## Security Properties

- **No secrets in logs** -- the master secret and KDF salt are both redacted in the `Debug` impl for `AppConfig`
- **Domain separation** -- distinct keys derived from one secret via unique HKDF info labels
- **Authenticated encryption** -- credential IDs are used as AAD (Additional Authenticated Data) to prevent credential swapping between rows
- **Counter-based nonce safety** -- atomic counter with hard failure at 2^32 encryptions prevents nonce reuse
- **File permissions** -- auto-generated `.secret` file is written with `0600` (owner read/write only)
- **Minimum secret length** -- enforced at 16 characters for both the env var and the `.secret` file

---

> **See also:** [Credential Encryption](credential-encryption.md) | [System Architecture](system-architecture.md)
