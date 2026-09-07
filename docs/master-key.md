> [Home](index.md) / Master Key

# Master Key

The **master key** is the root secret from which all server-side cryptographic keys are derived. It protects credentials at rest and hashes session tokens.

> [!CAUTION]
> The `.secret` file contains your root encryption key. Never commit it to version control. If lost, all encrypted credentials become unrecoverable.

---

**On this page:**
[Key Resolution](#key-resolution) · [Secret Strength and Stretching](#secret-strength-and-stretching) · [Key Derivation](#key-derivation) · [Zeroization](#zeroization) · [Server Initialization](#server-initialization) · [Nonce Safety](#nonce-safety) · [Key Rotation](#key-rotation) · [Issuing the call](#issuing-the-call) · [Replica Guard](#replica-guard) · [Environment Variables](#environment-variables) · [Security Properties](#security-properties)

---

## Key Resolution

On startup, the server resolves the master secret via a **three-tier hierarchy** (`crates/server/src/config.rs`):

| Priority | Source | Details |
|:--------:|--------|---------|
| 1 (highest) | `AGTCRDN_MASTER_SECRET` env var | Must be at least 16 characters |
| 2 | `.secret` file | Read from `{AGTCRDN_DB_PATH}/../.secret` (must also be at least 16 characters) |
| 3 (fallback) | Auto-generated | 32 random bytes, hex-encoded (64 chars), written to `.secret` with `0600` permissions |

> [!TIP]
> For production, set `AGTCRDN_MASTER_SECRET` via your secret manager (e.g., Vault, AWS Secrets Manager) rather than relying on the file-based fallback.

---

## Secret Strength and Stretching

HKDF is a key *derivation* function, not a password hash: it spreads the entropy of its input, it does not add any. A passphrase fed straight into HKDF produces an encryption key exactly as guessable as the passphrase. So every master secret passes through `crates/core/src/crypto/master_secret.rs` before derivation.

### The strength rule

A secret is **strong** when it carries **at least 32 bytes of material with at least 4 bits of Shannon entropy per byte**, where the material is whichever of these the secret plausibly is:

| Form | Recognised as | Example |
|------|---------------|---------|
| 64+ hex characters | its hex decoding | `5a2f8c1d...` (64 chars) |
| base64 / base64url of 32+ bytes | its base64 decoding | 43-char base64url (what versions before v0.3.4 auto-generated) |
| anything else, 32+ characters | its raw UTF-8 bytes | a 40-character random ASCII string |

A decoding only counts when it yields 32 bytes or more; otherwise the raw text is judged. The entropy floor is what stops a long but repetitive string (43 `a`s decodes as valid base64 into 32 bytes) from passing. 32 random bytes score about 4.9 bits per byte; an English passphrase scores under 4.

A strong secret feeds HKDF unchanged, exactly as before.

### Stretching a weak secret

Anything else is **weak** and is stretched with **Argon2id** before HKDF:

```
Argon2id(secret, salt = <db dir>/.master-salt, m/t/p from AGTCRDN_ARGON2_*) -> 32 bytes -> hex -> HKDF
```

The salt is 16 random bytes, created once and written to `<db dir>/.master-salt` with mode `0600`. It is **never rotated automatically** — the derived key depends on it, so losing it loses the credentials. Back it up with the `.secret` file. A salt file that exists but is not valid hex is a startup error, never a silently regenerated salt.

### Upgrade safety

Stretching changes the derived key. Switching it on for an install that already holds credentials would make those credentials undecryptable. So stretching is applied **only** when:

- the salt file already exists (this install was stretched before), **or**
- the store is fresh at startup: no credentials **and** no users (nothing can be lost).

Users count because OAuth provider client secrets, OIDC client secrets and MCP upstream tokens are sealed with the master key too, and none of them can exist before the root user is bootstrapped. The check runs after the store is opened but before that bootstrap (`finalize_master_secret` in `crates/server/src/main.rs`), so an empty user table is a reliable first-boot signal.

An existing install with a weak secret and no salt file therefore keeps the legacy derivation and logs a warning naming the fix: rotate to a strong secret through the [key-ring procedure](#procedure).

Stretching also changes the session hash key, which is derived from the same secret — so the boot that first stretches a secret ends any open browser session, exactly as a rotation restart does. On a first boot there are none.

`AGTCRDN_PREVIOUS_MASTER_SECRET` follows the same rule with one difference: it is historical, so it never *creates* a salt file. It is stretched when a salt file already exists, and used unchanged otherwise.

An in-memory database has nowhere to persist a salt, so it always takes the direct path.

### Argon2id cost

`AGTCRDN_ARGON2_M_COST_KIB` (default 65536), `AGTCRDN_ARGON2_T_COST` (default 3) and `AGTCRDN_ARGON2_P_COST` (default 4) set the cost for master-secret stretching, password hashing and secret hashing alike. They replaced the `test-crypto` cargo feature, which set the same values at compile time and which cargo's feature unification could switch on for a production build. The test harness installs cheap parameters at runtime instead (`AppConfig::test_default`).

---

## Key Derivation

A single master secret produces **domain-separated keys** via **HKDF-SHA256** (`crates/core/src/crypto/key_derivation.rs`). The server derives two keys at startup; a third label is available as a library function:

| Derived Key | HKDF Info Label | Purpose | Used at startup |
|-------------|-----------------|---------|:---------------:|
| AES-256 Encryption Key | `agentcordon:encryption-v2` | Credential encryption at rest | Yes |
| Session Hash Key | `agentcordon:session-hash-v2` | HMAC-SHA256 session token hashing | Yes |
| Device ID | `agentcordon:device-id-v1` | Deterministic device UUID generation (library only) | No |

Each label is unique -- the tests in `key_derivation.rs` verify no label collisions and confirm that every derivation function produces distinct output for the same (secret, salt) input.

> **No JWT signing key is derived.** Earlier versions derived an ES256 (P-256/ECDSA)
> keypair under `agentcordon:jwt-es256-v1` for workspace identity JWTs. The JWT issuer,
> `/.well-known/jwks.json`, and the permissions-token endpoint are gone -- nothing verified
> those tokens anywhere a client could reach -- and workspace bearer credentials are opaque
> OAuth 2.0 access tokens only. Nothing in the tree derives a signing keypair at startup.

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
  ├── resolve KDF salt             # env var / auto-derive from master secret
  ├── Argon2 cost + replica mode   # AGTCRDN_ARGON2_*, AGTCRDN_REPLICA_MODE
  └── master key version + previous secret (validated; see Key Rotation)

acquire_instance_lock()            # flock on <db path>.lock, before migrations

init_store(&config)                # open the database, run migrations

finalize_master_secret(&mut config, store)
  └── strong / stretched / legacy  # see Secret Strength and Stretching

init_crypto(&config)
  ├── KeyRing::from_secrets()      # derive_master_key() per version → KeyRing (Arc-wrapped, immutable)
  └── derive_session_hash_key()    # → [u8; 32] copied into AppState
```

The `AppState` struct (`crates/server/src/state.rs`) holds the key ring and the session hash key as shared, immutable references. The intermediate `CryptoKeys` struct groups them before they are moved into `AppState`. The session hash key is derived from the current secret only.

---

## Nonce Safety

The `AesGcmEncryptor` (`crates/core/src/crypto/aes_gcm.rs`) tracks an atomic 64-bit counter of encryptions:

| Threshold | Value | Behavior |
|-----------|:-----:|----------|
| Warning | 2^31 | Logs a one-time warning (fires exactly once, when the counter crosses the threshold) |
| Hard failure | 2^32 | Refuses further encryptions (`CryptoError::NonceExhaustion`) |

Each encryption generates a **random 12-byte nonce** via `OsRng`. The counter is a defense-in-depth measure against nonce reuse. The counter uses atomic `fetch_add` to prevent TOCTOU races in concurrent encryption, and is flushed to persistent storage every 100 encryptions. In the key ring each version has its own encryptor and therefore its own counter; only the current key ever encrypts.

---

## Key Rotation

The server holds a **key ring** (`crates/core/src/crypto/key_ring.rs`): one AES-256-GCM key per master-secret version. The current secret is version `AGTCRDN_MASTER_KEY_VERSION` (default 1). During a rotation the secret it replaces is loaded from `AGTCRDN_PREVIOUS_MASTER_SECRET` as version N-1, so rows sealed under either secret open.

### `key_version` semantics

`key_version` on `credentials` and on `credential_secret_history` records **which master-key version sealed that row**:

- New ciphertext (create, secret update, refresh-token rotation, history archive) is stamped with the current version.
- Decrypting a credential or history row uses the key its `key_version` names. If the ring has no key of that version, or that key refuses the ciphertext, the ring tries the current key and then the previous one. That fallback exists for rows written before v0.3.4, when `key_version` was a counter of re-encryptions and says nothing about which secret sealed the row.
- Restoring a history entry copies its ciphertext **and** its `key_version` back onto the credential.
- Rows without a `key_version` column (OAuth provider client secrets, OIDC client secrets, MCP OAuth tokens) are opened with the current key, then the previous key.

A `key_version` the ring does not know (a legacy counter, or a version whose secret is no longer configured) is not an error until decryption of that row is attempted; `rotate-key` reports such rows in `errors`.

### `POST /api/v1/admin/rotate-key`

Re-seals **every credential and every history row** under the current version: each row is opened with the key its `key_version` names, encrypted again with the current key and a fresh random nonce, and its `key_version` set to the current version. Rows already at the current version are re-sealed too (fresh nonce), so the call is idempotent and safe to repeat. The response reports `key_version`, `re_encrypted_count` / `total_credentials`, `history_re_encrypted_count` / `total_history_entries`, and `errors` (one line per row that could not be opened or written). Requires an admin user with Cedar `rotate_encryption_key` on the System resource; a workspace bearer token is refused.

The call writes one audit event, **`master_key_resealed`** (shown as *Master Key Resealed*), against the `system` resource, carrying `key_version`, `re_encrypted_count`, `history_re_encrypted_count` and `error_count`. It is deliberately not `credential_secret_rotated`: no secret changed value, and "has anyone re-sealed this store?" is answered by filtering `GET /api/v1/audit?event_type=master_key_resealed`.

### Issuing the call

There is a **Re-seal credentials** button on `/settings` -- pick **Master key** in the
settings section rail, or scroll to the *Master Key* card. It is an outlined button whose
confirmation dialog carries the warning; using it is the whole story, and it shows the
response inline as a table.

To do it by hand, the endpoint takes an authenticated user, and CSRF applies because that
authentication is a session cookie. The double-submit rule
(`crates/server/src/middleware/csrf.rs`) needs an `X-CSRF-Token` header whose value matches
the `agtcrdn_csrf` cookie. A missing header answers **`403 csrf_validation_failed`**, which
reads like a permissions problem and is not one.

```bash
S=https://agentcordon.example.com
JAR=$(mktemp)

# 1. Log in; this sets both agtcrdn_session (HttpOnly) and agtcrdn_csrf (readable).
curl -sS -c "$JAR" -X POST "$S/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"root\",\"password\":\"$AGTCRDN_ROOT_PASSWORD\"}" > /dev/null

# 2. Read the CSRF token out of the cookie jar and send it as a header.
CSRF=$(awk '$6=="agtcrdn_csrf" {print $7}' "$JAR")

curl -sS -b "$JAR" -X POST "$S/api/v1/admin/rotate-key" \
  -H "X-CSRF-Token: $CSRF" | jq .
```

```json
{
  "data": {
    "key_version": 2,
    "re_encrypted_count": 41,
    "total_credentials": 41,
    "history_re_encrypted_count": 12,
    "total_history_entries": 12,
    "errors": []
  }
}
```

Authorization is Cedar `rotate_encryption_key` on the `System` resource, which admin and
root hold. A workspace bearer token is refused -- this is a user action.

### Procedure

Starting from secret S1 at version N (N is 1 if you have never rotated):

1. Generate the new secret S2. Make it strong: 32 random bytes, hex-encoded (`openssl rand -hex 32`). A weak S2 on an install that already holds credentials is used unstretched and warned about, which is not what you want from a rotation.
2. Set `AGTCRDN_MASTER_SECRET=S2`, `AGTCRDN_MASTER_KEY_VERSION=N+1`, `AGTCRDN_PREVIOUS_MASTER_SECRET=S1`. If the secret comes from the `.secret` file rather than the env var, replace the file's contents with S2.
3. Restart the server. It refuses to start if the previous secret equals the current one, is shorter than 16 characters, or is set while the version is 1. Everything is readable: new writes use S2, old rows open with S1.
4. Call `POST /api/v1/admin/rotate-key` as an admin -- see [Issuing the call](#issuing-the-call) below. Check that `errors` is empty and that `re_encrypted_count` equals `total_credentials` (and likewise for history). Repeat the call if any row failed transiently.
5. Remove `AGTCRDN_PREVIOUS_MASTER_SECRET` and restart. From now on only S2 is loaded; a row that was not re-sealed in step 4 can no longer be opened, which is why step 4 must report no errors first.

The session hash key is derived from the current secret, so each restart in steps 3 and 5 invalidates outstanding browser sessions and users sign in again. Workspace OAuth access and refresh tokens are stored as hashes in the database, not derived from the master secret, so brokers keep working across the rotation without re-enrolling.

> [!IMPORTANT]
> Never change `AGTCRDN_MASTER_SECRET` without also bumping `AGTCRDN_MASTER_KEY_VERSION` and setting `AGTCRDN_PREVIOUS_MASTER_SECRET` to the old value. A server started with only the new secret cannot open anything sealed under the old one, and `rotate-key` cannot help at that point.

> [!TIP]
> `AGTCRDN_KDF_SALT`, when set, applies to both secrets. When it is unset each secret derives its own salt (the same rule the server has always applied to the current secret), so a deployment that never set the salt rotates cleanly.

---

## Replica Guard

The server keeps policy decisions, rate-limit counters and the SSE bus in process memory. Two servers over one SQLite file therefore enforce two different pictures of the world, and both migrate the same database at startup.

At startup, before migrations, the server takes an advisory `flock(LOCK_EX | LOCK_NB)` on `<AGTCRDN_DB_PATH>.lock` and holds it for the life of the process (`InstanceLock` in `crates/server/src/config.rs`). The kernel releases it when the process exits, however it exits, so there is no stale lock to clean up. A second server against the same database fails to start with a message naming the lock file and the escape hatch.

Exemptions: an in-memory database, and a non-SQLite backend (an external database is not guarded by a local file lock).

`AGTCRDN_REPLICA_MODE=unsafe-shared` skips the guard. It is the documented escape hatch for an operator who accepts split-brain enforcement; a replica-safe server (store-driven policy versioning, shared rate limiters, shared SSE) is a separate piece of work. Any value other than `single` (the default) or `unsafe-shared` is a startup error, so a typo cannot look like the escape hatch.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AGTCRDN_MASTER_SECRET` | Auto-generated | Master secret (min 16 chars; stretched with Argon2id unless it carries 32+ bytes of random material) |
| `AGTCRDN_MASTER_KEY_VERSION` | `1` | Version number of the current master secret; bump by one per rotation |
| `AGTCRDN_PREVIOUS_MASTER_SECRET` | Unset | Secret for version N-1, set only during a rotation (min 16 chars, must differ from the current secret, requires version >= 2) |
| `AGTCRDN_KDF_SALT` | Auto-derived from each master secret | HKDF salt override, applied to both secrets |
| `AGTCRDN_DB_PATH` | `./data/agent-cordon.db` | Database location (`.secret` and `.master-salt` stored in the same parent directory; `<db path>.lock` is the instance lock) |
| `AGTCRDN_ARGON2_M_COST_KIB` | `65536` | Argon2id memory cost in KiB |
| `AGTCRDN_ARGON2_T_COST` | `3` | Argon2id iterations |
| `AGTCRDN_ARGON2_P_COST` | `4` | Argon2id lanes |
| `AGTCRDN_REPLICA_MODE` | `single` | `single` refuses a second instance on the same SQLite database; `unsafe-shared` skips the guard |

---

## Security Properties

- **No secrets in logs** -- the master secret and KDF salt are both redacted in the `Debug` impl for `AppConfig`
- **Domain separation** -- distinct keys derived from one secret via unique HKDF info labels
- **Authenticated encryption** -- credential IDs are used as AAD (Additional Authenticated Data) to prevent credential swapping between rows
- **Counter-based nonce safety** -- atomic counter with hard failure at 2^32 encryptions prevents nonce reuse
- **File permissions** -- auto-generated `.secret` file is written with `0600` (owner read/write only)
- **Minimum secret length** -- enforced at 16 characters for both the env var and the `.secret` file
- **Passphrase stretching** -- a secret below 32 bytes of random material is stretched with Argon2id and a persisted 16-byte salt, except where doing so would orphan existing credentials
- **Single instance** -- an advisory lock on `<db path>.lock` stops a second server from enforcing policy over the same SQLite database

---

> **See also:** [Credential Encryption](credential-encryption.md) | [System Architecture](system-architecture.md)
