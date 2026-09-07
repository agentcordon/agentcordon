# 9. A versioned master-key ring, a re-seal path, and Argon2id stretching of weak secrets

- **Status:** Accepted
- **Date:** 2026-09-04

## Context

Two independent problems in the same area.

**Rotation destroyed the store.** The encryptor held exactly one key, derived from
`AGTCRDN_MASTER_SECRET`. The documented runbook was: change the secret, restart, call
`POST /api/v1/admin/rotate-key`. After the restart the server held only the *new* key, so
nothing could be decrypted and the rotate call had nothing to read. Following the documentation
lost every credential. A `key_version` column existed but counted *re-encryptions*, so it could
not say which key had sealed a row.

**A passphrase was as guessable as itself.** `AGTCRDN_MASTER_SECRET` was fed to HKDF directly.
A human-chosen secret therefore produced an encryption key with exactly the entropy of the
passphrase. Separately, a `test-crypto` cargo feature weakened Argon2 password hashing at
compile time, and cargo's feature unification could switch it on for a production build.

## Decision

**The encryptor is a versioned key ring** (`crates/core/src/crypto/key_ring.rs`).

- `AGTCRDN_MASTER_KEY_VERSION` names the current secret (default `1`).
  `AGTCRDN_PREVIOUS_MASTER_SECRET` loads the secret it replaced, for the rollover window. The
  ring holds at most two keys, N and N−1, and the server refuses to start if the two secrets
  are equal.
- **`key_version` records which master key sealed a row**, replacing the re-encryption counter.
  New credentials, secret updates, refresh-token rotations and history archives stamp the
  current version; decrypt selects the key that version names and falls back across the ring
  for rows written before this release. Restoring a history entry restores its version too.
  Migration 019 rebuilds `credential_secret_history` so the column exists on every install and
  backfills it to `1`.
- **`POST /api/v1/admin/rotate-key` re-seals history as well as credentials.** Each row is
  opened with the key its version names and written back under the current version. The
  response carries `key_version`, `re_encrypted_count` / `total_credentials`,
  `history_re_encrypted_count` / `total_history_entries` and `errors`; once it reports no
  errors the previous secret can be removed. It is idempotent — rows already at the current
  version are re-sealed under a fresh nonce — so it is safe to re-run.
- The operation has **its own audit event, `master_key_resealed`**, against the `system`
  resource, rather than reusing `credential_secret_rotated`: no secret changed value, only the
  key it is sealed under.
- The admin UI carries it as an admin-only **Master Key** card in Settings ("Re-seal
  credentials"), with a confirmation and a report, because the runbook's step 4 previously had
  no control anywhere and required hand-rolling a request with a session cookie and a matching
  CSRF token.

**Weak secrets are stretched, not rejected** (`crates/core/src/crypto/master_secret.rs`).

- A secret carrying at least 32 bytes of material at 4+ bits of Shannon entropy per byte
  (64+ hex chars, base64 of 32+ bytes, or 32+ raw characters) is *strong* and is used directly.
- Anything weaker is stretched with **Argon2id** and a random 16-byte salt persisted at
  `<db dir>/.master-salt` (mode 0600, created once, never rotated automatically). A corrupt or
  short salt file is an error, never silently replaced.
- **Upgrades are safe**: stretching only applies when the salt file already exists or the store
  is fresh. An existing install with a weak secret keeps its legacy derivation and gets a
  startup warning naming the rotation fix, rather than becoming undecryptable.
- The auto-generated `.secret` file is 32 random bytes in hex — i.e. strong by construction.
- Argon2 cost is a **runtime setting**: `AGTCRDN_ARGON2_M_COST_KIB`, `AGTCRDN_ARGON2_T_COST`,
  `AGTCRDN_ARGON2_P_COST` (defaults 65536 / 3 / 4), installed at startup, with the test harness
  installing cheap ones. The `test-crypto` cargo feature is deleted. An invalid value stops
  startup rather than silently lowering cost.

## Consequences

- Rotation is now: set `AGTCRDN_PREVIOUS_MASTER_SECRET` to the current secret, set the new
  secret, bump `AGTCRDN_MASTER_KEY_VERSION`, restart, re-seal, verify no errors, remove the
  previous secret, restart. `docs/master-key.md` is the runbook.
- The ring holds two keys, not N. A second rotation before the first is re-sealed will strand
  rows at version N−2. The re-seal report is the gate that says it is safe to move on.
- KMS/HSM-backed key encryption remains out of scope. This is a key ring, not a key management
  service.
- A weak secret on an existing install stays weak until the operator rotates. The warning says
  so; the alternative — silently changing the derivation — would have destroyed the store,
  which is the failure mode this ADR exists to remove.
