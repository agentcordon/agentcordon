# 2. Vaults are entities with UUID ids and per-owner unique names

- **Status:** Accepted
- **Date:** 2026-09-04

## Context

A vault used to be a string: the `credentials.vault` column. There was no vault row anywhere.
The consequences followed directly from that representation:

- A vault "existed" while some credential carried its name, and "owning" a vault meant owning
  any credential that happened to carry it. Two users who each called a vault `team` were, to
  the server, in the same vault.
- Naming a vault on a credential create was enough to join it, so a user could reach whatever
  another user shared into a vault by guessing its name.
- Renaming meant rewriting every credential row; deleting meant nothing at all.
- The credential form's vault picker was free text, and the credentials list could not filter
  on a stable key.

## Decision

A vault is a row with an identity: `vaults(id, name, owner_user_id, created_at, updated_at)`
(`migrations/021_vaults_table.sql`, domain type in `crates/core/src/domain/vault.rs`, service in
`crates/server/src/services/vaults.rs`).

- The id is a UUID and is what every API operation names. `POST /api/v1/vaults` creates,
  `GET /api/v1/vaults` lists, `PATCH /api/v1/vaults/{id}` renames,
  `DELETE /api/v1/vaults/{id}` deletes an empty vault and answers 409 otherwise, and shares
  live at `/api/v1/vaults/{id}/shares`.
- Credentials carry `vault_id` on create and update and return `vault_id` and `vault_name`.
  The old `vault` name field is gone from the credential wire shape.
- The name is a **display label**, deliberately not unique in the schema. Uniqueness is a
  service-layer rule — a vault name is unique per owner and free across owners — enforced with
  a 409 that names the existing row and is shown inline next to the field. Existing installs
  may already hold duplicates, so there is no unique index and no data migration for it.
- There is exactly one system default vault, id `00000000-0000-0000-0000-000000000001`, with
  no owner. It takes any credential whose creator names no vault.
- Migration 021 gives each distinct (vault name, creating user) pair among existing credentials
  its own vault. A credential created by a workspace has no creating user, so it goes to the
  workspace's owner's vault, falling back to root. Everything named `default` lands in the one
  system vault. The migration rebuilds `credentials` and `vault_shares`, so it carries the
  `-- migration-mode: foreign_keys_off` marker.

## Consequences

- Placing or moving a credential into a vault is now an authorization question with an answer:
  the caller must own the vault (or be root). Naming a vault no longer creates one, so the
  join-by-guessing-a-name path is closed.
- Two users may both have a vault called `team` and they are different vaults. The UI shows
  the display name; the id is what is submitted and filtered on.
- The vault select on the New Credential form is populated from `GET /api/v1/vaults` and
  submits `vault_id`, with an inline "New vault" control. Vaults are managed from
  Settings → Vaults.
- Migration 021 rewrites the largest table in the database (`credentials`) plus
  `vault_shares`. It has not been timed against a large install; that is tracked separately.
- Because names are enforced per owner in the service and not in the schema, a database that
  already holds duplicates keeps them and only refuses the *next* colliding write. That is a
  deliberate trade against failing an upgrade.
