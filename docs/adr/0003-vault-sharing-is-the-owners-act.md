# 3. Sharing a vault is the owner's act; `manage_vaults` is oversight only

- **Status:** Accepted
- **Date:** 2026-09-04

## Context

`manage_vaults` is a Cedar action the default policy grants to admins. Before this decision it
was read as "may do anything to any vault", including granting a share. Two problems followed:

1. Any admin could hand out another user's credentials by sharing that user's vault with
   themselves or a third party. Sharing is a *delegation of the owner's access*, and an admin
   is not the owner.
2. Share and unshare checked only the system-wide permission, so an admin could also "share" a
   vault that did not exist — because before ADR-0002 a vault existed only while a credential
   carried its name.

Separately, `GET /api/v1/vaults/{name}/shares` required only `list` on `System`, so any
signed-in user — a viewer included — could read who a vault was shared with, together with the
user ids of the sharer and every recipient.

There is a real oversight need behind `manage_vaults`, though: an admin auditing an incident
must be able to see who a vault reaches and to cut a share off.

## Decision

Split the two capabilities. Granting a share is the owner's act; `manage_vaults` is oversight.

- **Grant a share:** the vault's owner, at any role, and only the owner (root by bypass).
  `manage_vaults` does **not** imply it, and the admin UI offers a `manage_vaults` holder no
  control that grants one.
- **Read a share list:** the owner, or a `manage_vaults` holder. It is gated per vault in
  `crates/server/src/services/vaults.rs`, not at `System` scope. Vault policy decisions name
  the vault in their audit row and carry the request's correlation id.
- **Revoke a share:** the owner, or a `manage_vaults` holder. Revocation is what auditing a
  share actually needs, and it only ever removes access.
- **The only share permission level is `read`.** `write` and `admin` were accepted, stored,
  and consulted by nothing; they are now refused with 400.
- A `read` share makes the vault's credentials visible to the recipient **in the credential
  list and detail only**. It does not reveal secrets, does not grant the credential to a
  workspace, and does not carry the right to re-share. Credentials report an `access` field so
  the UI can offer only what the share permits and explain the rest.

## Consequences

- Admin is no longer a superset of owner for this operation. An admin who genuinely needs a
  credential asks its owner, or uses root.
- The rule generalises: a permission whose name starts with `manage_` is oversight over an
  aggregate — read, audit, revoke — and is not a substitute for ownership when the operation
  *widens* access. Future `manage_*` actions should be read that way.
- `manage_vaults` remains a `System`-scoped Cedar check because the schema has no `Vault`
  resource type. Per-vault ownership is therefore enforced in the vault service rather than in
  the policy. That split is an interim state; see ADR-0012.
- Recipients of a share see a "Shared by &lt;user&gt;" marking and a read-only banner, and the
  controls the server would refuse (Reveal Secret, Edit, Delete, Grant Permissions) are not
  offered.
