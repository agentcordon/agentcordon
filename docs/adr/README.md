# Architecture Decision Records

One file per decision, numbered from `0001`. Each records the situation that forced a choice,
the choice, and what it costs — in the format: Title, Status, Date, Context, Decision,
Consequences.

An ADR is a record, not documentation. It is not edited when the code moves on: a decision that
is reversed gets a **new** ADR that supersedes the old one, and the old one's status changes to
`Superseded by ADR-NNNN`. For how the code works today, read [`../../CONTEXT.md`](../../CONTEXT.md)
and the pages in [`../index.md`](../index.md).

If your work contradicts an ADR, say so explicitly rather than silently overriding it.

## Index

| # | Decision | Status | Date |
|---|----------|--------|------|
| [0001](0001-sqlite-is-the-only-storage-backend.md) | SQLite is the only storage backend | Accepted | 2026-09-04 |
| [0002](0002-vaults-are-entities-with-ids.md) | Vaults are entities with UUID ids and per-owner unique names | Accepted | 2026-09-04 |
| [0003](0003-vault-sharing-is-the-owners-act.md) | Sharing a vault is the owner's act; `manage_vaults` is oversight only | Accepted | 2026-09-04 |
| [0004](0004-oauth-provider-clients-are-admin-managed.md) | OAuth provider clients are admin-managed under `manage_oauth_provider_clients` | Accepted | 2026-09-04 |
| [0005](0005-server-broker-wire-types-live-once-in-core.md) | Server↔broker wire types live once in `agent-cordon-core` | Accepted | 2026-09-04 |
| [0006](0006-secrets-never-leave-the-server.md) | Secrets never leave the server: the broker never calls a provider token endpoint | Accepted | 2026-09-04 |
| [0007](0007-target-bound-vends.md) | Target-bound vends, with a structural URL pattern enforced at both server and broker | Accepted | 2026-09-04 |
| [0008](0008-cli-broker-channel-hardening.md) | CLI↔broker channel hardening: nonce, key pin, and a shared secret or TLS off loopback | Accepted | 2026-09-05 |
| [0009](0009-master-key-ring-and-argon2id-stretching.md) | A versioned master-key ring, a re-seal path, and Argon2id stretching of weak secrets | Accepted | 2026-09-04 |
| [0010](0010-installer-pinned-to-server-version.md) | The installer is pinned to the server's version, and upgrades are lockstep | Accepted | 2026-09-05 |
| [0011](0011-admin-ui-is-shells-over-the-admin-api.md) | The admin UI is shells over the admin API, with one primitives module and one placement grammar | Accepted | 2026-09-06 |
| [0012](0012-authorization-model-rework-deferred.md) | The authorization-model rework is deferred to the next phase | Accepted | 2026-09-06 |
| [0013](0013-init-installs-the-agentcordon-skill-per-runtime.md) | `agentcordon init` installs the AgentCordon skill per runtime; the MCP server surface is deferred | Accepted | 2026-09-06 |
| [0014](0014-pinned-host-overrides-the-ssrf-guard.md) | A credential fenced to one literal host is forwarded to it past the SSRF guard; `**` is one or more host labels | Accepted | 2026-09-07 |

## Reading order

- **Storage and data model:** 0001, 0002.
- **Who may do what:** 0003, 0004, 0012.
- **The credential path, server to agent:** 0006, 0007, 0014, 0005.
- **Trust boundaries and keys:** 0008, 0009.
- **Shipping and operating:** 0010, 0011.
- **How an agent runtime finds AgentCordon:** 0013.
