# 12. The authorization-model rework is deferred to the next phase

- **Status:** Accepted
- **Date:** 2026-09-06

## Context

The 0.4.0 consolidation set out to give authorization one entry point and one resource-scoped
answer. It got most of the way: `Authz::authorize(caller, action, resource)` is now the only
path to a Cedar evaluation, the five per-module `check_manage_*` wrappers are gone, root bypass
lives in one place, and a route-enumeration test forces every parameterized admin route to be
classified.

The classification is what exposed the remaining gap. The Cedar schema
(`policies/schema.cedarschema.json`) has resource entity types for `Credential`,
`WorkspaceResource`, `McpServer`, `PolicyResource` and `System` — and nothing else. So a route
that names a user, a vault, an OIDC provider, an OAuth provider client or an audit entry has no
resource to evaluate against, and its per-entity rules are enforced **in the service layer
instead of in the policy**. Two authorization models therefore coexist.

Reworking the model properly — new entity types, a migration of the shipped default policy,
and a re-classification of every route — is larger than the consolidation could carry without
a big-bang merge, and it depends on decisions (per-vault delegation, custom roles, time-bound
grants) that are not made yet.

## Decision

**Ship the interim model, record it explicitly, and defer the rework to the next phase.**

### The interim rules, as they stand

1. **One evaluation path.** `Authz::authorize(caller, action, resource)` is the one way a route
   answers "is this allowed"; `Authz::request(...)` is the fluent form for routes that add
   context claims, and `authorize` delegates to it. `Authz::filter` evaluates a list and writes
   **one** `policy_evaluated` row per request, recording counts and ids (capped at 200 per
   outcome), not one row per item.
2. **Root bypass lives in the policy engine**, before any entity is built
   (`crates/core/src/policy/cedar/mod.rs`), and surfaces as the audit reason `root_bypass`.
   Administrative privilege is `User::is_admin` — the admin role or the root flag — and there
   are no inline `role == Admin || is_root` checks.
3. **Root is not a role.** `UserRole` is `admin` / `operator` / `viewer`; `is_root` is a
   separate boolean on the user.
4. **A Cedar evaluation error is a deny.** A permit accompanied by any evaluation error is
   returned as `Forbid` with reason `evaluation_error`, because Cedar otherwise skips the
   failing policy and decides from the rest — silently disarming a `forbid` with a typo.
   Policies are validated against the schema at load, at seed time, and in CI.
5. **Resource-scoped where the schema allows it.** Credentials, workspaces, MCP servers and
   policies are evaluated against a concrete resource with its owner. Operators hold
   `manage_workspaces` at `System` for approving registrations and listing (rule 2e) and on a
   `WorkspaceResource` only when they own it (2e-owner); the same split exists for MCP servers
   (2e-mcp).
6. **`System`-scoped by necessity, ownership enforced in the service.** Users, vaults, OIDC
   providers, OAuth provider clients and audit entries have no resource type. Their per-entity
   rules live in their services — for example vault ownership in
   `crates/server/src/services/vaults.rs`, which passes the vault id as a `vault_id` context
   claim so the decision is at least attributable in the audit row.
7. **`manage_*` is oversight, not ownership.** A `manage_*` grant reads, audits and revokes; it
   does not stand in for the owner when an operation *widens* access. See ADR-0003.
8. **The classification is enforced.** `crates/server/tests/route_authorization.rs` requires
   every parameterized admin route to be either resource-scoped or listed as `System`-scoped
   **with the reason**, and separately asserts who reaches the resource: a stranger's expected
   status, and whether the owner and a non-root admin get through. A new parameterized route
   fails the test until it is classified.
9. **Interim quirks recorded rather than fixed.** `delegated_use` is a *permission name* the
   grant templates map to the `vend_credential` action, not a Cedar action. `ActorId` still
   spells its non-user variant `Agent`. `AgentCordon::Server` is built by the entity builder
   but is absent from the schema, so it is an unreachable seam. `MANAGE_AGENTS` and
   `MANAGE_DEVICES` remain as aliases of `MANAGE_WORKSPACES`, and the policy tester's
   action-description map still lists `manage_workspaces` three times because of them.

### What the rework should revisit

- **Entity types for the `System`-scoped aggregates** — at minimum `Vault` and `User` — so
  per-entity ownership is a policy decision instead of a service-layer `if`, and rule 6 above
  disappears.
- **The `manage_*` vocabulary itself.** Ten `manage_*` actions with inconsistent resource sets
  is a vocabulary that grew, not one that was designed. Decide whether oversight and mutation
  should be separate actions everywhere (as `manage_oauth_provider_clients` versus
  `manage_mcp_servers`-for-listing already is in practice).
- **The `Workspace` / `WorkspaceResource` split**, which exists because the same entity is a
  principal when it acts and a resource when it is administered. Confirm that is the right
  modelling or collapse it.
- **`delegated_use` and the generated `grant:` / `deny:` rows.** Grants are policy rows named by
  string prefix and identified by `is_generated_grant`. Decide whether per-credential grants
  should be policy at all, or a separate grant table the engine reads.
- **The dead vocabulary**: `ActorId::Agent`, the `Agent`/`Device` aliases, the `agent_id`,
  `agent_name`, `device_id`, `device_name` audit columns, and `AgentCordon::Server`.
- **Time-bound grants, custom roles and admin API tokens**, all of which were ruled out of
  scope for 0.4.0 and all of which touch this model.

## Consequences

- Two enforcement mechanisms coexist for the rest of this phase. That is a known, documented
  state, not an accident: the route-authorization table names every route where it applies and
  why.
- A reader must not assume that "no Cedar resource" means "no ownership check". For the
  `System`-scoped aggregates, the ownership check is real and lives in the service; the Cedar
  row records the decision.
- Because ownership for those aggregates is not expressible in policy, an operator cannot
  currently write a Cedar policy that delegates, say, one vault to one user. That is the
  principal functional cost of deferring, and the main reason the rework is the next phase.
- ADR-0003's rule ("`manage_vaults` is oversight only") is enforced in code today. When vaults
  gain a resource type it should become policy, and this ADR should be superseded rather than
  edited.
