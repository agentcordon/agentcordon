# AgentCordon

Rust workspace, five crates: `core` (storage, Cedar policy engine, crypto key ring, transforms, SSRF and URL-pattern checks), `server` (control plane: OAuth authorization server, admin API and UI, vault), `broker` (per-user daemon: holds OAuth tokens, vends and injects credentials, fronts MCP servers; never holds provider secrets), `cli` (`agentcordon` binary: talks only to the broker), `identity` (Ed25519 key file, `sha256:` identity, request and register signing; CLI and broker both depend on it, its test vectors freeze the signed bytes). `docs/system-architecture.md` describes the design; the code wins where they differ.

## Development

- `cargo test --workspace` runs everything. Server integration tests are one binary (`crates/server/tests/main.rs` lists the modules); run one with `cargo test -p agent-cordon-server --test integration <name>`.
- In a git worktree, point `CARGO_TARGET_DIR` at the main checkout's `target/` so dependency artifacts are reused.
- Migrations under `migrations/` are forward-only SQLite. A migration that rebuilds a table must run with `PRAGMA foreign_keys=OFF` around the rebuild; every production connection has foreign keys on, and `DROP TABLE` cascades. Every migration from 010 on has an upgrade test that seeds rows at version N-1 via `run_migrations_up_to` and then applies N.
- Side effects (audit event, UI event, policy reload) belong at the layer where the state change happens, which is a service, not a route handler. `crates/server/src/device_code_service.rs` is the reference shape.
- `Authz::authorize(caller, action, resource)` in `crates/server/src/authz/` is the one way a route answers "is this allowed"; `Authz::request(...)` is the fluent form for routes that add context claims. Authorization checks name the concrete resource and its owner; a System-scoped check is only for actions with no resource. `crates/server/tests/route_authorization.rs` enumerates every parameterized admin route and must classify a new one.
- Root bypass and admin privilege live in the policy engine and `User::is_admin`; no inline `role == Admin || is_root`.
- `clippy.toml` forbids blocking inside a task (`Handle::block_on`, `block_in_place`, `thread::scope`); `scripts/check-dead-modules.py` (run in CI) fails when a module under `core/src/proxy` or `server/src/middleware` has no non-test caller.
- A vend names its target (`method`, `target_url`); the server checks `allowed_url_pattern` structurally and the broker checks again before injecting. A credential's `key_version` names the master key that sealed it (`AGTCRDN_MASTER_KEY_VERSION`, `AGTCRDN_PREVIOUS_MASTER_SECRET` for rollover).

## Test seams

Tests live at these boundaries and nowhere lower:

1. Server HTTP boundary: `agent_cordon_server::test_helpers::TestAppBuilder` builds the real router over in-memory SQLite; drive it with `tower::ServiceExt::oneshot`. Helpers in `crates/server/tests/common/mod.rs`.
2. Broker HTTP boundary: `crates/broker/tests/common/mod.rs` builds the broker router in-process with `wiremock` standing in for the server and for upstreams, and signs requests with a test workspace key.
3. Migration runner: `run_migrations_up_to(conn, n)` then seed, then `run_migrations(conn)`.

Pure-function tests are for the identity, URL-matching, SigV4, and Cedar-engine code only.

## Work in flight

The 0.4.0 architecture consolidation is complete. Its decisions are the ADRs under `docs/adr/` and the vocabulary is `CONTEXT.md`; read the relevant ADR before touching migrations, OAuth routes, authorization helpers, the broker proxy path, or the docs on key rotation. The authorization-model rework is the next phase (ADR 0012).

## Agent skills

### Issue tracker

Issues are tracked in GitHub Issues for `agentcordon/agentcordon`, via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

The five default labels: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.
