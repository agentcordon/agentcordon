# CHUNK PLAN — chunk-03-home-resolver

Parent plan: 2026-04-17-high-cli-and-mig-1
Role: backend
Engineer: backend_03

## Scope

Replace the broken `/tmp` fallback in two CLI home-directory resolvers
with a Windows-correct, errors-cleanly resolver backed by the `dirs`
crate. Resolves CLI-4.

## Acceptance criteria

- `dirs = "5"` is added to `crates/cli/Cargo.toml` `[dependencies]` ONLY.
  Do NOT add it to the workspace-level `Cargo.toml`. The CLI is the only
  consumer.
- `crates/cli/src/broker.rs::dirs_or_home` (current lines 309-313) is
  rewritten to:
  - Return `Result<PathBuf, CliError>` (signature change — propagate the
    error to its single caller at line 270).
  - Use `dirs::home_dir()` to resolve the user home on all platforms.
  - On `None`, return `CliError::general("could not resolve user home
    directory; set HOME (Unix/macOS) or USERPROFILE (Windows)")`.
  - NEVER fall back to `/tmp`, `.`, `current_dir()`, or any default path.
- The single existing caller `discover_broker` at line 270 propagates the
  new `Result` via `?`.
- `crates/cli/src/commands/setup.rs::broker_port_path` (current lines
  107-111) is rewritten in the same shape: returns
  `Result<PathBuf, CliError>` and uses `dirs::home_dir()`. Its callers
  (search the file with grep — currently the only caller is
  `discover_existing_broker` at line 94) propagate the error via `?`.
- A grep for `"/tmp"` in `crates/cli/src/broker.rs` and
  `crates/cli/src/commands/setup.rs` returns NO matches in a non-test
  context after the change.
- A grep for `std::env::var("HOME")` in those two files returns NO matches.
- New unit tests in `crates/cli/src/broker.rs` and
  `crates/cli/src/commands/setup.rs`:
  - `resolves_home_when_present`: with `HOME` (or `USERPROFILE` on
    Windows) set to a known temp dir, the resolver returns
    `<temp>/.agentcordon` (or `<temp>/.agentcordon/broker.port`
    respectively).
  - `errors_when_no_home`: with both `HOME` and `USERPROFILE` unset, the
    resolver returns `Err(CliError::...)` whose message contains
    `"home directory"`. Use the same `EnvGuard`/`std::sync::Mutex`
    serialisation pattern that `init.rs:413-435` uses to keep env-var
    mutation safe across parallel test threads.
- `cargo test -p agentcordon-cli` passes.

## Files expected to change

- `crates/cli/Cargo.toml` — add `dirs = "5"` to `[dependencies]`. Keep
  the existing alphabetical-ish ordering of the file.
- `crates/cli/src/broker.rs` — rewrite `dirs_or_home`; propagate Result
  in the `discover_broker` caller.
- `crates/cli/src/commands/setup.rs` — rewrite `broker_port_path`;
  propagate Result in its caller.

## Reuse

- The `EnvGuard` pattern from `crates/cli/src/commands/init.rs:413-435`.
  Copy it into the test modules of the touched files (or a small shared
  test-utils module if you prefer; do NOT make this a public helper).
- `tempfile::TempDir` (already a dev-dependency at
  `crates/cli/Cargo.toml:35`).
- `CliError::general(...)` for the error.

## Prior art (from wiki)

- `(none found)` — no wiki article specifically covers the home-resolver
  surface. The post-merge documentation-agent will decide whether one is
  warranted.

## Dependencies on other chunks

- None. Independent of chunks 01, 02, 04.

## Notes for the engineer

- **DEV BUILDS ONLY.** Never `cargo build --release`. Standard
  verification: `cargo fmt --all`, `cargo clippy --workspace -- -D
  warnings`, `cargo test -p agentcordon-cli`, `cargo build --workspace`.
- Do NOT touch `wiki/**`, `docs/**`, `input/BUGS.md`, the server crate,
  the broker crate, the Cedar policy bundle, the workspace-level
  `Cargo.toml`, or any pre-existing server test failures.
- The root-user bypass at `crates/core/src/policy/cedar/mod.rs:86-95` is
  intentional by design — do not refile if encountered during review.
- `dirs::home_dir()` does the right thing on Windows
  (`FOLDERID_Profile` via `SHGetKnownFolderPath`) — there's no need to
  manually probe `USERPROFILE` or `HOMEDRIVE+HOMEPATH`. Just call the
  crate function.
- Tests that mutate environment variables MUST serialise via a static
  `Mutex` (see init.rs:413-435 for the established pattern). Without
  serialisation, parallel tests will race and produce non-deterministic
  failures. Use the SAFETY-comment style already in init.rs.
- Do NOT add a "fallback to current dir" branch. The parent PLAN
  explicitly says the function returns an error if no home can be
  resolved; the CLI surfaces a clear message and exits non-zero.
