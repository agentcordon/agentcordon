# ENGINEER PLAN — backend_03

Parent chunk: chunk-03-home-resolver
Parent plan: 2026-04-17-high-cli-and-mig-1

## Prior art consulted

- `wiki/_master-index.md` — surveyed; no article under workspace-identity
  or authentication directly covers the CLI home-directory resolver
  surface. Chunk PLAN states `(none found)` for wiki prior art, confirmed.
- `wiki/process/dev-builds-only.md` — authoritative rule, no
  `--release` anywhere in my verification steps.
- The chunk PLAN itself cites `crates/cli/src/commands/init.rs:413-435`
  as the `EnvGuard`/static `Mutex` pattern I must follow for the tests
  that mutate `HOME` / `USERPROFILE`. Read in full at
  `crates/cli/src/commands/init.rs:406-436`.

## Approach

Two surgical rewrites using the `dirs` crate 5.x:

1. `crates/cli/src/broker.rs::dirs_or_home` (currently lines 309-313,
   returns `PathBuf` with a `/tmp` fallback) becomes
   `fn dirs_or_home() -> Result<PathBuf, CliError>` that calls
   `dirs::home_dir()`. On `None`, returns
   `CliError::general("could not resolve user home directory; set HOME (Unix/macOS) or USERPROFILE (Windows)")`.
   The single caller `discover_broker` at line 270 propagates via `?`:
   `let port_path = dirs_or_home()?.join("broker.port");`.

2. `crates/cli/src/commands/setup.rs::broker_port_path` (currently
   lines 107-111, returns `PathBuf` with a `/tmp` fallback) becomes
   `fn broker_port_path() -> Result<PathBuf, CliError>` with the same
   `dirs::home_dir()` + error-on-none shape. Its single caller
   `discover_existing_broker` at line 94 propagates via `?`:
   `let port_path = broker_port_path()?;`.

3. `crates/cli/Cargo.toml` gets `dirs = "5"` added to `[dependencies]`.
   Alphabetical-ish ordering is preserved by slotting it between
   `colored` and `ed25519-dalek`. Workspace-level `Cargo.toml` is
   untouched per the hard invariant.

4. Unit tests go in the `#[cfg(test)]` modules of the two touched files
   (`broker.rs` has no test module today, so I add one; `setup.rs`
   likewise). Each module has:
   - `resolves_home_when_present` — sets `HOME` (and clears
     `USERPROFILE` for belt-and-braces on Windows), asserts the
     resolver returns `<temp>/.agentcordon` (broker.rs) or
     `<temp>/.agentcordon/broker.port` (setup.rs).
   - `errors_when_no_home` — unsets both `HOME` and `USERPROFILE`,
     asserts `Err(_)` with a message containing `"home directory"`.

   Each module carries its own `EnvGuard` with a file-local static
   `Mutex<()>`, copy-pasting the `init.rs:413-435` pattern and
   adapting it to manage `HOME` + `USERPROFILE` instead of
   `AGTCRDN_WORKSPACE_DIR`. Per chunk PLAN: do NOT make this a public
   helper.

   Note on `dirs::home_dir()` behaviour: the crate reads `HOME` on
   Unix/macOS and uses `SHGetKnownFolderPath(FOLDERID_Profile)` on
   Windows with `USERPROFILE` as an acknowledged input. In the
   `errors_when_no_home` test I'll unset both variables and rely on
   the fact that on a Linux CI box (our dev/test platform per
   `wiki/process/dev-builds-only.md` + the workspace platform linux
   6.15) the crate returns `None` when `HOME` is unset. On Windows
   the test path would differ, but CI runs on Linux — documenting
   this explicitly in the test module with a
   `#[cfg(unix)]` guard so Windows maintainers know to re-verify if
   they ever run the suite on Windows.

## Files I will change

- `crates/cli/Cargo.toml` — add `dirs = "5"` to `[dependencies]`.
- `crates/cli/src/broker.rs` — rewrite `dirs_or_home` to return
  `Result<PathBuf, CliError>`; update the `discover_broker` caller at
  line 270 to `?`-propagate; add a `#[cfg(test)] mod tests` with the
  two tests and a local `EnvGuard`.
- `crates/cli/src/commands/setup.rs` — rewrite `broker_port_path` to
  return `Result<PathBuf, CliError>`; update the
  `discover_existing_broker` caller at line 94 to `?`-propagate; add
  a `#[cfg(test)] mod tests` with the two tests and a local `EnvGuard`.

No migration, no policy, no schema touched.

## Unit tests I will write

- `crates/cli/src/broker.rs` `tests::resolves_home_when_present` —
  guards `HOME` to a fresh `TempDir`, clears `USERPROFILE`; asserts
  `dirs_or_home().unwrap() == <temp>/.agentcordon`.
- `crates/cli/src/broker.rs` `tests::errors_when_no_home` —
  `#[cfg(unix)]`; unsets `HOME` and `USERPROFILE`; asserts
  `dirs_or_home().is_err()` and the message contains
  `"home directory"`.
- `crates/cli/src/commands/setup.rs` `tests::resolves_home_when_present`
  — mirror of the above; asserts
  `broker_port_path().unwrap() == <temp>/.agentcordon/broker.port`.
- `crates/cli/src/commands/setup.rs` `tests::errors_when_no_home` —
  mirror; `#[cfg(unix)]`.

## How I'll run the tests

From the worktree root:

```
cargo fmt --all
cargo clippy --workspace -- -D warnings
cargo test -p agentcordon-cli
cargo build --workspace
```

Focused while iterating:
`cargo test -p agentcordon-cli broker::tests`
`cargo test -p agentcordon-cli commands::setup::tests`
