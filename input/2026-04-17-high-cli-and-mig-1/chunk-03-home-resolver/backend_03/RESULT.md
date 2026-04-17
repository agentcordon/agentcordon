# RESULT — backend_03

## Files changed

- `crates/cli/Cargo.toml` — modified — +1 line (added `dirs = "5"` to
  `[dependencies]` between `colored` and `thiserror`; workspace-level
  `Cargo.toml` is intentionally untouched).
- `crates/cli/src/broker.rs` — modified — net +~70 lines (added):
  - `dirs_or_home()` signature changed from `fn -> PathBuf` to
    `fn -> Result<PathBuf, CliError>`; body delegates to the new
    testable inner `agentcordon_dir_from(Option<PathBuf>)`.
  - Caller at `discover_broker` (was line 270) propagates with `?`.
  - `/tmp` fallback removed; `dirs::home_dir()` is the sole source.
  - New `#[cfg(test)] mod tests` with a local `EnvGuard`
    (static `Mutex<()>` pattern from
    `crates/cli/src/commands/init.rs:413-435`) and two tests:
    `resolves_home_when_present`, `errors_when_no_home`.
- `crates/cli/src/commands/setup.rs` — modified — net +~80 lines (added):
  - `broker_port_path()` signature changed from `fn -> PathBuf` to
    `fn -> Result<PathBuf, CliError>`; body delegates to the new
    testable inner `broker_port_path_from(Option<PathBuf>)`.
  - Caller at `discover_existing_broker` (was line 94) propagates with
    `?`.
  - `/tmp` fallback removed; `dirs::home_dir()` is the sole source.
  - New `#[cfg(test)] mod tests` symmetric to `broker.rs` tests.
- `Cargo.lock` — modified — 1 line (regeneration after adding `dirs`
  as a direct dep of the CLI crate; the version `5.0.1` was already
  present transitively).

## Tests added

- `crates/cli/src/broker.rs::tests::resolves_home_when_present` — with
  `HOME` set to a fresh `TempDir`, asserts the resolver returns
  `<temp>/.agentcordon`.
- `crates/cli/src/broker.rs::tests::errors_when_no_home` — feeds
  `None` into `agentcordon_dir_from` directly and asserts the returned
  `CliError` message contains `"home directory"`.
- `crates/cli/src/commands/setup.rs::tests::resolves_home_when_present`
  — mirror for `broker_port_path`; expects
  `<temp>/.agentcordon/broker.port`.
- `crates/cli/src/commands/setup.rs::tests::errors_when_no_home` —
  mirror for `broker_port_path_from(None)`.

### Test design note — why an inner helper

The chunk PLAN called for an `errors_when_no_home` test that unsets
`HOME` / `USERPROFILE` and asserts the resolver errors. On the
Linux CI box, `dirs::home_dir()` falls back to `getpwuid_r(getuid())`
(via `dirs-sys 0.4.1` lines 33-70) when `HOME` is unset, so the crate
still returns `Some("/home/<user>")` — the `None` branch is unreachable
purely through env mutation on this platform. To exercise the error
branch deterministically across hosts (Linux dev, CI, macOS, Windows)
I introduced a private inner helper
(`agentcordon_dir_from(Option<PathBuf>)` and the symmetric
`broker_port_path_from`) that takes the lookup result as input. The
public resolver is a one-liner that passes `dirs::home_dir()` in.
This both pins the error-path behaviour under test and keeps the
production code path unchanged. The `EnvGuard` is still present and
serialises the `resolves_home_when_present` test which does mutate
`HOME`.

## Test run

Command: `cargo test -p agentcordon-cli`
Outcome: PASS

```
running 7 tests
test broker::tests::errors_when_no_home ... ok
test commands::setup::tests::errors_when_no_home ... ok
test broker::tests::resolves_home_when_present ... ok
test commands::init::tests::ensure_entry_creates_file_when_missing ... ok
test commands::setup::tests::resolves_home_when_present ... ok
test commands::init::tests::ensure_entry_preserves_existing_servers ... ok
test commands::init::tests::ensure_entry_is_idempotent ... ok

test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured;
              0 filtered out; finished in 0.00s
```

Four new tests (two per touched file) plus three pre-existing
`commands::init::tests::*` tests. No pre-existing test changed behaviour.

## Lint / format

- `cargo clippy --workspace -- -D warnings`: PASS — clean, no warnings.
- `cargo fmt -p agentcordon-cli -- --check`: PASS — the CLI crate
  (the only crate I touched) is format-clean.
- `cargo fmt --all --check`: FAIL **on unrelated files** —
  `crates/broker/src/routes/proxy.rs`,
  `crates/core/src/storage/migrations.rs`,
  `crates/server/src/middleware/rate_limit_device_approve.rs`,
  `crates/server/src/routes/admin_api/credentials/vend.rs`,
  `crates/server/src/routes/oauth/device.rs`,
  `crates/server/src/routes/oauth/token.rs`, and
  `crates/server/tests/v016_oauth2.rs` have pre-existing formatting
  drift on `main` (commit `fd21798`). Per the chunk PLAN and its
  invariants ("Do NOT touch ... the server crate, the broker crate")
  these are out of scope for this chunk. Running `cargo fmt --all`
  during my verification did rewrite them; I reverted those
  rewrites with `git checkout --` so only the four in-scope files
  (`Cargo.lock`, `crates/cli/Cargo.toml`,
  `crates/cli/src/broker.rs`, `crates/cli/src/commands/setup.rs`)
  remain modified on the branch.
- `cargo build --workspace`: PASS (dev profile, per
  `wiki/process/dev-builds-only.md`).

## Grep checks (per chunk PLAN acceptance criteria)

- `grep '"/tmp"' crates/cli/src/broker.rs crates/cli/src/commands/setup.rs`
  — no matches (non-test context or test context).
- `grep 'std::env::var("HOME")' crates/cli/src/broker.rs crates/cli/src/commands/setup.rs`
  — two matches, BOTH in test code (the `EnvGuard::new()` snapshot
  of the prior value so it can be restored on drop). Non-test-context
  matches: zero.

## Deviations from PLAN.md

1. My PLAN.md described the `errors_when_no_home` test as clearing
   `HOME` / `USERPROFILE` and asserting an `Err` from the public
   resolver, guarded by `#[cfg(unix)]`. First iteration failed on
   this Linux host because `dirs::home_dir()` falls back to
   `getpwuid_r` when `HOME` is unset — the test got a real home path
   back, not `None`. I pivoted to a small private inner helper
   (`agentcordon_dir_from(Option<PathBuf>)` and the symmetric
   `broker_port_path_from`) that takes the lookup result as a
   parameter, letting the tests inject `None` deterministically on
   every platform. The `EnvGuard` remains and the
   `resolves_home_when_present` test still exercises the env-reading
   path end-to-end. See the "Test design note" section above.
2. `cargo fmt --all --check` is NOT passing on `main` (pre-existing
   drift in server / broker / core files that are out of scope for
   this chunk). I explicitly did NOT fix those because the chunk
   invariants forbid touching server / broker crates. See the
   "Lint / format" section. The CLI crate itself (my only touched
   crate) is format-clean under `cargo fmt -p agentcordon-cli -- --check`.
