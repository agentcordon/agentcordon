# Contributing to AgentCordon

Thank you for wanting to help. This page is everything you need to get a change
merged: how to build and test it, how to describe it, and the two documents you
have to agree to.

Open an issue before starting anything large. A design that surprises the
maintainer at review time is a wasted afternoon for both of us.

## Before your first pull request

- **Sign the [Contributor Licence Agreement](CLA.md).** A bot asks you on your
  first pull request; you sign by leaving one comment on it, once, forever. The
  CLA explains why an AGPL project asks for one.
- **Read the [Code of Conduct](CODE_OF_CONDUCT.md).** Contributor Covenant 2.1.
- **Read [`CONTEXT.md`](CONTEXT.md).** It is the project's vocabulary, written
  from the code — workspace, vend, vault, broker, control plane, envelope. A
  change that uses those words the way the code uses them reviews itself.
- **Read [`CLAUDE.md`](CLAUDE.md).** It carries the conventions this codebase
  actually enforces, including where tests are allowed to live.

## Build and test

Rust stable, and nothing else. There is no code generation step and no
JavaScript build for the admin UI.

```bash
cargo build --workspace
cargo test --workspace                 # everything
cargo fmt --all                        # CI runs this with --check
cargo clippy --workspace --all-targets -- -D warnings
```

The server's integration tests compile into one binary, so run a single one by
naming its module:

```bash
cargo test -p agent-cordon-server --test integration <name>
```

`crates/server/tests/main.rs` lists the modules; a new test file has to be added
there or it does not compile.

CI additionally runs `python3 scripts/check-dead-modules.py` (every module under
`core/src/proxy` and `server/src/middleware` must have a non-test caller),
`scripts/check-version.sh` (all three binaries print `[workspace.package]
version`), `cargo deny check advisories licenses bans sources`, `cargo doc
--workspace --no-deps` with `-D warnings`, and a source build of the server
image. Run any of them locally before pushing if your change touches what they
guard.

### Where tests go

`CLAUDE.md` § "Test seams" is the rule, and it is a real constraint rather than a
preference. Tests live at three boundaries and nowhere lower:

1. **The server HTTP boundary.** `agent_cordon_server::test_helpers::TestAppBuilder`
   builds the real router over in-memory SQLite; drive it with
   `tower::ServiceExt::oneshot`. Helpers are in `crates/server/tests/common/mod.rs`.
2. **The broker HTTP boundary.** `crates/broker/tests/common/mod.rs` builds the
   broker router in-process with `wiremock` standing in for the server and for
   upstreams, signing requests with a test workspace key.
3. **The migration runner.** `run_migrations_up_to(conn, n)`, then seed rows,
   then `run_migrations(conn)`. Every migration from 010 on has one.

Pure-function tests are for the identity crate, URL matching, SigV4 and the
Cedar engine only. A unit test on a service method that could have been an HTTP
test at seam 1 will be asked to move.

### Migrations

`migrations/` is forward-only SQLite. A migration that rebuilds a table must
wrap the rebuild in `PRAGMA foreign_keys=OFF` — every production connection has
foreign keys on, and `DROP TABLE` cascades. Add the upgrade test alongside it.

### The release UAT harness

Before a release, `uat/` runs the whole product end to end against real
containers and a real browser:

```bash
./uat/run.sh
```

One command: it builds both images, brings the topology up, installs Playwright
and Chromium into `uat/.browsers`, runs the scenarios, collects every
container's logs, writes provenance, prints the summary and tears everything
down. It needs Docker and takes a while. `--no-build` reuses the existing
images, `--keep` leaves the containers up to poke at, and `--down-only` cleans
up after an interrupted run. [`uat/README.md`](uat/README.md) explains the
four-way result tally, the scenario list, and the rule the harness follows:
every step is one a new user could take from the shipped documentation.

You are not expected to run it for an ordinary pull request. Run it if you
change the CLI↔broker or broker↔server wire format, the installer, or anything
the admin UI's shipped screens depend on.

## Commits and pull requests

The history is [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(cli): agent-first mcp-call & mcp-tools surface
fix(mcp): emit McpServerChanged on workspace binding add/remove
docs: give installation and deployment their own pages
chore: release v0.4.0
```

`feat`, `fix`, `docs`, `chore`, `refactor`, `test`, with an optional scope, and
`!` before the colon for a breaking change. One commit per logical change: a
reviewer should be able to read your branch commit by commit.

The subject line says what changed; the body says **why**, because the diff
already says what. Fill in the pull request template — what, why, how you tested
it — and note in `CHANGELOG.md` under `## [Unreleased]` anything a user would
notice.

## Where design decisions go

A decision that constrains future work is an **ADR**, not a comment.
[`docs/adr/README.md`](docs/adr/README.md) has the format — Title, Status, Date,
Context, Decision, Consequences — one file per decision, numbered from `0001`,
listed in the index.

An ADR is a record, not documentation: it is never edited when the code moves
on. A reversed decision gets a *new* ADR that supersedes the old one, and the
old one's status becomes `Superseded by ADR-NNNN`. If your change contradicts an
existing ADR, say so in the pull request rather than silently overriding it.

For how the system works *today*, the pages under [`docs/`](docs/index.md) are
the reference; update the page your change makes wrong.

## Issues

Bugs and feature requests use the templates under
[`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/). Questions go to
[Discussions](https://github.com/agentcordon/agentcordon/discussions).

Triage uses five labels, documented in
[`docs/agents/triage-labels.md`](docs/agents/triage-labels.md):

| Label | Meaning |
|---|---|
| `needs-triage` | The maintainer has not evaluated it yet |
| `needs-info` | Waiting on the reporter |
| `ready-for-agent` | Fully specified; an agent can pick it up |
| `ready-for-human` | Needs human judgement to implement |
| `wontfix` | Will not be actioned |

A `ready-for-agent` issue is a good first contribution: it is one where the
problem, the expected behaviour and the files involved are already written down.

**Do not open a public issue for a vulnerability.** See
[`SECURITY.md`](SECURITY.md).

## Licence

Contributions are licensed under [AGPL-3.0-only](LICENSE), on the terms in
[`CLA.md`](CLA.md).
