# 1. SQLite is the only storage backend

- **Status:** Accepted
- **Date:** 2026-09-04

## Context

The store carried two backends. The SQLite backend under `crates/core/src/storage/sqlite/`
was the production path and the one every test, migration and deployment used. Alongside it
sat a PostgreSQL backend behind a `postgres` cargo feature, which was never finished — most
store operations returned "not yet implemented" — and which CI did not compile, so it rotted
unseen. Its presence was not free:

- `build_audit_filter_sql` and `build_credential_update_sql` in `crates/core/src/storage/shared.rs`
  carried a two-dialect abstraction (a placeholder-style enum for `?` versus `$N`, a JSON cast
  suffix for `""` versus `::jsonb`) for a dialect nothing ran.
- `AGTCRDN_DB_TYPE` and `AGTCRDN_DB_URL` were read at startup and documented, so an operator
  could configure a backend that could not store anything.
- The `sqlx` dependency, and a `sqlite` feature that could only be switched off to produce a
  server with no storage at all.
- The architecture spec proposed splitting storage into a traits crate and per-backend crates,
  each compiled in CI, and a parity suite parameterised over backends — a large amount of work
  whose only justification was the second backend.

## Decision

Delete the PostgreSQL backend, the `postgres` cargo feature, and the `sqlx` dependency. Delete
the `sqlite` feature too: with one backend, a feature flag for it has no legal "off" position.
SQLite is the storage backend.

- `AGTCRDN_DB_PATH` is the only database setting. `AGTCRDN_DB_TYPE` and `AGTCRDN_DB_URL` are no
  longer read, and a server started with either set **refuses to boot** with a message naming
  the variable, rather than silently opening a SQLite file literally called `postgres://…`
  (`crates/server/src/config.rs`).
- The two-dialect abstraction is removed from the SQL builders.
- Storage stays one crate. The traits-and-domain / per-backend crate split from the spec is
  dropped, because its purpose was backend parity. The `storage/shared.rs` versus
  `storage/sqlite/` module boundary is kept as the seam.
- No parity suite is written. What replaces it is SQLite-specific correctness pinned at the
  seams: one place that maps SQLite constraint errors to `Conflict`/`NotFound`
  (`crates/core/src/storage/sqlite/helpers/errors.rs`), one fixed-precision timestamp format
  (`crates/core/src/domain/time.rs`), and storage-contract tests driven through the HTTP seam
  with fault injection (`crates/server/tests/storage_contracts.rs`).

## Consequences

- There is no migration path off SQLite and none is needed: nothing was ever deployed on
  Postgres, because it could not run.
- Horizontal scale is now explicitly a single-writer story. That is why a second server on the
  same database is refused with an advisory `flock` on `<db path>.lock` at startup
  (`AGTCRDN_REPLICA_MODE=unsafe-shared` is the escape hatch), rather than tolerated.
- Operators upgrading must delete `AGTCRDN_DB_TYPE` and `AGTCRDN_DB_URL` from their `.env`
  before starting a 0.4.0 server, or it will not boot. This is deliberate: a silent ignore
  would have left the operator believing they were on a backend they were not.
- Forward-only SQLite migrations under `migrations/` remain the schema mechanism, including
  the `-- migration-mode: foreign_keys_off` marker for table rebuilds.
- If Postgres is ever wanted, it is a new spec, starting from a clean seam rather than from a
  half-written backend.
