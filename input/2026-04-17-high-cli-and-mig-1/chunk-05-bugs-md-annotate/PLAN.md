# CHUNK PLAN — chunk-05-bugs-md-annotate

Parent plan: 2026-04-17-high-cli-and-mig-1
Role: test
Engineer: test_02

## Scope

Annotate the six findings resolved by chunks 01-04 in `input/BUGS.md`
with merge-commit references. Pure content edit; no code changes.

This chunk is dispatched LAST, AFTER chunks 01-04 have been merged to
main, so it can cite the actual merge SHAs.

## Acceptance criteria

- The following six rows in `input/BUGS.md` are annotated by APPENDING
  the marker `**Resolved by plan 2026-04-17-high-cli-and-mig-1**
  (commit <sha>)` to the END of the existing **Fix-sketch** cell of
  each row. The `<sha>` is the merge-commit SHA from main for the
  chunk that resolved that finding (read from
  `input/2026-04-17-high-cli-and-mig-1/STATE.md`).
  - **CLI-1** (init.rs TOCTOU) — chunk-02 SHA.
  - **CLI-2** (signed payload omits query) — chunk-01 SHA.
  - **CLI-3** (trailing-slash ambiguity) — chunk-01 SHA.
  - **CLI-4** (Windows HOME fallback) — chunk-03 SHA.
  - **BRK-2** (broker-side query-string omission) — chunk-01 SHA.
  - **MIG-1** (migration 007 destructive failure) — chunk-04 SHA.
- The marker is appended INSIDE the existing table cell (Markdown table
  row). Do not insert a new row, do not delete the row, do not change
  the Severity column, do not change the Title or Location columns. The
  Fix-sketch cell becomes:
  `<existing fix-sketch text> **Resolved by plan
  2026-04-17-high-cli-and-mig-1** (commit <sha>)`.
- A `git diff input/BUGS.md` shows ONLY six modified lines (one per
  finding). All other lines are byte-identical to pre-chunk-05.
- A `grep -c 'Resolved by plan 2026-04-17-high-cli-and-mig-1'
  input/BUGS.md` returns exactly `6`.
- The headline-priorities section (lines ~24-37 of BUGS.md) is NOT
  modified. The numbered list there refers to findings by ID; it does
  not get a per-item annotation.
- The cross-cutting observations section is NOT modified.

## Files expected to change

- `input/BUGS.md` — six row annotations as described.

## Reuse

- The `input/BUGS.md` row format is already established. Copy the
  marker string verbatim from this PLAN to ensure the grep assertion
  in the parent PLAN's E2E section #12 matches.

## Prior art (from wiki)

- `(none found)` — BUGS.md is a tracking document, not a wiki article.
  The wiki notes that resolved findings are marked inline rather than
  removed (`mark resolved inline` strategy from the parent PLAN's
  Goals section).

## Dependencies on other chunks

- chunk-01-signing-canon must merge first (provides SHAs for CLI-2,
  CLI-3, BRK-2).
- chunk-02-init-toctou must merge first (provides SHA for CLI-1).
- chunk-03-home-resolver must merge first (provides SHA for CLI-4).
- chunk-04-mig-007-precheck must merge first (provides SHA for MIG-1).

Triage will not dispatch this chunk until all four are in `merged`
state in STATE.md. The engineer reads the STATE.md to obtain the four
SHAs.

## Notes for the engineer

- **NO CARGO WORK.** This is a content edit. Do not run `cargo` at all
  unless something forces you to.
- Do NOT touch `wiki/**`, `docs/**`, the server crate, the broker
  crate, the CLI crate, any migrations, or any scripts. ONLY
  `input/BUGS.md` changes.
- The root-user bypass at `crates/core/src/policy/cedar/mod.rs:86-95`
  is intentional by design — do not refile if encountered during
  review.
- The marker string is load-bearing — the parent PLAN's E2E test #12
  greps for the exact phrase `"Resolved by plan
  2026-04-17-high-cli-and-mig-1"`. Do not abbreviate, re-case, or
  reformat it.
- Each finding row is in a different table (CORE, SRV, BRK, CLI, MIG)
  but all six rows live in `input/BUGS.md`. CLI-1/2/3/4 are in the
  CLI-* table; BRK-2 is in the BRK-* table; MIG-1 is in the MIG-*
  table. There is no separate "Resolved" table to move them to.
- Verify by reading the file post-edit and `grep -n 'Resolved by plan
  2026-04-17-high-cli-and-mig-1' input/BUGS.md` returning 6 lines.
- Read `input/2026-04-17-high-cli-and-mig-1/STATE.md` to get the
  worktree-branch and rounds columns; the merge-commit SHA will be
  added to the `notes` column by triage when merging. If a SHA is
  missing from STATE, ask triage.
