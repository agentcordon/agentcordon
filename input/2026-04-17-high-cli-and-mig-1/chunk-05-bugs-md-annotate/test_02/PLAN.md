# ENGINEER PLAN — test_02

Parent chunk: chunk-05-bugs-md-annotate
Parent plan: 2026-04-17-high-cli-and-mig-1

## Prior art consulted
- reviewed wiki/_master-index.md, wiki/process/_index.md, wiki/testing/_index.md; nothing directly relevant (BUGS.md is a tracking document, not a wiki article, and this chunk is a pure content edit with no harness work)
- parent PLAN.md "mark resolved inline" strategy — annotate in place, do not remove rows
- chunk PLAN.md — marker string is load-bearing and must be byte-exact for the parent E2E test #12 grep

## Test type
scaffolding (content-only annotation; no new test code — verification is shell-based `grep` and `git diff` checks)

## What I will test
This chunk delivers no new automated tests; instead it produces a verifiable content change in `input/BUGS.md`. Verification scenarios (all run from the worktree in RESULT.md):

- Scenario: marker count — Setup: apply six annotations. Action: `grep -c 'Resolved by plan 2026-04-17-high-cli-and-mig-1' input/BUGS.md`. Expected: exactly `6`.
- Scenario: diff shape — Action: `git diff input/BUGS.md`. Expected: exactly 6 modified lines (one per finding row); every other line byte-identical to the pre-chunk-05 baseline.
- Scenario: headline section untouched — Action: inspect lines ~24-37. Expected: no modifications.
- Scenario: cross-cutting section untouched — Action: inspect the "## Cross-cutting observations" section. Expected: no modifications.
- Scenario: each of the six findings annotated on its own row — Action: for each ID in {CLI-1, CLI-2, CLI-3, CLI-4, BRK-2, MIG-1}, `grep -n '^| <ID>' input/BUGS.md` returns a single line, and that line contains both the original Fix-sketch text and the appended marker with the correct SHA.

## Files I will create/change
- `input/BUGS.md` — append `**Resolved by plan 2026-04-17-high-cli-and-mig-1** (commit <sha>)` to the END of the Fix-sketch cell on six rows:
  - CLI-1  → commit 31ccd67
  - CLI-2  → commit 28973d8
  - CLI-3  → commit 28973d8
  - CLI-4  → commit c6b9f5b
  - BRK-2  → commit 28973d8
  - MIG-1  → commit 2fe5700

No other changes to BUGS.md. No code changes. No migrations. No scripts. No wiki edits.

## Test runner & command
No cargo. Verification is shell-only:
- `grep -c 'Resolved by plan 2026-04-17-high-cli-and-mig-1' input/BUGS.md`
- `git diff --stat input/BUGS.md` and `git diff input/BUGS.md`
- `grep -n 'Resolved by plan 2026-04-17-high-cli-and-mig-1' input/BUGS.md` — confirms six distinct rows

## Reuse
- BUGS.md row format is already established (Markdown table: `| ID | Severity | Title | Location | Fix sketch |`). Copy the marker string verbatim from the dispatcher/chunk PLAN so the parent E2E grep matches.
- Merge SHAs provided in the dispatcher message and mirrored in `input/2026-04-17-high-cli-and-mig-1/STATE.md`:
  - 28973d8 (chunk-01-signing-canon: CLI-2, CLI-3, BRK-2)
  - 31ccd67 (chunk-02-init-toctou: CLI-1)
  - c6b9f5b (chunk-03-home-resolver: CLI-4)
  - 2fe5700 (chunk-04-mig-007-precheck: MIG-1)
