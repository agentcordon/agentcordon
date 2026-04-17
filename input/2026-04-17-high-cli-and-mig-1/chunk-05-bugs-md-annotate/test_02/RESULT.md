# RESULT — chunk-05-bugs-md-annotate / test_02

Parent chunk: chunk-05-bugs-md-annotate
Parent plan: 2026-04-17-high-cli-and-mig-1
Engineer: test_02
Branch: `docs/bugs-md-annotate-plan-2026-04-17-high`
Worktree: `.worktrees/test_02-chunk-05-bugs-md-annotate`

## Summary

Content-only edit to `input/BUGS.md`. Six finding rows (CLI-1, CLI-2, CLI-3, CLI-4, BRK-2, MIG-1) each have the marker `**Resolved by plan 2026-04-17-high-cli-and-mig-1** (commit <sha>)` appended to the end of their Fix-sketch cell, with the SHA of the merge commit that closed each finding. All other content in BUGS.md is byte-identical to the pre-chunk-05 baseline.

## Files changed

- `input/BUGS.md` — six in-cell appendages (one per finding row). No rows added or removed.

## Tests added

None. This chunk delivers a content annotation, not test code. Verification is shell-based (see Verification commands below). The parent plan's E2E test #12 (`grep 'Resolved by plan 2026-04-17-high-cli-and-mig-1' input/BUGS.md` → 6 hits) is the authoritative acceptance check and passes.

## Coverage notes

This batch of annotations covers the six findings closed by chunks 01-04 of plan `2026-04-17-high-cli-and-mig-1`:

- CLI-1 — `agentcordon init` TOCTOU-safe keypair create (chunk-02, commit 31ccd67)
- CLI-2 — CLI-side query-string-inclusive signed payload (chunk-01, commit 28973d8)
- CLI-3 — trailing-slash path canonicalisation (chunk-01, commit 28973d8)
- CLI-4 — Windows-safe `dirs::home_dir()` resolver (chunk-03, commit c6b9f5b)
- BRK-2 — broker-side query-string-inclusive payload reconstruction (chunk-01, commit 28973d8)
- MIG-1 — migration-007 pre-flight duplicate scanner (chunk-04, commit 2fe5700)

Explicitly NOT covered by this chunk (intentional — out of scope for plan `2026-04-17-high-cli-and-mig-1`):
- Remaining High findings: SRV-1 (security headers), SRV-2 (HTTPS enforcement), CORE-1 (audit unwrap panics). Those belong to future plans.
- All Medium / Low / Info findings in BUGS.md.
- The 10 "prior audit findings not resurfaced" items.
- The headline-priorities narrative (lines 24-37) which still references these High IDs — intentionally left unchanged because it is narrative context, not per-finding tracking. The table rows are where resolution state is tracked.
- The cross-cutting observations section — intentionally unchanged.

Future test engineers / reviewers: when a plan closes more findings, append the same marker shape (`**Resolved by plan <plan-id>** (commit <sha>)`) to each closed row's Fix-sketch cell. Do not remove rows; the "mark resolved inline" strategy preserves audit trail.

## Verification commands (all run from worktree)

```
$ grep -c 'Resolved by plan 2026-04-17-high-cli-and-mig-1' input/BUGS.md
6

$ grep -n 'Resolved by plan 2026-04-17-high-cli-and-mig-1' input/BUGS.md
88:| BRK-2 | High | **Signed payload omits URL query string — request reuse across query params** | crates/broker/src/auth.rs:109 | Append `uri().query()` to the signed payload; update CLI canonicalisation to match. Dual-sided with CLI-2. **Resolved by plan 2026-04-17-high-cli-and-mig-1** (commit 28973d8) |
106:| CLI-1 | High | Keypair file creation is not TOCTOU-safe | crates/cli/src/commands/init.rs:30-63 | `OpenOptions::new().create_new(true).write(true).mode(0o600)`; retry on `EEXIST` with user confirmation; `CreateFileW` + `CREATE_NEW` on Windows **Resolved by plan 2026-04-17-high-cli-and-mig-1** (commit 31ccd67) |
107:| CLI-2 | High | **Query strings silently dropped from signed payload** | crates/cli/src/commands/proxy.rs:35; signing.rs:127 | Append canonicalised query string to signed path. Dual-sided with BRK-2 **Resolved by plan 2026-04-17-high-cli-and-mig-1** (commit 28973d8) |
108:| CLI-3 | High | Trailing-slash disagreement with server path normalisation produces signature mismatches | crates/cli/src/signing.rs:127 | Canonicalise path on both ends, or reject trailing slashes at sign time **Resolved by plan 2026-04-17-high-cli-and-mig-1** (commit 28973d8) |
109:| CLI-4 | High | Windows `HOME` fallback to `/tmp` instead of `USERPROFILE` | crates/cli/src/broker.rs:311; commands/setup.rs:109 | Use `dirs::home_dir()` crate or `USERPROFILE`; last-resort fallback to current dir, never `/tmp` **Resolved by plan 2026-04-17-high-cli-and-mig-1** (commit c6b9f5b) |
143:| MIG-1 | High | **Migration 007 fails destructively on duplicate `(workspace_id, owner_id, name)` rows with no pre-flight scanner** | migrations/007_credential_name_unique.sql | Pre-check script: `SELECT workspace_id, owner_id, name, COUNT(*) FROM credentials GROUP BY 1,2,3 HAVING COUNT(*) > 1`. Document dedup path before upgrading **Resolved by plan 2026-04-17-high-cli-and-mig-1** (commit 2fe5700) |

$ git diff --stat HEAD~1 -- input/BUGS.md
 input/BUGS.md | 12 ++++++------
 1 file changed, 6 insertions(+), 6 deletions(-)
```

Exactly 12 diff-lines = 6 removed + 6 added. Every removed line has a matching added line that differs ONLY by the appended marker + SHA. All non-annotated rows, the headline-priorities section (lines 24-37), and the "## Cross-cutting observations" section are byte-identical to the baseline commit in this worktree (65f6ee6). Verified by inspection of the full `git diff` output above.

## Non-changes (invariants preserved)

- No `cargo` commands were run (content-only edit).
- No code, wiki, docs, migrations, or scripts touched.
- Six target rows annotated; every other row (CORE-*, SRV-*, BRK-3..10, CLI-5..10, POLICY-*, TEST-*, MIG-2) left untouched.
- The marker string is byte-exact: `Resolved by plan 2026-04-17-high-cli-and-mig-1`.
- The root-user bypass note about `crates/core/src/policy/cedar/mod.rs:86-95` was neither touched nor re-filed.

## Open issues / follow-ups

None from this chunk. After this merges, the parent plan `2026-04-17-high-cli-and-mig-1` has no remaining chunks — closed.

Follow-ups for the broader audit (out of scope here; tracked in BUGS.md):
- SRV-1 / SRV-2 / CORE-1 Highs await separate plans.
- Wiki articles referenced in the parent PLAN's Prior-art section (keypair-and-signing.md, broker-verification.md, data-model.md) should be updated by the knowledge-maintainer to reflect the new signed-payload format and migration 007's actual DDL. That is Phase 5d of the parent plan, not this chunk.
