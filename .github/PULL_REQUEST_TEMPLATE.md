## What

<!-- What does this change? One or two sentences. -->

## Why

<!-- The problem, not the patch — the diff already says what changed.
     Link the issue if there is one: Fixes #123 -->

## How it was tested

<!-- What you ran, and what you added. Name the test seam
     (server HTTP boundary, broker HTTP boundary, migration runner)
     and the module, e.g.
       cargo test -p agent-cordon-server --test integration vaults
     If you ran ./uat/run.sh, say so and note the result. -->

- [ ] `cargo test --workspace`
- [ ] `cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings`

## Checklist

- [ ] I have read and signed the [CLA](https://github.com/agentcordon/agentcordon/blob/main/CLA.md), and this contribution is
      offered under [AGPL-3.0-only](https://github.com/agentcordon/agentcordon/blob/main/LICENSE).
- [ ] Docs and `CHANGELOG.md` are updated, or this change needs neither: the
      page under [`docs/`](https://github.com/agentcordon/agentcordon/blob/main/docs/index.md) that my change makes wrong, an entry
      under `## [Unreleased]` for anything a user would notice, and an
      [ADR](https://github.com/agentcordon/agentcordon/blob/main/docs/adr/README.md) if this decision constrains future work.

<!-- Do not report a vulnerability here. See SECURITY.md. -->
