# Releasing

Cutting a release is one command. Everything else happens because of the tag
that command pushes.

```bash
git switch main && git pull            # clean tree, up to date
cargo release 0.4.1 --execute          # the whole release
```

Nothing is built on your laptop, nothing is uploaded by hand, and no version
string is typed twice: `[workspace.package] version` in the root `Cargo.toml`
is the single source of truth, and the tag must equal `v` + that version or
the release workflow refuses to build.

| | |
|---|---|
| Prerequisite | `cargo install cargo-release --locked` (one time) |
| Config | [`release.toml`](../release.toml) at the repo root |
| Workflow | [`.github/workflows/release.yml`](../.github/workflows/release.yml) |
| Wall-clock | ~20-30 minutes from tag to a published release with an image |

---

## What the one command does

`cargo release <version> --execute`, run from a clean `main`:

1. **Bumps the version.** `[workspace.package] version` moves to `<version>`;
   all five crates inherit it with `version.workspace = true`, and every
   binary picks it up through `CARGO_PKG_VERSION`. `Cargo.lock` is refreshed.
2. **Writes the CHANGELOG.** `## [Unreleased]` stays on top, empty, and a
   `## [<version>] - <date>` section is inserted directly beneath it holding
   what was under Unreleased. The compare links at the bottom of the file are
   re-pointed at the new tag.
3. **Commits** as `chore: release v<version>` — one commit for the whole
   workspace.
4. **Tags** `v<version>` with an annotated tag message.
5. **Pushes** the commit and the tag to `origin`.

It refuses to run from any branch but `main`, and refuses to run with a dirty
tree. Nothing is published to crates.io — the crates are `publish = false`; the
release artifacts are the binaries and the container image.

Run it without `--execute` first to see the diff; dry-run is the default and
touches neither git nor the working tree:

```bash
cargo release 0.4.1              # prints the plan and the CHANGELOG diff
```

> **One-off for 0.4.0.** The manifest already carries `0.4.0` ahead of its tag,
> so `cargo release 0.4.0` bumps nothing and writes the compare link as
> `v0.4.0...v0.4.0`. Fix that single line to `v0.3.3...v0.4.0` in the release
> commit. From 0.4.1 on the links are correct without help.

## What the tag triggers

The push of `v<version>` starts `.github/workflows/release.yml`, five jobs:

| Job | What it does | Fails when |
|-----|--------------|-----------|
| **verify** | Runs `scripts/check-version.sh --tag v<version>`: the tag must equal `v` + the Cargo workspace version, and `CHANGELOG.md` must have a `## [<version>]` section | The tag was cut by hand, or the release commit is not what the tag points at |
| **build** | Five targets (linux x86_64/aarch64, macOS x86_64/arm64, Windows x86_64) producing `agentcordon-<target>` and `agentcordon-broker-<target>` plus `agent-cordon-server-<target>` on Linux, each with a signed build-provenance attestation | A target does not compile |
| **release** | Assembles one `SHA256SUMS`, cuts the release body from this version's CHANGELOG section, creates the GitHub Release (pre-release when the tag has `-rc`/`-beta`/`-alpha`) | An asset is missing, or the CHANGELOG section is empty |
| **container** | Buildx `linux/amd64,linux/arm64` from the Linux binaries, pushed to `ghcr.io/agentcordon/agentcordon` as `<version>`, `<major>.<minor>`, `latest` (stable only) and `sha-<short>`, with OCI labels, SBOM and provenance attestations | GHCR is unreachable, or a binary is missing |
| **smoke** | Pulls the pushed image and checks `agent-cordon-server --version`, runs the published amd64 CLI's `--version`, and fetches `/install.sh` from a started container to confirm it points at this tag | The image or a binary reports the wrong version, or `/install.sh` is pinned elsewhere |

Asset names are a contract, not a convention: the installer the server serves
at `/install.sh` (`crates/server/src/install_script.sh`) and `tools/install.ps1`
download `agentcordon-<target>` and `agentcordon-broker-<target>` from
`releases/download/v<version>` and verify them against `SHA256SUMS`. Renaming an
asset breaks every fresh install of that version.

## Verifying a release

```bash
# The release and its assets
gh release view v0.4.1

# The image, and that it reports the version it claims
docker run --rm --entrypoint agent-cordon-server \
  ghcr.io/agentcordon/agentcordon:0.4.1 --version

# The installer path users actually take
curl -fsSL https://<your-server>/install.sh | head -30
```

The smoke job does all three; this is for when you want to see it yourself.

## Pre-releases

Tag with an `-rc.N` suffix and everything adapts:

```bash
cargo release 0.5.0-rc.1 --execute
```

The GitHub Release is marked as a pre-release, and the image is pushed as
`0.5.0-rc.1` and `sha-<short>` **only** — an rc never becomes `latest` and
never moves the `0.5` tag, so `docker compose up` keeps pulling the last
stable image. The CHANGELOG still gets its own `## [0.5.0-rc.1]` section,
because `verify` insists on one for whatever tag it is building.

## When something fails

**`verify` failed.** Nothing was built, and nothing was published — this is the
cheap failure. The two causes:

- *Tag does not match the manifest.* The tag was cut by hand, or `main` moved
  after the release commit. Delete the tag locally and on the remote
  (`git tag -d v0.4.1 && git push --delete origin v0.4.1`) and re-run
  `cargo release 0.4.1 --execute` from a clean `main`.
- *No CHANGELOG section.* Add `## [0.4.1] - <date>` with the notes, amend the
  release commit, re-tag, force-push the tag.

**A later job failed** (a flaky runner, GHCR throttling). The tag is already
correct, so do not re-tag: re-run the workflow against the existing tag from
the Actions tab -> *Release* -> *Run workflow*, and give it the tag
(`v0.4.1`). `workflow_dispatch` exists for exactly this. Jobs are idempotent —
`softprops/action-gh-release` updates the existing release rather than
failing, and the image tags are overwritten with identical content.

**The release is wrong and already published.** Do not re-cut the same
version: delete or mark the release as a draft, then release a patch version
with the fix. Users' installers pin to a version and verify checksums, so a
silently replaced asset is worse than a new number.

## Related

- [`scripts/check-version.sh`](../scripts/check-version.sh) — the version
  consistency check, run by CI on every push and by the release `verify` job.
- [`deny.toml`](../deny.toml) — advisories, licences, banned crates; CI gates
  every push on it.
- [Upgrading](upgrading.md) — what an operator does with a new release.
