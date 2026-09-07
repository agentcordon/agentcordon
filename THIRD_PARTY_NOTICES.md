# Third-party notices

AgentCordon itself is licensed under the GNU Affero General Public License
v3.0 only (`AGPL-3.0-only`; see [LICENSE](LICENSE)). This file records
the third-party material that ships **inside** the binaries and the container
image but does not come from Cargo.

## Vendored assets

| Asset | Where | Version | Licence | Full text |
|-------|-------|---------|---------|-----------|
| Inter (variable, roman) | `crates/server/static/fonts/InterVariable.woff2` | 4.1 | SIL Open Font License 1.1 (`OFL-1.1`) | [`crates/server/static/fonts/LICENSE`](crates/server/static/fonts/LICENSE) |
| Lucide icon sprite | `crates/server/static/icons.svg` | 0.544.0 | ISC (portions derive from Feather, MIT) | [`crates/server/static/icons.LICENSE`](crates/server/static/icons.LICENSE) |

Both are embedded in the server binary and served by the admin UI, so they are
redistributed with every release artifact. Service logos under
`crates/server/static/img/logos/` are third-party trademarks used to identify
the services they name; they are not covered by AgentCordon's licence and are
not modified.

## Rust dependencies

The crate graph is checked in CI by [`cargo-deny`](https://embarkstudios.github.io/cargo-deny/)
against [`deny.toml`](deny.toml), which holds the licence allow-list, the
RUSTSEC advisory policy, and the registries a dependency may come from. Run it
locally with:

```bash
cargo deny check
```

To produce the full per-crate licence inventory for an audit:

```bash
cargo install cargo-about --locked
cargo about generate --format json > licenses.json
```
