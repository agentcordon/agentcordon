#!/usr/bin/env bash
#
# One version, three binaries, one tag, one changelog entry.
#
# `[workspace.package] version` in the root Cargo.toml is the single source of
# truth: `cargo release` bumps it, every binary reads it through
# CARGO_PKG_VERSION, and the tag the release workflow builds from must match
# it. This script is what says so out loud — CI runs it on every push, and the
# release workflow's `verify` job runs it with `--tag` before a single binary
# is built.
#
# Usage:
#   scripts/check-version.sh                 # build the binaries and check they agree
#   scripts/check-version.sh --tag v0.4.0    # check the tag and the CHANGELOG (no build)
#   scripts/check-version.sh --tag v0.4.0 --binaries
#   BIN_DIR=target/release scripts/check-version.sh   # check binaries already built
#
# Exit status is 0 only when everything checked agrees.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TAG=""
CHECK_BINARIES=""

while [ $# -gt 0 ]; do
    case "$1" in
        --tag)
            TAG="${2:-}"
            if [ -z "$TAG" ]; then
                echo "error: --tag needs a value (e.g. --tag v0.4.0)" >&2
                exit 2
            fi
            shift 2
            ;;
        --binaries)
            CHECK_BINARIES=1
            shift
            ;;
        -h|--help)
            sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "error: unknown argument '$1'" >&2
            exit 2
            ;;
    esac
done

# Default: no --tag means this is the CI consistency check, so check binaries.
if [ -z "$TAG" ]; then
    CHECK_BINARIES=1
fi

fail() {
    echo "error: $*" >&2
    exit 1
}

# --- The source of truth --------------------------------------------------
VERSION=$(awk '
    /^\[workspace\.package\]/ { in_block = 1; next }
    /^\[/                     { in_block = 0 }
    in_block && /^version[[:space:]]*=/ {
        gsub(/[^0-9a-zA-Z.+-]/, "", $NF); print $NF; exit
    }
' Cargo.toml)

[ -n "$VERSION" ] || fail "no version in [workspace.package] of Cargo.toml"
echo "workspace version: $VERSION"

# --- Tag and CHANGELOG ----------------------------------------------------
if [ -n "$TAG" ]; then
    if [ "$TAG" != "v$VERSION" ]; then
        fail "tag '$TAG' does not match the workspace version 'v$VERSION'.
       The tag must be v + the version in [workspace.package] of Cargo.toml.
       Either the tag was cut by hand, or the release commit is missing.
       Fix: delete the tag, run 'cargo release $VERSION --execute' from main."
    fi
    echo "tag:               $TAG (matches)"

    if ! grep -Eq "^## \[${VERSION}\]" CHANGELOG.md; then
        fail "CHANGELOG.md has no '## [$VERSION]' section.
       Every release ships its own notes; the release body is cut from that
       section. Add it (cargo release writes it for you from [Unreleased]),
       commit, re-tag, and re-run."
    fi
    echo "CHANGELOG.md:      ## [$VERSION] present"
fi

# --- The binaries ---------------------------------------------------------
if [ -n "$CHECK_BINARIES" ]; then
    BIN_DIR="${BIN_DIR:-}"
    if [ -z "$BIN_DIR" ]; then
        BIN_DIR="${CARGO_TARGET_DIR:-target}/debug"
        echo "building binaries into $BIN_DIR ..."
        cargo build --workspace --bins --locked
    fi

    status=0
    for bin in agentcordon agentcordon-broker agent-cordon-server; do
        path="$BIN_DIR/$bin"
        [ -x "$path" ] || path="$BIN_DIR/$bin.exe"
        if [ ! -x "$path" ]; then
            echo "error: $bin not found in $BIN_DIR" >&2
            status=1
            continue
        fi
        # clap prints "<name> <version>".
        reported=$("$path" --version | awk '{ print $NF }')
        if [ "$reported" != "$VERSION" ]; then
            echo "error: $bin reports '$reported', workspace says '$VERSION'" >&2
            status=1
        else
            echo "$bin: $reported"
        fi
    done
    [ "$status" -eq 0 ] || fail "a binary disagrees with [workspace.package] version"
fi

echo "ok"
