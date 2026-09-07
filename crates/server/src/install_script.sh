#!/bin/sh
# AgentCordon CLI + broker installer.
#
#   curl -fsSL {server_url}/install.sh | sh
#
# This script is POSIX sh. It does not re-exec itself and it never fetches
# itself a second time: whatever URL you piped it from is the only one it
# came from. `| sh`, `| bash`, `| dash` and `| zsh` all behave identically.
set -eu

INSTALL_DIR="${HOME}/.local/bin"

# Pinned to the version of the server that served this script, not to
# `latest`. `latest` is the newest *published* release, which on a server
# built from source is older than the server itself — and v0.4.0 changed the
# signed request payload, so a CLI and broker from the wrong side of that
# change cannot talk to this server at all. Better to fail loudly than to
# install a mismatched pair.
AGTCRDN_VERSION="{version}"
GITHUB_RELEASE="https://github.com/agentcordon/agentcordon/releases/download/v{version}"

# Printed whenever the pinned release is not on GitHub — the normal state of a
# server built from `main` between releases.
#
# Only a 404 means that. A proxy, a DNS failure or a rate-limit used to land
# here too, so a network problem was reported as "there is no release" and the
# user was told to build from source (ONBOARDING-empirical.md F7).
# `fetch_status` separates the two.
no_release() {
    echo "" >&2
    echo "No published release for AgentCordon v${AGTCRDN_VERSION}." >&2
    echo "" >&2
    echo "This server is running v${AGTCRDN_VERSION}, and the installer only installs" >&2
    echo "binaries from the matching release: a CLI and broker from a different" >&2
    echo "version may not be able to talk to it." >&2
    echo "" >&2
    echo "Build the CLI and broker from source instead (README, Building from Source):" >&2
    echo "  git clone https://github.com/agentcordon/agentcordon" >&2
    echo "  cd agentcordon && cargo build --release" >&2
    echo "  install -m 0755 target/release/agentcordon target/release/agentcordon-broker ${INSTALL_DIR}/" >&2
    echo "" >&2
    exit 1
}

# The HTTP status of a GET, or "000" when the request never completed. curl
# exits non-zero on a transport failure and prints nothing, so an empty
# capture is the transport case.
fetch_status() {
    curl -fsSL -o "$2" -w '%{http_code}' "$1" 2>/dev/null || echo "000"
}

# A fetch that did not complete: DNS, a proxy, TLS, a rate-limit. Distinct from
# a 404, which really does mean the release is not published.
unreachable() {
    echo "" >&2
    echo "Could not reach ${1}." >&2
    echo "" >&2
    echo "This is a network failure, not a missing release: the request did not" >&2
    echo "complete. Check your connection, proxy settings (HTTPS_PROXY) and DNS," >&2
    echo "then run the installer again." >&2
    echo "" >&2
    exit 1
}

# The server this script came from, templated in at request time. Override with
# AGTCRDN_SERVER_URL; AGENTCORDON_SERVER_URL is accepted for compatibility with
# older copies of this script.
SERVER_URL="{server_url}"
if [ -n "${AGENTCORDON_SERVER_URL:-}" ]; then SERVER_URL="$AGENTCORDON_SERVER_URL"; fi
if [ -n "${AGTCRDN_SERVER_URL:-}" ]; then SERVER_URL="$AGTCRDN_SERVER_URL"; fi

# Set AGENTCORDON_SKIP_CHECKSUM=1 only to install from a release that predates
# the published SHA256SUMS. Verification is on by default.
SKIP_CHECKSUM="${AGENTCORDON_SKIP_CHECKSUM:-0}"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
    linux)
        case "$ARCH" in
            x86_64|amd64) TARGET="x86_64-unknown-linux-gnu" ;;
            aarch64|arm64) TARGET="aarch64-unknown-linux-gnu" ;;
            *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
        esac
        ;;
    darwin)
        case "$ARCH" in
            x86_64|amd64) TARGET="x86_64-apple-darwin" ;;
            aarch64|arm64) TARGET="aarch64-apple-darwin" ;;
            *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
        esac
        ;;
    *)
        echo "Unsupported OS: $OS (use the Windows binary from GitHub Releases)" >&2
        exit 1
        ;;
esac

TMPDIR_AC=$(mktemp -d)
cleanup() { rm -rf "$TMPDIR_AC"; }
trap cleanup EXIT INT TERM

# --- Pick a SHA-256 tool ---------------------------------------------------
# Returns the lowercase hex digest of "$1" on stdout, or exits non-zero when
# no tool is available.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | sed 's/.*= *//'
    else
        return 1
    fi
}

# --- Fetch SHA256SUMS ------------------------------------------------------
SUMS="${TMPDIR_AC}/SHA256SUMS"
if [ "$SKIP_CHECKSUM" != "1" ]; then
    echo "Fetching SHA256SUMS..."
    status=$(fetch_status "${GITHUB_RELEASE}/SHA256SUMS" "$SUMS")
    case "$status" in
        200) ;;
        404) no_release ;;
        000) unreachable "${GITHUB_RELEASE}/SHA256SUMS" ;;
        *)
            echo "" >&2
            echo "Unexpected HTTP ${status} fetching SHA256SUMS from GitHub." >&2
            echo "Nothing was installed." >&2
            exit 1
            ;;
    esac
    if ! sha256_of "$SUMS" >/dev/null 2>&1; then
        echo "No sha256sum, shasum, or openssl on this system; cannot verify downloads." >&2
        echo "Install one of them, or set AGENTCORDON_SKIP_CHECKSUM=1 to override." >&2
        exit 1
    fi
fi

# --- Download and verify ---------------------------------------------------
# $1 = asset name in the release, $2 = installed file name
fetch_verified() {
    asset="$1"
    dest="$2"
    tmp="${TMPDIR_AC}/${asset}"

    echo "Downloading ${asset}..."
    status=$(fetch_status "${GITHUB_RELEASE}/${asset}" "$tmp")
    case "$status" in
        200) ;;
        404) no_release ;;
        000) unreachable "${GITHUB_RELEASE}/${asset}" ;;
        *)
            echo "Unexpected HTTP ${status} downloading ${asset}. Nothing was installed." >&2
            exit 1
            ;;
    esac

    if [ "$SKIP_CHECKSUM" != "1" ]; then
        expected=$(awk -v a="$asset" '$2 == a || $2 == "*" a { print $1; exit }' "$SUMS")
        if [ -z "$expected" ]; then
            echo "SHA256SUMS has no entry for ${asset}; refusing to install it." >&2
            echo "Set AGENTCORDON_SKIP_CHECKSUM=1 to override." >&2
            exit 1
        fi
        actual=$(sha256_of "$tmp")
        if [ "$expected" != "$actual" ]; then
            echo "SHA-256 mismatch for ${asset}!" >&2
            echo "  expected: ${expected}" >&2
            echo "  actual:   ${actual}" >&2
            echo "Nothing was installed." >&2
            exit 1
        fi
        echo "  verified ${asset} (sha256 ok)"
    fi

    mkdir -p "$INSTALL_DIR"
    chmod +x "$tmp"
    mv "$tmp" "${INSTALL_DIR}/${dest}"
}

fetch_verified "agentcordon-${TARGET}" "agentcordon"
fetch_verified "agentcordon-broker-${TARGET}" "agentcordon-broker"

echo ""
echo "Installed:"
echo "  ${INSTALL_DIR}/agentcordon         (workspace CLI)"
echo "  ${INSTALL_DIR}/agentcordon-broker  (credential broker)"
echo ""

# Check if install dir is on PATH.
#
# `export PATH="…:$PATH"` lasts until the terminal closes, and it does not
# parse in nushell at all. What a user needs is the line *and* the file to put
# it in, which $SHELL names (ONBOARDING-empirical.md F3).
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
        echo "${INSTALL_DIR} is not on your PATH."
        echo ""
        case "${SHELL:-}" in
            */fish)
                echo "  Add it permanently (fish):"
                echo "    fish_add_path ${INSTALL_DIR}"
                ;;
            */nu)
                echo "  Add it permanently (nushell) — append to your config.nu"
                echo "  (\$nu.config-path):"
                echo "    \$env.PATH = (\$env.PATH | prepend \"${INSTALL_DIR}\")"
                ;;
            */zsh)
                echo "  Add it permanently (zsh) — append to ~/.zshrc:"
                echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
                ;;
            */bash)
                echo "  Add it permanently (bash) — append to ~/.bashrc:"
                echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
                ;;
            *)
                echo "  Add it permanently — append to your shell's startup file"
                echo "  (~/.bashrc for bash, ~/.zshrc for zsh; fish uses"
                echo "  fish_add_path, nushell uses \$env.PATH in config.nu):"
                echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
                ;;
        esac
        echo ""
        echo "  For this terminal only:"
        echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
        echo ""
        ;;
esac

echo "Get started:"
echo "  agentcordon init                 # choose your agent runtimes and install the skill"
echo "  agentcordon register --server-url ${SERVER_URL}"
