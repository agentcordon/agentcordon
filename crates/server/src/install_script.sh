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

# The HTTP status of a GET, written to $2, or "000" when the request never
# completed.
#
# Deliberately not `curl -f`: `-f` makes curl exit non-zero on a 404, and then
# the caller cannot tell "there is no release" from "the network is broken",
# which is the entire point of this function.
fetch_status() {
    code=$(curl -sSL -o "$2" -w '%{http_code}' "$1" 2>/dev/null) || code=""
    [ -n "$code" ] || code="000"
    printf '%s\n' "$code"
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

# AGENTCORDON_SKIP_DOWNLOAD=1 does everything the installer does *locally* --
# record the server URL, persist PATH, print the closing message -- and skips
# the GitHub download. It is for the case a server built from `main` creates:
# no release matches this version, so you built the two binaries yourself and
# dropped them in ${INSTALL_DIR}, and you still want the setup that follows.
# It is also the only way to test the local half of this script without
# reaching the public internet.
SKIP_DOWNLOAD="${AGENTCORDON_SKIP_DOWNLOAD:-0}"

# Set AGENTCORDON_NO_MODIFY_PATH=1 to be told the line to add instead of
# having a shell startup file edited. Same contract as rustup's flag of the
# same shape.
NO_MODIFY_PATH="${AGENTCORDON_NO_MODIFY_PATH:-0}"

# The CLI's user-level config. `server_url` here is what makes --server-url
# optional: this script was served *by* the server, so the machine need never
# be told which one it belongs to again. The CLI reads the flag first, then
# AGTCRDN_SERVER_URL, then this file. (The CLI does not read AGTCRDN_DATA_DIR
# -- see docs/cli-reference.md -- so neither does this.)
CONFIG_DIR="${HOME}/.agentcordon"
CONFIG_FILE="${CONFIG_DIR}/config.toml"

# Delimiters for the block appended to a shell startup file, so a rerun can
# recognise its own work and a user can find the lines to delete.
MARK_BEGIN="# >>> agentcordon >>>"
MARK_END="# <<< agentcordon <<<"

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
if [ "$SKIP_DOWNLOAD" = "1" ]; then
    SKIP_CHECKSUM=1
fi
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

if [ "$SKIP_DOWNLOAD" = "1" ]; then
    echo "AGENTCORDON_SKIP_DOWNLOAD=1: not downloading; configuring this machine only."
    echo ""
else
    fetch_verified "agentcordon-${TARGET}" "agentcordon"
    fetch_verified "agentcordon-broker-${TARGET}" "agentcordon-broker"
    echo ""
fi

# --- Record the server this script came from -------------------------------
#
# Rewrites only the `server_url` key, so a hand-added key survives. A value
# that is already what we would write is left alone; a *different* one is
# replaced and both URLs are printed, because re-running a second server's
# installer silently repointing the machine is exactly the surprise worth
# spending two lines on.
record_server_url() {
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR" 2>/dev/null || true

    previous=""
    if [ -f "$CONFIG_FILE" ]; then
        previous=$(sed -n 's/^[[:space:]]*server_url[[:space:]]*=[[:space:]]*"\(.*\)"[[:space:]]*$/\1/p' "$CONFIG_FILE" | head -n 1)
    fi

    if [ "$previous" = "$SERVER_URL" ]; then
        echo "  ${CONFIG_FILE} already records ${SERVER_URL}"
        return 0
    fi

    tmp="${CONFIG_DIR}/.config.toml.$$"
    if [ -f "$CONFIG_FILE" ]; then
        grep -v '^[[:space:]]*server_url[[:space:]]*=' "$CONFIG_FILE" > "$tmp" || true
    else
        {
            echo "# Written by the AgentCordon installer."
            echo "# The CLI reads server_url when neither --server-url nor"
            echo "# AGTCRDN_SERVER_URL is set."
        } > "$tmp"
    fi
    echo "server_url = \"${SERVER_URL}\"" >> "$tmp"
    mv "$tmp" "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE" 2>/dev/null || true

    if [ -n "$previous" ]; then
        echo "  Changed the server in ${CONFIG_FILE}:"
        echo "    was ${previous}"
        echo "    now ${SERVER_URL}"
    else
        echo "  Recorded ${SERVER_URL} in ${CONFIG_FILE}"
        echo "  (so the CLI needs no --server-url)"
    fi
}

# --- Persist PATH ----------------------------------------------------------
#
# `export PATH="...:$PATH"` printed to a terminal is gone when that terminal
# closes, and it does not parse in nushell at all
# (uat/artifacts/reviews/ONBOARDING-empirical.md F3). rustup and uv both append
# to the login shell's startup file; so does this, marker-delimited so a rerun
# is a no-op and the lines to delete are obvious.
#
# Sets PATH_FILE and PATH_LINE for the shell named by $SHELL, or leaves
# PATH_FILE empty when the shell is one we have no rule for.
resolve_path_target() {
    PATH_FILE=""
    PATH_LINE="export PATH=\"${INSTALL_DIR}:\$PATH\""
    case "${SHELL:-}" in
        */fish)
            PATH_FILE="${HOME}/.config/fish/conf.d/agentcordon.fish"
            PATH_LINE="fish_add_path \"${INSTALL_DIR}\""
            ;;
        */nu)
            PATH_FILE="${HOME}/.config/nushell/env.nu"
            PATH_LINE="\$env.PATH = (\$env.PATH | prepend \"${INSTALL_DIR}\")"
            ;;
        */zsh)
            PATH_FILE="${HOME}/.zshrc"
            ;;
        */bash)
            # A macOS Terminal tab is a *login* shell, which reads
            # ~/.bash_profile and not ~/.bashrc.
            if [ "$OS" = "darwin" ]; then
                PATH_FILE="${HOME}/.bash_profile"
            else
                PATH_FILE="${HOME}/.bashrc"
            fi
            ;;
    esac
}

persist_path() {
    resolve_path_target

    if [ "$NO_MODIFY_PATH" = "1" ]; then
        echo "  AGENTCORDON_NO_MODIFY_PATH=1: no shell startup file was changed."
        echo "  Add ${INSTALL_DIR} to your PATH yourself:"
        echo "    ${PATH_LINE}"
        return 0
    fi

    if [ -z "$PATH_FILE" ]; then
        echo "  Unrecognised shell (\$SHELL=${SHELL:-unset}); PATH was not changed."
        echo "  Add ${INSTALL_DIR} to your PATH yourself:"
        echo "    ${PATH_LINE}"
        return 0
    fi

    if [ -f "$PATH_FILE" ] && grep -qF "$MARK_BEGIN" "$PATH_FILE"; then
        echo "  ${PATH_FILE} already puts ${INSTALL_DIR} on PATH; left unchanged."
        return 0
    fi

    mkdir -p "$(dirname "$PATH_FILE")"
    {
        echo ""
        echo "$MARK_BEGIN"
        echo "# Added by the AgentCordon installer."
        echo "$PATH_LINE"
        echo "$MARK_END"
    } >> "$PATH_FILE"

    echo "  Added ${INSTALL_DIR} to PATH in ${PATH_FILE}:"
    echo "    ${PATH_LINE}"
    echo "  To undo: remove the block between \"${MARK_BEGIN}\" and \"${MARK_END}\"."
    echo "  Open a new terminal, or: ${PATH_LINE}"
}

record_server_url

case ":$PATH:" in
    *":$INSTALL_DIR:"*)
        echo "  ${INSTALL_DIR} is already on your PATH."
        ;;
    *)
        persist_path
        ;;
esac

echo ""
echo "Installed: agentcordon and agentcordon-broker in ${INSTALL_DIR} (server ${SERVER_URL})"
echo "Next: cd into a project and run \`agentcordon init\`."
