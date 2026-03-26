#!/usr/bin/env bash
# AgentCordon Agent Installer
# Downloads the agentcordon binary for agent use.
#
# Usage: curl -fsSL <device-url>/install.sh | bash
#   (preferred — auto-configures workspace)
#
# Or standalone:
#   ./install-agent.sh <device-url>
#
# The binary provides both the device daemon and CLI commands.
# Each agent workspace maintains its own identity in .agentcordon/

set -euo pipefail

DEVICE_URL="${1:?Usage: install-agent.sh <device-url>}"
DEVICE_URL="${DEVICE_URL%/}"
BIN_DIR="${HOME}/.local/bin"
BIN_PATH="${BIN_DIR}/agentcordon"

echo "Downloading agentcordon from ${DEVICE_URL}..."
mkdir -p "${BIN_DIR}"

if ! curl -fsSL "${DEVICE_URL}/download/agentcordon" -o "${BIN_PATH}"; then
    echo "Error: Failed to download from ${DEVICE_URL}/download/agentcordon" >&2
    echo "Make sure the device is running and accessible." >&2
    exit 1
fi

chmod +x "${BIN_PATH}"
echo "Installed: ${BIN_PATH}"

# PATH check
case ":${PATH}:" in
    *":${BIN_DIR}:"*)
        ;;
    *)
        echo ""
        echo "WARNING: ${BIN_DIR} is not on your PATH."
        echo "Add to your shell profile:"
        echo "  export PATH=\"${BIN_DIR}:\$PATH\""
        ;;
esac

echo ""
echo "Next steps:"
echo "  agentcordon init              # Generate workspace identity"
echo "  agentcordon register          # Register with server"
echo "  agentcordon status            # Check enrollment status"
