#!/usr/bin/env bash
# AgentCordon installer — https://getcordoned.sh
#
# Zero-config quick start:
#   curl -fsSL https://getcordoned.sh | bash
#
# Interactive mode (customize port, credentials):
#   curl -fsSL https://getcordoned.sh | bash -s -- --interactive
#
# Options:
#   --interactive    Prompt for port, admin username, and password
#   --port PORT      Set host port (default: 3140)
#   --dir DIR        Set install directory (default: ~/agentcordon)
#   --help           Show this help message

# Re-exec under bash if invoked as sh (e.g. curl | sh)
if [ -z "${BASH_VERSION:-}" ]; then
  exec bash "$0" "$@" 2>/dev/null || exec /usr/bin/env bash "$0" "$@"
fi

set -euo pipefail

# --- Defaults ---
INSTALL_DIR="$HOME/agentcordon"
PORT="3140"
INTERACTIVE=false
COMPOSE_URL="https://raw.githubusercontent.com/agentcordon/agentcordon/main/docker-compose.yml"

# --- Colors ---
PURPLE='\033[0;35m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# --- Functions ---

usage() {
  echo "Usage: $0 [OPTIONS]"
  echo ""
  echo "Install and run AgentCordon (Agentic Identity Provider)"
  echo ""
  echo "Options:"
  echo "  --interactive    Prompt for port, admin username, and password"
  echo "  --port PORT      Set host port (default: 3140)"
  echo "  --dir DIR        Set install directory (default: ~/agentcordon)"
  echo "  --help           Show this help message"
  echo ""
  echo "Zero-config (default):"
  echo "  The server auto-generates admin credentials and crypto secrets."
  echo "  Check 'docker compose logs agentcordon' for the generated password."
  echo ""
  echo "Examples:"
  echo "  curl -fsSL https://getcordoned.sh | bash"
  echo "  curl -fsSL https://getcordoned.sh | bash -s -- --port 8080"
  echo "  curl -fsSL https://getcordoned.sh | bash -s -- --interactive"
  exit 0
}

info()  { echo -e "  ${GREEN}✓${NC} $1"; }
warn()  { echo -e "  ${YELLOW}!${NC} $1"; }
error() { echo -e "  ${RED}✗${NC} $1"; exit 1; }

detect_platform() {
  OS="$(uname -s)"
  ARCH="$(uname -m)"

  case "$OS" in
    Linux)  OS="linux" ;;
    Darwin) OS="darwin" ;;
    *)      error "Unsupported OS: $OS. AgentCordon supports Linux and macOS." ;;
  esac

  case "$ARCH" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)             error "Unsupported architecture: $ARCH. AgentCordon supports amd64 and arm64." ;;
  esac

  echo -e "  ${DIM}Platform: ${OS}/${ARCH}${NC}"
}

check_port() {
  local port="$1"
  if command -v ss &>/dev/null; then
    if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
      return 1
    fi
  elif command -v lsof &>/dev/null; then
    if lsof -i ":${port}" &>/dev/null; then
      return 1
    fi
  fi
  return 0
}

# --- Parse args ---

while [[ $# -gt 0 ]]; do
  case "$1" in
    --interactive) INTERACTIVE=true; shift ;;
    --port)        PORT="$2"; shift 2 ;;
    --dir)         INSTALL_DIR="$2"; shift 2 ;;
    --help|-h)     usage ;;
    *)             error "Unknown option: $1. Use --help for usage." ;;
  esac
done

# --- Banner ---

echo ""
echo -e "${PURPLE}${BOLD}  ┌─────────────────────────────────┐${NC}"
echo -e "${PURPLE}${BOLD}  │        AgentCordon               │${NC}"
echo -e "${PURPLE}${BOLD}  │   Agentic Identity Provider      │${NC}"
echo -e "${PURPLE}${BOLD}  └─────────────────────────────────┘${NC}"
echo ""

# --- Preflight ---

detect_platform

if ! command -v docker &>/dev/null; then
  error "Docker not found. Install it from https://docker.com and try again."
fi

if ! docker compose version &>/dev/null 2>&1; then
  error "Docker Compose (v2) not found. Install Docker Desktop or the compose plugin and try again."
fi

if ! docker info &>/dev/null 2>&1; then
  error "Docker daemon is not running. Start Docker and try again."
fi

info "Docker is ready ($(docker compose version --short 2>/dev/null || echo 'v2'))"

# --- Interactive mode ---

if [ "$INTERACTIVE" = true ]; then
  echo ""
  echo -e "${BOLD}  Configure your installation${NC}"
  echo ""

  # Port
  read -r -p "  Port [${PORT}]: " INPUT_PORT
  PORT="${INPUT_PORT:-$PORT}"

  # Username
  read -r -p "  Admin username [leave blank for auto]: " INPUT_USERNAME

  # Password
  if [ -n "${INPUT_USERNAME:-}" ]; then
    echo -e "  Admin password ${DIM}(leave blank to auto-generate)${NC}"
    read -r -s -p "  Password: " INPUT_PASSWORD
    echo ""
    if [ -n "$INPUT_PASSWORD" ] && [ ${#INPUT_PASSWORD} -lt 12 ]; then
      error "Password must be at least 12 characters."
    fi
  fi
fi

# --- Check port availability ---

if ! check_port "$PORT"; then
  warn "Port $PORT appears to be in use."
  if [ "$INTERACTIVE" = true ]; then
    read -r -p "  Continue anyway? [y/N]: " CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy] ]]; then
      error "Aborted. Choose a different port with --port PORT."
    fi
  else
    warn "Continuing anyway — Docker will fail if the port is truly unavailable."
  fi
fi

# --- Create install dir ---

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# --- Generate docker-compose.yml ---

cat > docker-compose.yml <<'COMPOSE'
# AgentCordon — Zero-Config Production Compose
# Generated by install.sh — https://getcordoned.sh

services:
  agentcordon:
    image: ghcr.io/agentcordon/agentcordon:latest
    container_name: agentcordon
    ports:
      - "${AGTCRDN_PORT:-3140}:3140"
    volumes:
      - agentcordon-data:/data
    env_file:
      - path: .env
        required: false
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3140/health"]
      interval: 30s
      timeout: 5s
      start_period: 15s
      retries: 3
    restart: unless-stopped

volumes:
  agentcordon-data:
COMPOSE

info "Created docker-compose.yml"

# --- Generate .env (only if customizations were made) ---

if [ "$INTERACTIVE" = true ]; then
  ENV_CONTENT="# AgentCordon — generated by installer on $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  ENV_CONTENT+="\nAGTCRDN_PORT=${PORT}"

  if [ -n "${INPUT_USERNAME:-}" ]; then
    ENV_CONTENT+="\nAGTCRDN_ROOT_USERNAME=${INPUT_USERNAME}"
    if [ -n "${INPUT_PASSWORD:-}" ]; then
      ENV_CONTENT+="\nAGTCRDN_ROOT_PASSWORD=${INPUT_PASSWORD}"
    fi
  fi

  echo -e "$ENV_CONTENT" > .env
  info "Created .env with custom settings"
elif [ "$PORT" != "3140" ]; then
  echo "AGTCRDN_PORT=${PORT}" > .env
  info "Created .env with custom port"
fi

# --- Pull and start ---

echo ""
echo "  Pulling latest image..."
docker compose pull --quiet 2>/dev/null || docker compose pull
info "Image ready"

echo ""
echo "  Starting AgentCordon..."
docker compose up -d

# --- Wait for healthy ---

echo ""
echo -n "  Waiting for server"
HEALTHY=false
for _ in $(seq 1 30); do
  if curl -sf "http://localhost:${PORT}/health" &>/dev/null; then
    HEALTHY=true
    break
  fi
  echo -n "."
  sleep 2
done
echo ""

if [ "$HEALTHY" = true ]; then
  info "AgentCordon is running"
else
  warn "Server didn't respond within 60s. It may still be starting."
  echo -e "  Check status: ${BOLD}cd $INSTALL_DIR && docker compose logs${NC}"
fi

# --- Done ---

echo ""
echo -e "${PURPLE}${BOLD}  ┌─────────────────────────────────┐${NC}"
echo -e "${PURPLE}${BOLD}  │          You're in.              │${NC}"
echo -e "${PURPLE}${BOLD}  └─────────────────────────────────┘${NC}"
echo ""
echo -e "  ${BOLD}Admin UI:${NC}  http://localhost:${PORT}"
echo ""

if [ "$INTERACTIVE" = true ] && [ -n "${INPUT_USERNAME:-}" ]; then
  echo -e "  ${BOLD}Username:${NC}  ${INPUT_USERNAME}"
  if [ -n "${INPUT_PASSWORD:-}" ]; then
    echo -e "  ${BOLD}Password:${NC}  (as entered)"
  else
    echo -e "  ${BOLD}Password:${NC}  Check docker logs: ${DIM}docker compose logs agentcordon | grep password${NC}"
  fi
else
  echo -e "  ${DIM}Admin credentials were auto-generated.${NC}"
  echo -e "  ${BOLD}View them:${NC} cd $INSTALL_DIR && docker compose logs agentcordon | grep -i password"
fi

echo ""
echo -e "  ${BOLD}Next steps:${NC}"
echo -e "    1. Log in and add your API credentials"
echo -e "    2. Run ${BOLD}agentcordon setup http://localhost:${PORT}${NC} in your agent's project"
echo -e "    3. Point your agents at AgentCordon — they never see your secrets"
echo ""
echo -e "  ${BOLD}Commands:${NC}"
echo -e "    Stop:    cd $INSTALL_DIR && docker compose down"
echo -e "    Start:   cd $INSTALL_DIR && docker compose up -d"
echo -e "    Logs:    cd $INSTALL_DIR && docker compose logs -f"
echo -e "    Update:  curl -fsSL https://getcordoned.sh | bash"
echo ""
