#!/usr/bin/env bash
# AFTERLIFE – hard reset script.
# Stops and removes the container, image, and all persistent data so the
# next run of setup.sh starts completely fresh, including a new .onion address.
set -euo pipefail

RED="\033[1;31m"
YELLOW="\033[1;33m"
GREEN="\033[1;32m"
RESET="\033[0m"

CONTAINER_NAME="afterlife-server"
DATA_DIR="./data"
TOR_HS_DIR="./tor-hs"
ENV_FILE="./.env"

warn() { echo -e "${YELLOW}[!] $*${RESET}"; }
info() { echo -e "${YELLOW}[+] $*${RESET}"; }
success() { echo -e "${GREEN}[OK] $*${RESET}"; }
fail() { echo -e "${RED}[ERROR] $*${RESET}" >&2; exit 1; }

echo -e "${RED}========================================${RESET}"
echo -e "${RED}     AFTERLIFE HARD RESET${RESET}"
echo -e "${RED}========================================${RESET}"
echo
warn "This will permanently delete:"
warn "  - The Docker container and image"
warn "  - The database and master encryption key (${DATA_DIR}/)"
warn "  - The Tor hidden service keys (${TOR_HS_DIR}/)"
warn "  - The .env file"
warn ""
warn "A new .onion address will be generated on next setup."
echo
read -rp "Type RESET to confirm: " confirmation
[[ "$confirmation" == "RESET" ]] || { echo "Aborted."; exit 0; }
echo

# ── Stop and remove container ─────────────────────────────────────────────────
info "Stopping container..."
docker compose down 2>/dev/null || true
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

# ── Remove image ──────────────────────────────────────────────────────────────
info "Removing Docker image..."
docker rmi -f "$(docker images -q --filter=reference='*afterlife*')" 2>/dev/null || true
docker image prune -f >/dev/null
docker builder prune -f >/dev/null

# ── Wipe persistent data ──────────────────────────────────────────────────────
info "Deleting data directory..."
sudo rm -rf "$DATA_DIR"

info "Deleting Tor hidden service keys..."
sudo rm -rf "$TOR_HS_DIR"

info "Deleting .env file..."
rm -f "$ENV_FILE"

echo
success "Reset complete. Run ./setup.sh to deploy a fresh instance."
