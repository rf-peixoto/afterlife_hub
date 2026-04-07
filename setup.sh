#!/usr/bin/env bash
set -euo pipefail

# =========================
# Configuration
# =========================
CERT_DIR="./certs"
ENV_FILE="./.env"
COMPOSE_FILE="./docker-compose.yml"

DEFAULT_PORT="1337"

# =========================
# Colors
# =========================
GREEN="\033[1;32m"
RED="\033[1;31m"
CYAN="\033[1;36m"
YELLOW="\033[1;33m"
RESET="\033[0m"

echo -e "${CYAN}"
echo "========================================"
echo "         AFTERLIFE DEPLOYMENT"
echo "========================================"
echo -e "${RESET}"

# =========================
# Dependency checks
# =========================
for cmd in docker docker-compose openssl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo -e "${RED}[ERROR] Missing dependency: $cmd${RESET}"
        exit 1
    fi
done

# =========================
# User input
# =========================
read -rp "Admin username: " ADMIN_USER
read -rsp "Admin password: " ADMIN_PASS
echo

read -rp "Exposed port [$DEFAULT_PORT]: " PORT
PORT="${PORT:-$DEFAULT_PORT}"

# =========================
# Input validation
# =========================
if [[ -z "$ADMIN_USER" || -z "$ADMIN_PASS" ]]; then
    echo -e "${RED}[ERROR] Username and password cannot be empty.${RESET}"
    exit 1
fi

# =========================
# Create folders
# =========================
mkdir -p "$CERT_DIR"

# =========================
# Generate certificate
# =========================
echo -e "${YELLOW}[+] Generating SSL certificate...${RESET}"

openssl req -x509 -newkey rsa:4096 \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -sha256

chmod 600 "$CERT_DIR/server.key"
chmod 644 "$CERT_DIR/server.crt"

# =========================
# Create environment file
# =========================
echo -e "${YELLOW}[+] Writing environment configuration...${RESET}"

cat > "$ENV_FILE" <<EOF
ADMIN_USERNAME=${ADMIN_USER}
ADMIN_PASSWORD=${ADMIN_PASS}
SERVER_PORT=${PORT}
CERT_FILE=/app/certs/server.crt
KEY_FILE=/app/certs/server.key
EOF

chmod 600 "$ENV_FILE"

# =========================
# Start docker
# =========================
echo -e "${YELLOW}[+] Starting containers...${RESET}"

docker-compose --env-file "$ENV_FILE" up -d --build

# =========================
# Success
# =========================
echo -e "${GREEN}"
echo "========================================"
echo "AFTERLIFE IS RUNNING"
echo "========================================"
echo "URL: https://0.0.0.0:${PORT}"
echo "Certificate: ${CERT_DIR}/server.crt"
echo "Key: ${CERT_DIR}/server.key"
echo -e "${RESET}"
