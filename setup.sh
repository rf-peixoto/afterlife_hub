#!/usr/bin/env bash
set -euo pipefail

# ==========================================
# AFTERLIFE secure deployment bootstrap
# ==========================================

CERT_DIR="./certs"
DATA_DIR="./data"
ENV_FILE="./.env"
DEFAULT_PORT="2077"

GREEN="\033[1;32m"
RED="\033[1;31m"
CYAN="\033[1;36m"
YELLOW="\033[1;33m"
RESET="\033[0m"

banner() {
    echo -e "${CYAN}"
    echo "========================================"
    echo "         AFTERLIFE DEPLOYMENT"
    echo "========================================"
    echo -e "${RESET}"
}

check_dependencies() {
    for cmd in docker docker-compose openssl; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo -e "${RED}[ERROR] Missing dependency: $cmd${RESET}"
            exit 1
        fi
    done
}

prompt_inputs() {
    read -rp "Admin username [admin]: " ADMIN_USER
    ADMIN_USER="${ADMIN_USER:-admin}"

    read -rsp "Admin password: " ADMIN_PASS
    echo

    read -rp "Exposed port [$DEFAULT_PORT]: " PORT
    PORT="${PORT:-$DEFAULT_PORT}"

    if [[ -z "$ADMIN_PASS" ]]; then
        echo -e "${RED}[ERROR] Password cannot be empty.${RESET}"
        exit 1
    fi

    if [[ ${#ADMIN_PASS} -lt 12 ]]; then
        echo -e "${RED}[ERROR] Password must have at least 12 characters.${RESET}"
        exit 1
    fi
}

prepare_folders() {
    mkdir -p "$CERT_DIR"
    mkdir -p "$DATA_DIR"
}

generate_certificates() {
    echo -e "${YELLOW}[+] Generating SSL certificate...${RESET}"

    openssl req -x509 -newkey rsa:4096 \
        -nodes \
        -keyout "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.crt" \
        -sha256 \
        -days 365 \
        -subj "/C=BR/ST=SaoPaulo/L=SaoPaulo/O=Afterlife/CN=localhost"

    chmod 600 "$CERT_DIR/server.key"
    chmod 644 "$CERT_DIR/server.crt"
}

write_env() {
    echo -e "${YELLOW}[+] Writing environment file...${RESET}"

    cat > "$ENV_FILE" <<EOF
AFTERLIFE_BOOTSTRAP_ADMIN_USERNAME=${ADMIN_USER}
AFTERLIFE_BOOTSTRAP_ADMIN_PASSWORD=${ADMIN_PASS}
AFTERLIFE_EXPOSE_PORT=${PORT}
EOF

    chmod 600 "$ENV_FILE"
}

start_stack() {
    echo -e "${YELLOW}[+] Starting Docker containers...${RESET}"
    docker-compose --env-file "$ENV_FILE" up -d --build
}

success() {
    echo -e "${GREEN}"
    echo "========================================"
    echo "AFTERLIFE IS RUNNING"
    echo "========================================"
    echo "URL: https://127.0.0.1:${PORT}"
    echo "Cert: ${CERT_DIR}/server.crt"
    echo "Key : ${CERT_DIR}/server.key"
    echo -e "${RESET}"
}

main() {
    banner
    check_dependencies
    prompt_inputs
    prepare_folders
    generate_certificates
    write_env
    start_stack
    success
}

main
