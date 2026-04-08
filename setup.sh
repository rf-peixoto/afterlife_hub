#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="./data"
ENV_FILE="./.env"
DEFAULT_PORT="2077"

GREEN="\033[1;32m"
RED="\033[1;31m"
CYAN="\033[1;36m"
YELLOW="\033[1;33m"
RESET="\033[0m"

banner() {
    echo -e "${CYAN}========================================${RESET}"
    echo -e "${CYAN}         AFTERLIFE DEPLOYMENT${RESET}"
    echo -e "${CYAN}========================================${RESET}"
}

info() {
    echo -e "${YELLOW}[+] $*${RESET}"
}

success() {
    echo -e "${GREEN}[OK] $*${RESET}"
}

fail() {
    echo -e "${RED}[ERROR] $*${RESET}" >&2
    exit 1
}

compose_cmd() {
    if docker compose version >/dev/null 2>&1; then
        echo "docker compose"
        return
    fi
    if command -v docker-compose >/dev/null 2>&1; then
        echo "docker-compose"
        return
    fi
    fail "docker compose was not found."
}

check_dependencies() {
    command -v docker >/dev/null 2>&1 || fail "docker is required."
}

validate_port() {
    [[ "$1" =~ ^[0-9]+$ ]] || fail "port must contain digits only."
    (( "$1" >= 1 && "$1" <= 65535 )) || fail "port must be between 1 and 65535."
}

validate_admin_user() {
    [[ "$1" =~ ^[A-Za-z0-9_]{3,24}$ ]] || fail "admin username must be 3-24 chars, letters/digits/underscore only."
}

validate_password() {
    local pass="$1"
    [[ -n "$pass" ]] || fail "admin password cannot be empty."
    (( ${#pass} >= 12 )) || fail "admin password must be at least 12 characters."
}

prompt_inputs() {
    echo -e "${CYAN}The first admin account will be created with these credentials.${RESET}"
    echo -e "${CYAN}This admin can ban users and delete any job.${RESET}"
    echo
    read -rp "Admin username: " ADMIN_USER
    validate_admin_user "$ADMIN_USER"

    read -rsp "Admin password (min 12 chars): " ADMIN_PASS
    echo
    validate_password "$ADMIN_PASS"

    read -rp "Exposed port [${DEFAULT_PORT}]: " EXPOSE_PORT
    EXPOSE_PORT="${EXPOSE_PORT:-$DEFAULT_PORT}"
    validate_port "$EXPOSE_PORT"
}

prepare_folders() {
    mkdir -p "$DATA_DIR"
}

write_env() {
    info "Writing ${ENV_FILE} ..."
    cat > "$ENV_FILE" <<ENVVARS
AFTERLIFE_BOOTSTRAP_ADMIN_USERNAME=${ADMIN_USER}
AFTERLIFE_BOOTSTRAP_ADMIN_PASSWORD=${ADMIN_PASS}
AFTERLIFE_EXPOSE_PORT=${EXPOSE_PORT}
ENVVARS
    chmod 600 "$ENV_FILE" || true
}

start_stack() {
    local compose
    compose="$(compose_cmd)"
    info "Starting Docker stack..."
    $compose --env-file "$ENV_FILE" up -d --build
}

show_summary() {
    echo -e "${GREEN}========================================${RESET}"
    echo -e "${GREEN}AFTERLIFE IS RUNNING${RESET}"
    echo -e "${GREEN}========================================${RESET}"
    echo "Admin username: ${ADMIN_USER}"
    echo "Exposed port   : ${EXPOSE_PORT}"
    echo
    echo "Client example (plain TCP):"
    echo "  python3 client.py --host YOUR_SERVER_IP --port ${EXPOSE_PORT}"
    echo
    echo "⚠️  Traffic is unencrypted – use only in trusted networks."
}

main() {
    banner
    check_dependencies
    prompt_inputs
    prepare_folders
    write_env
    start_stack
    show_summary
}

main