#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="./certs"
DATA_DIR="./data"
ENV_FILE="./.env"
DEFAULT_PORT="2077"
DEFAULT_ADMIN_USER="admin"
DEFAULT_CERT_DAYS="825"

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
    fail "docker compose was not found. Install Docker Compose v2 or docker-compose."
}

check_dependencies() {
    command -v docker >/dev/null 2>&1 || fail "docker is required."
    command -v openssl >/dev/null 2>&1 || fail "openssl is required."
}

validate_port() {
    [[ "$1" =~ ^[0-9]+$ ]] || fail "port must contain digits only."
    (( "$1" >= 1 && "$1" <= 65535 )) || fail "port must be between 1 and 65535."
}

validate_admin_user() {
    [[ "$1" =~ ^[A-Za-z0-9_]{3,24}$ ]] || fail "admin username must match the server nickname rule: 3-24 chars, letters/digits/underscore only."
}

validate_password() {
    local pass="$1"
    [[ -n "$pass" ]] || fail "admin password cannot be empty."
    (( ${#pass} >= 12 )) || fail "admin password must have at least 12 characters."
}

validate_server_name() {
    local name="$1"
    [[ -n "$name" ]] || fail "server name/IP cannot be empty."
    [[ "$name" != *"'"* && "$name" != *'"'* && "$name" != *"\\"* && "$name" != *"/"* && "$name" != *"%"* ]] || fail "server name/IP contains forbidden characters."
}

prompt_inputs() {
    read -rp "Admin username [${DEFAULT_ADMIN_USER}]: " ADMIN_USER
    ADMIN_USER="${ADMIN_USER:-$DEFAULT_ADMIN_USER}"
    validate_admin_user "$ADMIN_USER"

    read -rsp "Admin password: " ADMIN_PASS
    echo
    validate_password "$ADMIN_PASS"

    read -rp "Public hostname or IP for the server certificate SAN: " SERVER_NAME
    validate_server_name "$SERVER_NAME"

    read -rp "Exposed port [${DEFAULT_PORT}]: " EXPOSE_PORT
    EXPOSE_PORT="${EXPOSE_PORT:-$DEFAULT_PORT}"
    validate_port "$EXPOSE_PORT"
}

prepare_folders() {
    mkdir -p "$CERT_DIR" "$DATA_DIR"
    chmod 700 "$CERT_DIR" "$DATA_DIR" || true
}

write_openssl_config() {
    local san_line
    if [[ "$SERVER_NAME" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || [[ "$SERVER_NAME" == *:* ]]; then
        san_line="IP.1 = ${SERVER_NAME}"
    else
        san_line="DNS.1 = ${SERVER_NAME}"
    fi

    cat > "$CERT_DIR/openssl-server.cnf" <<CFG
[ req ]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[ dn ]
CN = ${SERVER_NAME}
O = AFTERLIFE
OU = Secure Deployment

[ req_ext ]
subjectAltName = @alt_names
extendedKeyUsage = serverAuth
keyUsage = critical, digitalSignature, keyEncipherment

[ alt_names ]
${san_line}
CFG
}

generate_certificates() {
    info "Generating local CA and server certificate..."
    write_openssl_config

    openssl genrsa -out "$CERT_DIR/ca.key" 4096 >/dev/null 2>&1
    openssl req -x509 -new -nodes -key "$CERT_DIR/ca.key" -sha256 -days 3650 \
        -out "$CERT_DIR/ca.crt" -subj "/CN=AFTERLIFE Local CA" >/dev/null 2>&1

    openssl genrsa -out "$CERT_DIR/server.key" 4096 >/dev/null 2>&1
    openssl req -new -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" \
        -config "$CERT_DIR/openssl-server.cnf" >/dev/null 2>&1
    openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
        -CAcreateserial -out "$CERT_DIR/server.crt" -days "$DEFAULT_CERT_DAYS" -sha256 \
        -extensions req_ext -extfile "$CERT_DIR/openssl-server.cnf" >/dev/null 2>&1

    chmod 600 "$CERT_DIR/ca.key" "$CERT_DIR/server.key" || true
    chmod 644 "$CERT_DIR/ca.crt" "$CERT_DIR/server.crt" || true
    rm -f "$CERT_DIR/server.csr" "$CERT_DIR/ca.srl"
    success "Certificates generated in ${CERT_DIR}/"
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
    # shellcheck disable=SC2086
    $compose --env-file "$ENV_FILE" up -d --build
}

show_summary() {
    echo -e "${GREEN}========================================${RESET}"
    echo -e "${GREEN}AFTERLIFE IS RUNNING${RESET}"
    echo -e "${GREEN}========================================${RESET}"
    echo "Server certificate : ${CERT_DIR}/server.crt"
    echo "Server private key : ${CERT_DIR}/server.key"
    echo "Client trust CA    : ${CERT_DIR}/ca.crt"
    echo "Server SAN name/IP : ${SERVER_NAME}"
    echo "Exposed port       : ${EXPOSE_PORT}"
    echo
    echo "Client example:"
    echo "  python3 client.py --host ${SERVER_NAME} --port ${EXPOSE_PORT} --cert ${CERT_DIR}/ca.crt"
}

main() {
    banner
    check_dependencies
    prompt_inputs
    prepare_folders
    generate_certificates
    write_env
    start_stack
    show_summary
}

main
