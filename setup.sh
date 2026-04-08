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
    command -v python3 >/dev/null 2>&1 || fail "python3 is required."
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
    [[ "$name" != *"'"* && "$name" != *'"'* && "$name" != *"\\"* && "$name" != *"/"* && "$name" != *"%"* && "$name" != *$'\n'* && "$name" != *$'\r'* && "$name" != *$'\t'* ]] || fail "server name/IP contains forbidden characters."
}

classify_server_name() {
    python3 - "$1" <<'PY'
import ipaddress
import re
import sys
value = sys.argv[1].strip()
try:
    ipaddress.ip_address(value)
    print("ip")
    raise SystemExit(0)
except ValueError:
    pass
if len(value) > 253:
    print("invalid")
    raise SystemExit(0)
label_re = re.compile(r'^[A-Za-z0-9-]{1,63}$')
labels = value.split('.')
if len(labels) < 2:
    print("invalid")
    raise SystemExit(0)
for label in labels:
    if not label or label.startswith('-') or label.endswith('-') or not label_re.fullmatch(label):
        print("invalid")
        raise SystemExit(0)
print("dns")
PY
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

    SERVER_NAME_TYPE="$(classify_server_name "$SERVER_NAME")"
    [[ "$SERVER_NAME_TYPE" != "invalid" ]] || fail "server name must be a valid public DNS name or IP address."

    read -rp "Exposed port [${DEFAULT_PORT}]: " EXPOSE_PORT
    EXPOSE_PORT="${EXPOSE_PORT:-$DEFAULT_PORT}"
    validate_port "$EXPOSE_PORT"
}

prepare_folders() {
    mkdir -p "$CERT_DIR" "$DATA_DIR"
    chmod 700 "$CERT_DIR" "$DATA_DIR" || true
}

write_ca_config() {
    cat > "$CERT_DIR/openssl-ca.cnf" <<'CFG'
[ req ]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_ca

[ dn ]
CN = AFTERLIFE Local CA
O = AFTERLIFE
OU = Local Certificate Authority

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
CFG
}

write_server_config() {
    local alt_lines=""
    if [[ "$SERVER_NAME_TYPE" == "ip" ]]; then
        alt_lines="IP.1 = ${SERVER_NAME}"
    else
        alt_lines="DNS.1 = ${SERVER_NAME}"
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
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = critical, serverAuth
subjectKeyIdentifier = hash

[ alt_names ]
${alt_lines}
CFG
}

verify_server_certificate() {
    local expected=""
    if [[ "$SERVER_NAME_TYPE" == "ip" ]]; then
        expected="IP Address:${SERVER_NAME}"
    else
        expected="DNS:${SERVER_NAME}"
    fi

    if ! openssl x509 -in "$CERT_DIR/server.crt" -noout -text | grep -F "$expected" >/dev/null 2>&1; then
        fail "generated server certificate does not contain the expected SAN entry: ${expected}"
    fi
}

generate_certificates() {
    info "Generating local CA and server certificate..."
    write_ca_config
    write_server_config

    openssl genrsa -out "$CERT_DIR/ca.key" 4096 >/dev/null 2>&1
    openssl req -x509 -new -nodes -key "$CERT_DIR/ca.key" -sha256 -days 3650 \
        -out "$CERT_DIR/ca.crt" -config "$CERT_DIR/openssl-ca.cnf" >/dev/null 2>&1

    openssl genrsa -out "$CERT_DIR/server.key" 4096 >/dev/null 2>&1
    openssl req -new -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" \
        -config "$CERT_DIR/openssl-server.cnf" >/dev/null 2>&1
    openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
        -CAcreateserial -out "$CERT_DIR/server.crt" -days "$DEFAULT_CERT_DAYS" -sha256 \
        -copy_extensions copyall -extfile "$CERT_DIR/openssl-server.cnf" -extensions req_ext >/dev/null 2>&1

    cat "$CERT_DIR/server.crt" "$CERT_DIR/server.key" > "$CERT_DIR/server.pem"

    chmod 600 "$CERT_DIR/ca.key" "$CERT_DIR/server.key" "$CERT_DIR/server.pem" || true
    chmod 644 "$CERT_DIR/ca.crt" "$CERT_DIR/server.crt" || true
    rm -f "$CERT_DIR/server.csr" "$CERT_DIR/ca.srl"

    verify_server_certificate
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
    echo "Combined server PEM: ${CERT_DIR}/server.pem"
    echo "Client trust CA    : ${CERT_DIR}/ca.crt"
    echo "Server SAN name/IP : ${SERVER_NAME} (${SERVER_NAME_TYPE})"
    echo "Exposed port       : ${EXPOSE_PORT}"
    echo
    if [[ "$SERVER_NAME_TYPE" == "ip" ]]; then
        echo "Raw IP detected. Client must connect directly to that IP without --server-name."
        echo "Client example:"
        echo "  python3 client.py --host ${SERVER_NAME} --port ${EXPOSE_PORT} --cert ${CERT_DIR}/ca.crt"
    else
        echo "DNS name detected. Client should verify against that hostname."
        echo "Client example:"
        echo "  python3 client.py --host ${SERVER_NAME} --port ${EXPOSE_PORT} --cert ${CERT_DIR}/ca.crt --server-name ${SERVER_NAME}"
    fi
    echo
    echo "Quick SAN check:"
    echo "  openssl x509 -in ${CERT_DIR}/server.crt -noout -text | grep -A1 'Subject Alternative Name'"
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
