#!/usr/bin/env bash
set -euo pipefail

APP_NAME="afterlife-hub"
DATA_DIR="data"
CERT_DIR="${DATA_DIR}/certs"
ENV_FILE=".env"
DEFAULT_PORT="2077"
DEFAULT_CN="afterlife.hub"
DEFAULT_CERT_DAYS="36500"
DEFAULT_UID="1000"
DEFAULT_GID="1000"

red()    { printf '\033[1;31m%s\033[0m\n' "$*"; }
green()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; }
cyan()   { printf '\033[1;36m%s\033[0m\n' "$*"; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        red "[!] Missing required command: $1"
        exit 1
    }
}

ask_default() {
    local prompt="$1"
    local default_value="$2"
    local answer
    read -r -p "$prompt [$default_value]: " answer
    if [ -z "$answer" ]; then
        printf '%s' "$default_value"
    else
        printf '%s' "$answer"
    fi
}

ask_secret() {
    local prompt="$1"
    local answer=""
    while [ -z "$answer" ]; do
        read -r -s -p "$prompt: " answer
        printf '\n'
        [ -z "$answer" ] && yellow "[*] Value cannot be empty."
    done
    printf '%s' "$answer"
}

write_env_file() {
    local admin_user="$1"
    local admin_pass="$2"
    local port="$3"
    local container_uid="$4"
    local container_gid="$5"

    cat > "$ENV_FILE" <<EOF
AFTERLIFE_BOOTSTRAP_ADMIN_USERNAME=${admin_user}
AFTERLIFE_BOOTSTRAP_ADMIN_PASSWORD=${admin_pass}
AFTERLIFE_PORT=${port}
MASTER_KEY_PATH=/app/data/master.key
DATABASE_PATH=/app/data/afterlife.db
TLS_ENABLED=true
TLS_CERTFILE=/app/data/certs/server.crt
TLS_KEYFILE=/app/data/certs/server.key
CONTAINER_UID=${container_uid}
CONTAINER_GID=${container_gid}
EOF
}

generate_cert_if_missing() {
    local cn="$1"
    local days="$2"

    mkdir -p "$CERT_DIR"

    if [ -f "${CERT_DIR}/server.crt" ] && [ -f "${CERT_DIR}/server.key" ]; then
        yellow "[*] Existing TLS certificate and key found. Keeping current files."
        return 0
    fi

    cyan "[*] Generating self-signed TLS certificate..."
    openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
        -days "$days" \
        -keyout "${CERT_DIR}/server.key" \
        -out "${CERT_DIR}/server.crt" \
        -subj "/CN=${cn}"

    green "[+] Certificate generated:"
    printf '    - %s/server.crt\n' "$CERT_DIR"
    printf '    - %s/server.key\n' "$CERT_DIR"
}

prepare_directories_and_permissions() {
    local container_uid="$1"
    local container_gid="$2"

    cyan "[*] Preparing data directories and permissions..."
    sudo mkdir -p "$DATA_DIR" "$CERT_DIR"
    sudo chown -R "${container_uid}:${container_gid}" "$DATA_DIR"

    sudo chmod 755 "$DATA_DIR"
    sudo chmod 755 "$CERT_DIR"

    if [ -f "${CERT_DIR}/server.crt" ]; then
        sudo chmod 644 "${CERT_DIR}/server.crt"
    fi

    if [ -f "${CERT_DIR}/server.key" ]; then
        sudo chmod 600 "${CERT_DIR}/server.key"
    fi

    if [ -f "${DATA_DIR}/master.key" ]; then
        sudo chmod 600 "${DATA_DIR}/master.key"
    fi
}

export_client_cert() {
    cp -f "${CERT_DIR}/server.crt" ./server.crt
    chmod 644 ./server.crt
    green "[+] Client certificate exported to ./server.crt"
}

start_stack() {
    cyan "[*] Starting Docker stack..."
    docker compose down >/dev/null 2>&1 || true
    docker compose up -d --build
}

show_summary() {
    local port="$1"

    printf '\n'
    green "[+] Setup complete."
    printf '\n'
    printf 'Server port: %s\n' "$port"
    printf 'Pinned cert for clients: %s\n' "./server.crt"
    printf '\n'
    printf 'Client example:\n'
    printf '  python3 client.py --host YOUR_SERVER_IP --port %s --cert ./server.crt\n' "$port"
    printf '\n'
    printf 'Useful checks:\n'
    printf '  docker ps\n'
    printf '  docker logs afterlife-server\n'
    printf '  ss -ltnp | grep %s\n' "$port"
    printf '\n'
}

main() {
    require_cmd openssl
    require_cmd docker
    require_cmd sudo

    cyan "[*] ${APP_NAME} setup"
    printf '\n'

    local admin_user
    local admin_pass
    local port
    local cn
    local cert_days
    local container_uid
    local container_gid

    admin_user="$(ask_default "Bootstrap admin username" "admin")"
    admin_pass="$(ask_secret "Bootstrap admin password")"
    port="$(ask_default "Exposed port" "$DEFAULT_PORT")"
    cn="$(ask_default "Certificate CN" "$DEFAULT_CN")"
    cert_days="$(ask_default "Certificate lifetime in days" "$DEFAULT_CERT_DAYS")"
    container_uid="$(ask_default "Container UID for writable volume ownership" "$DEFAULT_UID")"
    container_gid="$(ask_default "Container GID for writable volume ownership" "$DEFAULT_GID")"

    printf '\n'
    cyan "[*] Writing ${ENV_FILE}..."
    write_env_file "$admin_user" "$admin_pass" "$port" "$container_uid" "$container_gid"

    generate_cert_if_missing "$cn" "$cert_days"
    prepare_directories_and_permissions "$container_uid" "$container_gid"
    export_client_cert
    start_stack
    show_summary "$port"
}

main "$@"