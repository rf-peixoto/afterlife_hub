#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="./data"
TOR_HS_DIR="./tor-hs"
TOR_DATA_DIR="./tor-data"
ENV_FILE="./.env"
DEFAULT_CONTAINER_NAME="afterlife-server"
STARTUP_WAIT_SECONDS=120
HEALTHCHECK_LOG_TAIL=80

GREEN="\033[1;32m"
RED="\033[1;31m"
CYAN="\033[1;36m"
YELLOW="\033[1;33m"
RESET="\033[0m"

ADMIN_USER=""
ADMIN_PASS=""
CONTAINER_NAME="${DEFAULT_CONTAINER_NAME}"

banner() {
    echo -e "${CYAN}========================================${RESET}"
    echo -e "${CYAN}     AFTERLIFE TOR DEPLOYMENT${RESET}"
    echo -e "${CYAN}========================================${RESET}"
}

info()    { echo -e "${YELLOW}[+] $*${RESET}"; }
success() { echo -e "${GREEN}[OK] $*${RESET}"; }
warn()    { echo -e "${YELLOW}[WARN] $*${RESET}"; }
fail()    { echo -e "${RED}[ERROR] $*${RESET}" >&2; exit 1; }

compose_cmd() {
    if docker compose version >/dev/null 2>&1; then
        echo "docker compose"; return
    fi
    if command -v docker-compose >/dev/null 2>&1; then
        echo "docker-compose"; return
    fi
    fail "docker compose was not found."
}

require_cmd() { command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"; }

check_dependencies() {
    require_cmd docker
    require_cmd sudo
    require_cmd awk
    require_cmd grep
    require_cmd sleep
    require_cmd chmod
    require_cmd chown
    require_cmd mkdir
}

validate_admin_user() {
    [[ "$1" =~ ^[A-Za-z0-9_]{3,12}$ ]] || fail "Admin username must be 3-12 chars, letters/digits/underscore only."
}

validate_password() {
    local pass="$1"
    [[ -n "$pass" ]]          || fail "Admin password cannot be empty."
    (( ${#pass} >= 12 ))      || fail "Admin password must be at least 12 characters."
    [[ "$pass" != *$'\n'* ]]  || fail "Admin password cannot contain newline characters."
    [[ "$pass" != *$'\r'* ]]  || fail "Admin password cannot contain carriage return characters."
}

prompt_inputs() {
    echo -e "${CYAN}This will bootstrap AFTERLIFE as a Tor hidden service.${RESET}"
    echo -e "${CYAN}The server will NOT be reachable via a raw IP address.${RESET}"
    echo

    read -rp  "Admin username (3-12 chars): " ADMIN_USER
    validate_admin_user "$ADMIN_USER"

    read -rsp "Admin password (min 12 chars): " ADMIN_PASS
    echo
    validate_password "$ADMIN_PASS"

    read -rp  "Docker container name [${DEFAULT_CONTAINER_NAME}]: " CONTAINER_NAME
    CONTAINER_NAME="${CONTAINER_NAME:-$DEFAULT_CONTAINER_NAME}"
}

prepare_folders() {
    info "Preparing folder structure..."
    sudo mkdir -p "$DATA_DIR" "$TOR_HS_DIR" "$TOR_DATA_DIR"
    sudo chmod 700 "$DATA_DIR"
    # tor-hs and tor-data start as root:root. We fix ownership after the
    # image is built, once we know debian-tor's actual UID inside the container.
    sudo chmod 755 "$TOR_HS_DIR"
    sudo chmod 755 "$TOR_DATA_DIR"
}

write_env() {
    info "Writing ${ENV_FILE} ..."
    : > "$ENV_FILE"
    {
        printf 'AFTERLIFE_BOOTSTRAP_ADMIN_USERNAME=%s\n' "$ADMIN_USER"
        printf 'AFTERLIFE_BOOTSTRAP_ADMIN_PASSWORD=%s\n' "$ADMIN_PASS"
        printf 'AFTERLIFE_DB_PATH=%s\n'         '/app/data/AFTERLIFE.db'
        printf 'AFTERLIFE_MASTER_KEY_PATH=%s\n' '/app/data/master.key'
        printf 'AFTERLIFE_LOG_PATH=%s\n'        '/app/data/server.log'
        printf 'AFTERLIFE_PORT=%s\n'            '2077'
    } > "$ENV_FILE"
    chmod 600 "$ENV_FILE" || true
}

apply_permissions() {
    info "Applying data directory permissions..."
    sudo chmod 700 "$DATA_DIR"
    [[ -f "${DATA_DIR}/master.key" ]]   && sudo chmod 600 "${DATA_DIR}/master.key"   || true
    [[ -f "${DATA_DIR}/server.log" ]]   && sudo chmod 644 "${DATA_DIR}/server.log"   || true
    [[ -f "${DATA_DIR}/AFTERLIFE.db" ]] && sudo chmod 600 "${DATA_DIR}/AFTERLIFE.db" || true
}

build_image() {
    local compose
    compose="$(compose_cmd)"
    info "Building Docker image..."
    $compose --env-file "$ENV_FILE" build
}

fix_tor_directory_ownership() {
    # Tor requires HiddenServiceDir to be owned by the tor user (debian-tor)
    # and mode 700. On some Docker configurations (user namespace remapping),
    # root inside the container cannot chown volume-mounted host directories.
    # We solve this on the HOST: query debian-tor's UID from the built image,
    # then chown the directories before the container starts.
    local compose
    compose="$(compose_cmd)"

    info "Querying debian-tor UID from built image..."
    local deb_tor_uid deb_tor_gid
    deb_tor_uid="$($compose --env-file "$ENV_FILE" run \
        --rm --no-deps --entrypoint "" \
        afterlife-server \
        id -u debian-tor 2>/dev/null || echo "")"
    deb_tor_gid="$($compose --env-file "$ENV_FILE" run \
        --rm --no-deps --entrypoint "" \
        afterlife-server \
        id -g debian-tor 2>/dev/null || echo "")"

    if [[ "$deb_tor_uid" =~ ^[0-9]+$ && "$deb_tor_gid" =~ ^[0-9]+$ ]]; then
        info "Setting tor directory ownership to debian-tor (UID ${deb_tor_uid} GID ${deb_tor_gid})..."
        sudo chown "${deb_tor_uid}:${deb_tor_gid}" "$TOR_HS_DIR"
        sudo chmod 700 "$TOR_HS_DIR"
        sudo chown "${deb_tor_uid}:${deb_tor_gid}" "$TOR_DATA_DIR"
        sudo chmod 700 "$TOR_DATA_DIR"
    else
        warn "Could not determine debian-tor UID. Falling back to UID 107 (Debian default)."
        sudo chown "107:107" "$TOR_HS_DIR"
        sudo chmod 700 "$TOR_HS_DIR"
        sudo chown "107:107" "$TOR_DATA_DIR"
        sudo chmod 700 "$TOR_DATA_DIR"
    fi
}

start_stack() {
    local compose
    compose="$(compose_cmd)"
    info "Starting Docker stack..."
    $compose --env-file "$ENV_FILE" down >/dev/null 2>&1 || true
    $compose --env-file "$ENV_FILE" up -d
}

container_exists() {
    docker inspect "$CONTAINER_NAME" >/dev/null 2>&1
}

logs_show_listening() {
    docker logs --tail "${HEALTHCHECK_LOG_TAIL}" "$CONTAINER_NAME" 2>&1 \
        | grep -q "server_listening"
}

logs_show_permission_error() {
    docker logs --tail "${HEALTHCHECK_LOG_TAIL}" "$CONTAINER_NAME" 2>&1 \
        | grep -q "Permission denied"
}

wait_for_onion_address() {
    info "Waiting for Tor hidden service to start (up to ${STARTUP_WAIT_SECONDS}s)..."
    local elapsed=0
    while (( elapsed < STARTUP_WAIT_SECONDS )); do
        local addr
        addr="$(docker logs --tail "${HEALTHCHECK_LOG_TAIL}" "$CONTAINER_NAME" 2>&1 \
            | grep "Onion address" \
            | awk '{print $NF}' \
            | tail -1)"
        if [[ -n "$addr" ]]; then
            echo "$addr"
            return 0
        fi
        sleep 1
        (( elapsed++ ))
    done
    return 1
}

show_diagnostics() {
    echo
    info "Diagnostics"
    echo "Container : ${CONTAINER_NAME}"
    echo "Data dir  : $(realpath "$DATA_DIR" 2>/dev/null || echo "$DATA_DIR")"
    echo "HS dir    : $(realpath "$TOR_HS_DIR" 2>/dev/null || echo "$TOR_HS_DIR")"
    echo "Tor data  : $(realpath "$TOR_DATA_DIR" 2>/dev/null || echo "$TOR_DATA_DIR")"
    echo
    echo "Host permissions:"
    ls -ld "$DATA_DIR" "$TOR_HS_DIR" "$TOR_DATA_DIR" || true
    echo
    echo "Recent docker logs:"
    docker logs --tail "${HEALTHCHECK_LOG_TAIL}" "$CONTAINER_NAME" 2>/dev/null || true
    echo
}

show_summary() {
    local onion_addr="$1"
    echo -e "${GREEN}========================================${RESET}"
    echo -e "${GREEN}AFTERLIFE DEPLOYMENT COMPLETE${RESET}"
    echo -e "${GREEN}========================================${RESET}"
    echo "Admin username  : ${ADMIN_USER}"
    echo "Container name  : ${CONTAINER_NAME}"
    echo "Log file        : ${DATA_DIR}/server.log"
    echo "Database        : ${DATA_DIR}/AFTERLIFE.db"
    echo
    echo -e "${CYAN}Onion address   : ${onion_addr}${RESET}"
    echo
    echo "Client command (requires proxychains + Tor):"
    echo "  proxychains python3 client.py --host ${onion_addr} --port 2077"
    echo
    echo "The .onion address is stable across restarts because the keys are stored in:"
    echo "  ${TOR_HS_DIR}/"
    echo "Back up this directory if you want to preserve the address permanently."
    echo
    echo "Useful commands:"
    echo "  docker logs -f ${CONTAINER_NAME}"
    echo "  tail -f ${DATA_DIR}/server.log"
    echo "  ls -l ${DATA_DIR}"
}

main() {
    banner
    check_dependencies
    prompt_inputs
    prepare_folders
    write_env
    apply_permissions
    build_image
    fix_tor_directory_ownership
    start_stack

    if ! container_exists; then
        fail "Container '${CONTAINER_NAME}' was not created. Check docker-compose.yml."
    fi

    sleep 3

    local onion_addr
    if ! onion_addr="$(wait_for_onion_address)"; then
        show_diagnostics
        fail "Timed out waiting for Tor hidden service address. Check logs above."
    fi

    sleep 2

    if ! logs_show_listening; then
        if logs_show_permission_error; then
            show_diagnostics
            fail "Container has permission errors. Check logs above."
        fi
        show_diagnostics
        fail "Container did not reach listening state. Check logs above."
    fi

    success "Container is up and listening."
    show_summary "$onion_addr"
}

main "$@"
