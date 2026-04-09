#!/usr/bin/env bash
set -euo pipefail

APP_NAME="AFTERLIFE"
DATA_DIR="./data"
ENV_FILE="./.env"
DEFAULT_PORT="2077"
DEFAULT_CONTAINER_NAME="afterlife-server"
STARTUP_WAIT_SECONDS="6"
HEALTHCHECK_LOG_TAIL="50"

GREEN="\033[1;32m"
RED="\033[1;31m"
CYAN="\033[1;36m"
YELLOW="\033[1;33m"
RESET="\033[0m"

ADMIN_USER=""
ADMIN_PASS=""
EXPOSE_PORT=""
CONTAINER_NAME="${DEFAULT_CONTAINER_NAME}"

banner() {
    echo -e "${CYAN}========================================${RESET}"
    echo -e "${CYAN}         AFTERLIFE DEPLOYMENT${RESET}"
    echo -e "${CYAN}========================================${RESET}"
}

info() { echo -e "${YELLOW}[+] $*${RESET}"; }
success() { echo -e "${GREEN}[OK] $*${RESET}"; }
warn() { echo -e "${YELLOW}[WARN] $*${RESET}"; }
fail() { echo -e "${RED}[ERROR] $*${RESET}" >&2; exit 1; }

compose_cmd() {
    if docker compose version >/dev/null 2>&1; then
        echo "docker compose"; return;
    fi
    if command -v docker-compose >/dev/null 2>&1; then
        echo "docker-compose"; return;
    fi
    fail "docker compose was not found."
}

require_cmd() { command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"; }

check_dependencies() {
    require_cmd docker
    require_cmd python3
    require_cmd sudo
    require_cmd awk
    require_cmd grep
    require_cmd sed
    require_cmd sleep
    require_cmd chmod
    require_cmd chown
    require_cmd mkdir
    require_cmd stat
}

validate_port() {
    [[ "$1" =~ ^[0-9]+$ ]] || fail "Port must contain digits only."
    (( "$1" >= 1 && "$1" <= 65535 )) || fail "Port must be between 1 and 65535."
}

validate_admin_user() {
    [[ "$1" =~ ^[A-Za-z0-9_]{3,24}$ ]] || fail "Admin username must be 3-24 chars, letters/digits/underscore only."
}

validate_password() {
    local pass="$1"
    [[ -n "$pass" ]] || fail "Admin password cannot be empty."
    (( ${#pass} >= 12 )) || fail "Admin password must be at least 12 characters."
}

prompt_inputs() {
    echo -e "${CYAN}This will bootstrap AFTERLIFE in plain TCP mode.${RESET}"
    echo -e "${CYAN}The first admin account will be created with these credentials.${RESET}"
    echo

    read -rp "Admin username: " ADMIN_USER
    validate_admin_user "$ADMIN_USER"

    read -rsp "Admin password (min 12 chars): " ADMIN_PASS
    echo
    validate_password "$ADMIN_PASS"

    read -rp "Exposed port [${DEFAULT_PORT}]: " EXPOSE_PORT
    EXPOSE_PORT="${EXPOSE_PORT:-$DEFAULT_PORT}"
    validate_port "$EXPOSE_PORT"

    read -rp "Docker container name [${DEFAULT_CONTAINER_NAME}]: " CONTAINER_NAME
    CONTAINER_NAME="${CONTAINER_NAME:-$DEFAULT_CONTAINER_NAME}"
}

prepare_folders() {
    info "Preparing folder structure..."
    sudo mkdir -p "$DATA_DIR"
}

write_env() {
    info "Writing ${ENV_FILE} ..."
    : > "$ENV_FILE"
    {
        printf 'AFTERLIFE_BOOTSTRAP_ADMIN_USERNAME=%s
' "$ADMIN_USER"
        printf 'AFTERLIFE_BOOTSTRAP_ADMIN_PASSWORD=%s
' "$ADMIN_PASS"
        printf 'AFTERLIFE_EXPOSE_PORT=%s
' "$EXPOSE_PORT"
        printf 'AFTERLIFE_DB_PATH=%s
' '/app/data/AFTERLIFE_space.db'
        printf 'AFTERLIFE_MASTER_KEY_PATH=%s
' '/app/data/master.key'
        printf 'AFTERLIFE_LOG_PATH=%s
' '/app/data/server.log'
    } > "$ENV_FILE"
    chmod 600 "$ENV_FILE" || true
}

apply_bootstrap_permissions() {
    info "Applying bootstrap permissions..."
    sudo chmod 700 "$DATA_DIR"
    [[ -f "${DATA_DIR}/server.log" ]] && sudo chmod 644 "${DATA_DIR}/server.log" || true
    [[ -f "${DATA_DIR}/master.key" ]] && sudo chmod 600 "${DATA_DIR}/master.key" || true
    [[ -f "${DATA_DIR}/AFTERLIFE_space.db" ]] && sudo chmod 600 "${DATA_DIR}/AFTERLIFE_space.db" || true
}

start_stack() {
    local compose
    compose="$(compose_cmd)"
    info "Starting Docker stack..."
    $compose --env-file "$ENV_FILE" down >/dev/null 2>&1 || true
    $compose --env-file "$ENV_FILE" up -d --build
}

restart_stack() {
    local compose
    compose="$(compose_cmd)"
    info "Restarting Docker stack..."
    $compose --env-file "$ENV_FILE" restart
}

wait_for_container() {
    info "Waiting ${STARTUP_WAIT_SECONDS}s for container startup..."
    sleep "$STARTUP_WAIT_SECONDS"
}

container_exists() { docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; }
container_running() { [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null || true)" == "true" ]]; }
get_container_user() { docker inspect -f '{{.Config.User}}' "$CONTAINER_NAME" 2>/dev/null || true; }
get_container_image() { docker inspect -f '{{.Config.Image}}' "$CONTAINER_NAME" 2>/dev/null || true; }

resolve_named_user_uid_gid() {
    local image user_name
    image="$(get_container_image)"
    user_name="$1"
    docker run --rm --entrypoint sh "$image" -c "id -u '$user_name' && id -g '$user_name'" 2>/dev/null | awk 'NR==1{u=$1} NR==2{g=$1} END{if(u ~ /^[0-9]+$/ && g ~ /^[0-9]+$/) print u":"g}'
}

detect_uid_gid_from_container() {
    local cfg_user
    cfg_user="$(get_container_user)"

    if [[ -z "$cfg_user" ]]; then
        echo "0:0"; return
    fi
    if [[ "$cfg_user" =~ ^[0-9]+:[0-9]+$ ]]; then
        echo "$cfg_user"; return
    fi
    if [[ "$cfg_user" =~ ^[0-9]+$ ]]; then
        echo "${cfg_user}:${cfg_user}"; return
    fi
    if container_running; then
        local uid gid
        uid="$(docker exec "$CONTAINER_NAME" sh -c 'id -u' 2>/dev/null || true)"
        gid="$(docker exec "$CONTAINER_NAME" sh -c 'id -g' 2>/dev/null || true)"
        if [[ "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ ]]; then
            echo "${uid}:${gid}"; return
        fi
    fi
    local resolved
    resolved="$(resolve_named_user_uid_gid "$cfg_user" || true)"
    if [[ "$resolved" =~ ^[0-9]+:[0-9]+$ ]]; then
        echo "$resolved"; return
    fi
    echo "1000:1000"
}

apply_runtime_permissions() {
    local uidgid="$1"
    local uid gid
    uid="${uidgid%%:*}"
    gid="${uidgid##*:}"

    info "Applying runtime ownership and permissions for UID:GID ${uid}:${gid} ..."
    sudo chown -R "${uid}:${gid}" "$DATA_DIR"
    sudo chmod 700 "$DATA_DIR"
    [[ -f "${DATA_DIR}/master.key" ]] && sudo chmod 600 "${DATA_DIR}/master.key" || true
    [[ -f "${DATA_DIR}/server.log" ]] && sudo chmod 644 "${DATA_DIR}/server.log" || true
    [[ -f "${DATA_DIR}/AFTERLIFE_space.db" ]] && sudo chmod 600 "${DATA_DIR}/AFTERLIFE_space.db" || true
}

logs_show_masterkey_permission_error_recent() {
    docker logs --tail "${HEALTHCHECK_LOG_TAIL}" "$CONTAINER_NAME" 2>&1 | grep -q "PermissionError: \[Errno 13\] Permission denied: '/app/data/master.key'"
}

logs_show_listening_recent() {
    docker logs --tail "${HEALTHCHECK_LOG_TAIL}" "$CONTAINER_NAME" 2>&1 | grep -q "AFTERLIFE Space server listening on"
}

logs_show_logfile_path_recent() {
    docker logs --tail "${HEALTHCHECK_LOG_TAIL}" "$CONTAINER_NAME" 2>&1 | grep -q "/app/data/server.log"
}

recover_with_runtime_permissions() {
    local uidgid="${1:-}"
    if [[ -z "$uidgid" ]]; then
        uidgid="$(detect_uid_gid_from_container)"
    fi
    warn "Detected persistent permission failure. Re-applying ownership and strict permissions..."
    apply_runtime_permissions "$uidgid"
    restart_stack
    wait_for_container
}

show_diagnostics() {
    echo
    info "Diagnostics"
    echo "Container name   : ${CONTAINER_NAME}"
    echo "Container user   : $(get_container_user || true)"
    echo "Detected UID:GID : $(detect_uid_gid_from_container || true)"
    echo "Data dir         : $(realpath "$DATA_DIR" 2>/dev/null || echo "$DATA_DIR")"
    echo
    echo "Host permissions:"
    ls -ld "$DATA_DIR" || true
    ls -l "$DATA_DIR" || true
    echo
    echo "Recent docker logs:"
    docker logs --tail "${HEALTHCHECK_LOG_TAIL}" "$CONTAINER_NAME" 2>/dev/null || true
    echo
}

show_summary() {
    echo -e "${GREEN}========================================${RESET}"
    echo -e "${GREEN}AFTERLIFE DEPLOYMENT COMPLETE${RESET}"
    echo -e "${GREEN}========================================${RESET}"
    echo "Admin username : ${ADMIN_USER}"
    echo "Exposed port   : ${EXPOSE_PORT}"
    echo "Container name : ${CONTAINER_NAME}"
    echo "Log file       : ${DATA_DIR}/server.log"
    echo "Database       : ${DATA_DIR}/AFTERLIFE_space.db"
    echo
    echo "Client command:"
    echo "  python3 client.py --host YOUR_SERVER_IP --port ${EXPOSE_PORT}"
    echo
    echo "Useful commands:"
    echo "  docker logs -f ${CONTAINER_NAME}"
    echo "  docker logs --tail 100 ${CONTAINER_NAME}"
    echo "  tail -f ${DATA_DIR}/server.log"
    echo "  ls -l ${DATA_DIR}"
    echo
    echo "Note:"
    echo "  Traffic is unencrypted in this setup. Use only on trusted networks or behind a secure tunnel."
}

main() {
    if [[ $# -gt 0 ]]; then
        warn "Ignoring unexpected positional arguments: $*"
    fi

    banner
    check_dependencies
    prompt_inputs
    prepare_folders
    write_env
    apply_bootstrap_permissions
    start_stack
    wait_for_container

    if ! container_exists; then
        fail "Container '${CONTAINER_NAME}' was not created. Check your docker-compose.yml and container_name."
    fi

    local uidgid
    uidgid="$(detect_uid_gid_from_container)"
    apply_runtime_permissions "$uidgid"
    restart_stack
    wait_for_container

    if logs_show_masterkey_permission_error_recent; then
        warn "Recent logs still show permission problems after runtime permission fix."
        recover_with_runtime_permissions
    fi

    if logs_show_listening_recent; then
        success "Container started successfully and is listening."
        show_diagnostics
        show_summary
        exit 0
    fi

    if logs_show_masterkey_permission_error_recent; then
        show_diagnostics
        fail "Container still has recent permission errors."
    fi

    show_diagnostics
    fail "Container did not reach healthy listening state."
}

main "$@"
