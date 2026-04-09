#!/usr/bin/env bash
set -euo pipefail

APP_NAME="AFTERLIFE"
DATA_DIR="./data"
CERTS_DIR="${DATA_DIR}/certs"
ENV_FILE="./.env"
CLIENT_CERT_EXPORT="./server.crt"
DEFAULT_PORT="2077"
CERT_VALID_DAYS="36500"
CERT_CN="localhost"
CERT_SAN_DNS_DEFAULT="localhost,afterlife.hub"
CERT_SAN_IPS_DEFAULT="127.0.0.1,::1"
CERT_SAN_DNS=""
CERT_SAN_IPS=""
DEFAULT_CONTAINER_NAME="afterlife-server"
STARTUP_WAIT_SECONDS="6"
HEALTHCHECK_LOG_TAIL="30"

GREEN="\033[1;32m"
RED="\033[1;31m"
CYAN="\033[1;36m"
YELLOW="\033[1;33m"
RESET="\033[0m"

ADMIN_USER=""
ADMIN_PASS=""
EXPOSE_PORT=""
CONTAINER_NAME="${DEFAULT_CONTAINER_NAME}"
EXTRA_SAN_DNS=""
EXTRA_SAN_IPS=""

banner() {
    echo -e "${CYAN}========================================${RESET}"
    echo -e "${CYAN}      AFTERLIFE TLS DEPLOYMENT${RESET}"
    echo -e "${CYAN}========================================${RESET}"
}

info() {
    echo -e "${YELLOW}[+] $*${RESET}"
}

success() {
    echo -e "${GREEN}[OK] $*${RESET}"
}

warn() {
    echo -e "${YELLOW}[WARN] $*${RESET}"
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

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

check_dependencies() {
    require_cmd docker
    require_cmd openssl
    require_cmd python3
    require_cmd sudo
    require_cmd awk
    require_cmd grep
    require_cmd sed
    require_cmd sleep
    require_cmd chmod
    require_cmd chown
    require_cmd mkdir
    require_cmd cp
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

trim() {
    local s="$*"
    s="${s#${s%%[![:space:]]*}}"
    s="${s%${s##*[![:space:]]}}"
    printf '%s' "$s"
}

unique_csv_append() {
    local current="$1"
    local value="$2"
    local item

    value="$(trim "$value")"
    [[ -n "$value" ]] || { printf '%s' "$current"; return; }

    IFS=',' read -r -a items <<< "$current"
    for item in "${items[@]}"; do
        item="$(trim "$item")"
        [[ "$item" == "$value" ]] && { printf '%s' "$current"; return; }
    done

    if [[ -z "$current" ]]; then
        printf '%s' "$value"
    else
        printf '%s,%s' "$current" "$value"
    fi
}

normalize_csv() {
    local input="$1"
    local output=""
    local part

    IFS=',' read -r -a parts <<< "$input"
    for part in "${parts[@]}"; do
        part="$(trim "$part")"
        [[ -n "$part" ]] || continue
        output="$(unique_csv_append "$output" "$part")"
    done

    printf '%s' "$output"
}

looks_like_ip() {
    local value="$1"
    [[ "$value" == *:* ]] && return 0
    [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

validate_dns_name() {
    local name="$1"
    [[ ${#name} -le 253 ]] || return 1
    [[ "$name" =~ ^[A-Za-z0-9.-]+$ ]] || return 1
    [[ "$name" != .* ]] || return 1
    [[ "$name" != *. ]] || return 1
    [[ "$name" != *..* ]] || return 1
    return 0
}

validate_ip_value() {
    local value="$1"
    python3 - <<'PY' "$value"
import ipaddress
import sys
try:
    ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit(1)
PY
}

validate_csv_dns() {
    local input="$1"
    local part
    [[ -z "$input" ]] && return 0
    IFS=',' read -r -a parts <<< "$input"
    for part in "${parts[@]}"; do
        part="$(trim "$part")"
        [[ -n "$part" ]] || continue
        validate_dns_name "$part" || fail "Invalid DNS SAN entry: $part"
    done
}

validate_csv_ips() {
    local input="$1"
    local part
    [[ -z "$input" ]] && return 0
    IFS=',' read -r -a parts <<< "$input"
    for part in "${parts[@]}"; do
        part="$(trim "$part")"
        [[ -n "$part" ]] || continue
        validate_ip_value "$part" || fail "Invalid IP SAN entry: $part"
    done
}

autodetect_san_candidates() {
    local detected_dns=""
    local detected_ips=""
    local host_short host_fqdn ip

    host_short="$(hostname 2>/dev/null || true)"
    host_fqdn="$(hostname -f 2>/dev/null || true)"

    if [[ -n "$host_short" && "$host_short" != "localhost" ]]; then
        detected_dns="$(unique_csv_append "$detected_dns" "$host_short")"
    fi
    if [[ -n "$host_fqdn" && "$host_fqdn" != "localhost" ]]; then
        detected_dns="$(unique_csv_append "$detected_dns" "$host_fqdn")"
    fi

    while IFS= read -r ip; do
        ip="$(trim "$ip")"
        [[ -n "$ip" ]] || continue
        [[ "$ip" == 127.* ]] && continue
        [[ "$ip" == "::1" ]] && continue
        detected_ips="$(unique_csv_append "$detected_ips" "$ip")"
    done < <(hostname -I 2>/dev/null | tr ' ' '\n')

    EXTRA_SAN_DNS="$detected_dns"
    EXTRA_SAN_IPS="$detected_ips"
}

build_final_san_lists() {
    CERT_SAN_DNS="$(normalize_csv "${CERT_SAN_DNS_DEFAULT},${EXTRA_SAN_DNS}")"
    CERT_SAN_IPS="$(normalize_csv "${CERT_SAN_IPS_DEFAULT},${EXTRA_SAN_IPS}")"
}

prompt_inputs() {
    autodetect_san_candidates
    build_final_san_lists

    echo -e "${CYAN}This will bootstrap AFTERLIFE with pinned self-signed TLS.${RESET}"
    echo -e "${CYAN}Certificate CN default: ${CERT_CN}${RESET}"
    echo -e "${CYAN}Default SAN DNS: ${CERT_SAN_DNS_DEFAULT}${RESET}"
    echo -e "${CYAN}Default SAN IPs: ${CERT_SAN_IPS_DEFAULT}${RESET}"
    [[ -n "$EXTRA_SAN_DNS" ]] && echo -e "${CYAN}Auto-detected extra DNS SANs: ${EXTRA_SAN_DNS}${RESET}"
    [[ -n "$EXTRA_SAN_IPS" ]] && echo -e "${CYAN}Auto-detected extra IP SANs: ${EXTRA_SAN_IPS}${RESET}"
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

    echo
    read -rp "TLS certificate common name/CN [${CERT_CN}]: " cert_cn_input
    CERT_CN="${cert_cn_input:-$CERT_CN}"
    validate_dns_name "$CERT_CN" || fail "Certificate CN must be a valid DNS name."

    read -rp "Extra DNS names for SAN (comma-separated) [${EXTRA_SAN_DNS}]: " dns_input
    EXTRA_SAN_DNS="${dns_input:-$EXTRA_SAN_DNS}"
    EXTRA_SAN_DNS="$(normalize_csv "$EXTRA_SAN_DNS")"
    validate_csv_dns "$EXTRA_SAN_DNS"

    read -rp "Extra IPs for SAN (comma-separated) [${EXTRA_SAN_IPS}]: " ips_input
    EXTRA_SAN_IPS="${ips_input:-$EXTRA_SAN_IPS}"
    EXTRA_SAN_IPS="$(normalize_csv "$EXTRA_SAN_IPS")"
    validate_csv_ips "$EXTRA_SAN_IPS"

    if looks_like_ip "$CERT_CN"; then
        fail "Certificate CN should be a hostname, not an IP. Put IPs in SAN instead."
    fi

    build_final_san_lists

    echo
    info "Final certificate CN: ${CERT_CN}"
    info "Final certificate SAN DNS: ${CERT_SAN_DNS}"
    info "Final certificate SAN IPs: ${CERT_SAN_IPS}"
}

prepare_folders() {
    info "Preparing folder structure..."
    sudo mkdir -p "$DATA_DIR" "$CERTS_DIR"
}

generate_tls_material() {
    local key_path="${CERTS_DIR}/server.key"
    local cert_path="${CERTS_DIR}/server.crt"

    if [[ -s "$key_path" && -s "$cert_path" ]]; then
        info "Existing TLS certificate found. Reusing it."
    else
        info "Generating self-signed TLS certificate..."
        openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
            -days "$CERT_VALID_DAYS" \
            -keyout "$key_path" \
            -out "$cert_path" \
            -subj "/CN=${CERT_CN}" \
            -addext "subjectAltName=DNS:${CERT_SAN_DNS//,/\,DNS:},IP:${CERT_SAN_IPS//,/\,IP:}" >/dev/null 2>&1
        success "TLS certificate generated."
    fi

    cp -f "$cert_path" "$CLIENT_CERT_EXPORT"
    chmod 644 "$CLIENT_CERT_EXPORT"
    success "Client certificate exported to ${CLIENT_CERT_EXPORT}"
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
        printf 'AFTERLIFE_TLS_CERT_PATH=%s
' '/app/data/certs/server.crt'
        printf 'AFTERLIFE_TLS_KEY_PATH=%s
' '/app/data/certs/server.key'
    } > "$ENV_FILE"
    chmod 600 "$ENV_FILE" || true
}

apply_bootstrap_permissions() {
    info "Applying bootstrap permissions..."
    sudo chmod 700 "$DATA_DIR"
    sudo chmod 755 "$CERTS_DIR"
    sudo chmod 644 "${CERTS_DIR}/server.crt"
    sudo chmod 600 "${CERTS_DIR}/server.key"
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

container_exists() {
    docker inspect "$CONTAINER_NAME" >/dev/null 2>&1
}

container_running() {
    [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null || true)" == "true" ]]
}

get_container_user() {
    docker inspect -f '{{.Config.User}}' "$CONTAINER_NAME" 2>/dev/null || true
}

get_container_image() {
    docker inspect -f '{{.Config.Image}}' "$CONTAINER_NAME" 2>/dev/null || true
}

resolve_named_user_uid_gid() {
    local image user_name
    image="$(get_container_image)"
    user_name="$1"

    docker run --rm --entrypoint sh "$image" -c "id -u '$user_name' && id -g '$user_name'" 2>/dev/null \
    | awk 'NR==1{u=$1} NR==2{g=$1} END{if(u ~ /^[0-9]+$/ && g ~ /^[0-9]+$/) print u\":\"g}'
}

detect_uid_gid_from_container() {
    local cfg_user
    cfg_user="$(get_container_user)"

    if [[ -z "$cfg_user" ]]; then
        echo "0:0"
        return
    fi

    if [[ "$cfg_user" =~ ^[0-9]+:[0-9]+$ ]]; then
        echo "$cfg_user"
        return
    fi

    if [[ "$cfg_user" =~ ^[0-9]+$ ]]; then
        echo "${cfg_user}:${cfg_user}"
        return
    fi

    if container_running; then
        local uid gid
        uid="$(docker exec "$CONTAINER_NAME" sh -c 'id -u' 2>/dev/null || true)"
        gid="$(docker exec "$CONTAINER_NAME" sh -c 'id -g' 2>/dev/null || true)"
        if [[ "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ ]]; then
            echo "${uid}:${gid}"
            return
        fi
    fi

    local resolved
    resolved="$(resolve_named_user_uid_gid "$cfg_user" || true)"
    if [[ "$resolved" =~ ^[0-9]+:[0-9]+$ ]]; then
        echo "$resolved"
        return
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
    sudo chmod 755 "$CERTS_DIR"
    sudo chmod 644 "${CERTS_DIR}/server.crt"
    sudo chmod 600 "${CERTS_DIR}/server.key"

    [[ -f "${DATA_DIR}/master.key" ]] && sudo chmod 600 "${DATA_DIR}/master.key" || true
    [[ -f "${DATA_DIR}/server.log" ]] && sudo chmod 644 "${DATA_DIR}/server.log" || true
    [[ -f "${DATA_DIR}/AFTERLIFE_space.db" ]] && sudo chmod 600 "${DATA_DIR}/AFTERLIFE_space.db" || true
}

logs_show_masterkey_permission_error_recent() {
    docker logs --tail "${HEALTHCHECK_LOG_TAIL}" "$CONTAINER_NAME" 2>&1 | grep -q "PermissionError: \[Errno 13\] Permission denied: '/app/data/master.key'"
}

logs_show_tls_permission_error_recent() {
    docker logs --tail "${HEALTHCHECK_LOG_TAIL}" "$CONTAINER_NAME" 2>&1 | grep -q "Unable to initialize TLS context: \[Errno 13\] Permission denied"
}

logs_show_listening_recent() {
    docker logs --tail "${HEALTHCHECK_LOG_TAIL}" "$CONTAINER_NAME" 2>&1 | grep -q "AFTERLIFE Space server listening with TLS"
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
    echo "Server cert      : $(realpath "$CLIENT_CERT_EXPORT" 2>/dev/null || echo "$CLIENT_CERT_EXPORT")"
    echo "Cert CN          : ${CERT_CN}"
    echo "Cert SAN DNS     : ${CERT_SAN_DNS}"
    echo "Cert SAN IPs     : ${CERT_SAN_IPS}"
    echo
    echo "Host permissions:"
    ls -ld "$DATA_DIR" "$CERTS_DIR" || true
    ls -l "$CERTS_DIR" || true
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
    echo "Server cert    : ${CLIENT_CERT_EXPORT}"
    echo "Cert CN        : ${CERT_CN}"
    echo "Cert SAN DNS   : ${CERT_SAN_DNS}"
    echo "Cert SAN IPs   : ${CERT_SAN_IPS}"
    echo
    echo "Client command:"
    echo "  python3 client.py --host YOUR_SERVER_IP --port ${EXPOSE_PORT} --cert ./server.crt"
    echo
    echo "Useful commands:"
    echo "  docker logs -f ${CONTAINER_NAME}"
    echo "  docker logs --tail 100 ${CONTAINER_NAME}"
    echo "  ls -ld data data/certs"
    echo "  ls -l data"
    echo
    echo "Note:"
    echo "  X.509 certificates cannot truly be expiration-free."
    echo "  This setup uses a long-lived certificate valid for ${CERT_VALID_DAYS} days."
}

main() {
    if [[ $# -gt 0 ]]; then
        warn "Ignoring unexpected positional arguments: $*"
    fi

    banner
    check_dependencies
    prompt_inputs
    prepare_folders
    generate_tls_material
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

    if logs_show_masterkey_permission_error_recent || logs_show_tls_permission_error_recent; then
        warn "Recent logs still show permission problems after runtime permission fix."
        recover_with_runtime_permissions
    fi

    if logs_show_listening_recent; then
        success "Container started successfully and is listening with TLS."
        show_diagnostics
        show_summary
        exit 0
    fi

    if logs_show_masterkey_permission_error_recent || logs_show_tls_permission_error_recent; then
        show_diagnostics
        fail "Container still has recent permission errors."
    fi

    show_diagnostics
    fail "Container did not reach healthy listening state."
}

main "$@"
