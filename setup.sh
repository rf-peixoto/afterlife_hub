#!/usr/bin/env bash
# AFTERLIFE deployment helper. Run on the server from the project directory.
#   ./setup.sh                 first install (or rebuild/upgrade an existing one)
#   ./setup.sh --update-images re-pin the base images to their latest digests
#
# Works with Docker or Podman, rootful or rootless. Ownership of the data
# directories is set from INSIDE a helper container, so the uids always match
# what the real containers see (rootless engines remap uids on the host).
set -euo pipefail
umask 077

APP_UID=10001
TOR_UID=10002
ENV_FILE="./.env"
MARKER="./.afterlife-installed"
APP_IMAGE="afterlife-app:local"
DEFAULT_POW_DIFFICULTY=5
PYTHON_TAG="python:3.12-slim-trixie"
DEBIAN_TAG="debian:trixie-slim"
WAIT_SECONDS=240
UPDATE_IMAGES=0
[[ "${1:-}" == "--update-images" ]] && UPDATE_IMAGES=1

GREEN="\033[1;32m"; RED="\033[1;31m"; CYAN="\033[1;36m"; YELLOW="\033[1;33m"; RESET="\033[0m"
info()    { echo -e "${YELLOW}[+] $*${RESET}"; }
success() { echo -e "${GREEN}[OK] $*${RESET}"; }
warn()    { echo -e "${YELLOW}[WARN] $*${RESET}"; }
fail()    { echo -e "${RED}[ERROR] $*${RESET}" >&2; exit 1; }

compose() { docker compose --env-file "$ENV_FILE" "$@"; }

# Run a command as root inside a throw-away container that has the given
# project directories mounted. SELinux labelling is disabled for this helper
# only, so it never relabels files away from the running service.
helper() {
    local mounts=() d
    for d in data secrets tor-hs tor-data run; do mounts+=(-v "$PWD/$d:/w/$d"); done
    docker run --rm -i --user 0 --network none --security-opt label=disable \
        "${mounts[@]}" --entrypoint /bin/sh "$APP_IMAGE" -c "$1"
}

check_dependencies() {
    command -v docker >/dev/null 2>&1 || fail "docker (or podman with the docker CLI shim) is not installed."
    docker compose version >/dev/null 2>&1 || fail "A compose provider is required (docker compose v2, or podman with docker-compose/podman-compose)."
    [[ -f docker-compose.yml && -f server.py ]] || fail "Run this script from the AFTERLIFE project directory."
    if docker --version 2>/dev/null | grep -qi podman; then
        info "Container engine: Podman"
    else
        info "Container engine: Docker"
    fi
}

# ---------------------------------------------------------------- .env (no secrets in it)
env_get() {
    if [[ -f "$ENV_FILE" ]]; then
        { grep -E "^$1=" "$ENV_FILE" || true; } | tail -1 | cut -d= -f2- | sed -e "s/^'//" -e "s/'$//"
    fi
}

env_set() {
    local key="$1" value="$2" tmp
    [[ "$value" =~ ^[A-Za-z0-9_.:@/+-]*$ ]] || fail "Refusing to write unsafe value for $key."
    tmp="$(mktemp)"
    if [[ -f "$ENV_FILE" ]]; then grep -vE "^$key=" "$ENV_FILE" > "$tmp" || true; fi
    printf "%s='%s'\n" "$key" "$value" >> "$tmp"   # single quotes: compose never interpolates them
    mv "$tmp" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
}

# ---------------------------------------------------------------- prompts
ADMIN_USER=""
ADMIN_PASS=""

prompt_admin() {
    local pass2
    read -rp "Admin username (3-12 chars): " ADMIN_USER
    [[ "$ADMIN_USER" =~ ^[A-Za-z0-9_]{3,12}$ ]] || fail "Admin username must be 3-12 chars: letters, digits, underscore."
    read -rsp "Admin password (12-128 chars): " ADMIN_PASS; echo
    read -rsp "Repeat admin password: " pass2; echo
    [[ "$ADMIN_PASS" == "$pass2" ]] || fail "Passwords do not match."
    (( ${#ADMIN_PASS} >= 12 && ${#ADMIN_PASS} <= 128 )) || fail "Admin password must be 12-128 characters."
    [[ "$ADMIN_PASS" != *[$'\n\r\t']* ]] || fail "Admin password cannot contain newlines or tabs."
}

prompt_pow() {
    local d
    echo
    echo -e "${CYAN}Anti-bot proof-of-work BASE difficulty${RESET} (scrypt, ~20 ms per guess; each bit doubles the work)"
    echo "  1-3 light | 4-6 moderate (recommended) | 7-9 strong | 10+ heavy"
    read -rp "Base difficulty [${DEFAULT_POW_DIFFICULTY}]: " d
    d="${d:-$DEFAULT_POW_DIFFICULTY}"
    if ! [[ "$d" =~ ^[0-9]+$ ]] || (( d < 1 || d > 20 )); then fail "Difficulty must be a whole number from 1 to 20."; fi
    env_set AFTERLIFE_POW_DIFFICULTY "$d"
}

# ---------------------------------------------------------------- images
pin_images() {
    if [[ -n "$(env_get PYTHON_IMAGE)" && -n "$(env_get DEBIAN_IMAGE)" && $UPDATE_IMAGES -eq 0 ]]; then
        info "Using pinned base images from .env (run with --update-images to refresh)."
        return
    fi
    info "Pulling and pinning base images by digest..."
    local tag digest
    for tag in "$PYTHON_TAG" "$DEBIAN_TAG"; do
        docker pull -q "$tag" >/dev/null
        digest="$(docker image inspect --format '{{index .RepoDigests 0}}' "$tag")"
        [[ "$digest" == *@sha256:* ]] || fail "Could not determine digest for $tag."
        if [[ "$tag" == python:* ]]; then env_set PYTHON_IMAGE "$digest"; else env_set DEBIAN_IMAGE "$digest"; fi
        success "$tag -> $digest"
    done
}

build_images() {
    if [[ "${AFTERLIFE_SETUP_SKIP_BUILD:-0}" == "1" ]]; then return; fi
    info "Building images (tor from deb.torproject.org, verified by key fingerprint)..."
    compose build
}

# ---------------------------------------------------------------- filesystem (via helper container)
prepare_folders() {
    info "Preparing directories and ownership..."
    mkdir -p ./data ./secrets ./tor-hs ./tor-data ./run 2>/dev/null || true
    local script="set -e
        chown ${APP_UID}:${APP_UID} /w/data /w/secrets /w/run
        chown -R ${APP_UID}:${APP_UID} /w/data /w/secrets
        chown -R ${TOR_UID}:${TOR_UID} /w/tor-hs /w/tor-data
        chmod 700 /w/data /w/secrets /w/tor-hs /w/tor-data
        chmod 755 /w/run"
    if helper "$script" 2>/dev/null; then return; fi
    # Typical cause: directories left by an older setup.sh that chowned them on the
    # HOST to uid 10001/10002, which a rootless engine cannot map. Reclaim them for
    # the current user once, then let the container assign the right ids.
    warn "Could not set ownership from the container; reclaiming leftover directories (sudo)..."
    command -v sudo >/dev/null 2>&1 || fail "Please run: chown -R $(id -u):$(id -g) data secrets tor-hs tor-data run   (as root), then re-run."
    sudo chown -R "$(id -u):$(id -g)" ./data ./secrets ./tor-hs ./tor-data ./run
    helper "$script" || fail "Could not set directory ownership inside the container."
}

existing_install() {
    [[ -f "$MARKER" ]] && return 0
    helper "test -f /w/data/AFTERLIFE.db" 2>/dev/null
}

write_bootstrap_password() {
    # One-time secret file, read and deleted by the server on first start. It is
    # passed through stdin (never argv), and never lands in .env, an environment
    # variable, or an image.
    printf '%s\n' "$ADMIN_PASS" | helper "set -e; umask 077
        cat > /w/secrets/bootstrap_admin_password
        chown ${APP_UID}:${APP_UID} /w/secrets/bootstrap_admin_password
        chmod 600 /w/secrets/bootstrap_admin_password"
    ADMIN_PASS=""
}

wait_for() {
    local what="$1" service="$2" pattern="$3" i=0 logs
    info "Waiting for $what (up to ${WAIT_SECONDS}s)..."
    while (( i < WAIT_SECONDS )); do
        logs="$(compose logs --no-color "$service" 2>/dev/null || true)"
        if grep -q "$pattern" <<<"$logs"; then return 0; fi
        if grep -q "FATAL" <<<"$logs"; then
            grep -v '^$' <<<"$logs" | tail -40; fail "$service failed to start (see above)."
        fi
        sleep 1; i=$((i + 1))
    done
    compose logs --no-color --tail 60 "$service" || true
    fail "Timed out waiting for $what."
}

main() {
    check_dependencies
    if [[ ! -f "$ENV_FILE" ]]; then : > "$ENV_FILE"; chmod 600 "$ENV_FILE"; fi
    local fresh=1
    if [[ -f "$MARKER" ]]; then fresh=0; fi
    if (( fresh )); then
        echo -e "${CYAN}This bootstraps AFTERLIFE as a Tor onion service. No port is exposed to the internet.${RESET}"
        prompt_admin
        prompt_pow
    else
        info "Existing installation detected: rebuilding/upgrading without touching accounts."
    fi
    [[ "${AFTERLIFE_SETUP_SKIP_BUILD:-0}" == "1" ]] || pin_images
    build_images
    prepare_folders
    if (( fresh )) && existing_install; then
        warn "A database already exists in ./data; keeping its accounts (the admin you entered is ignored)."
        fresh=0
    fi
    if (( fresh )); then
        env_set AFTERLIFE_BOOTSTRAP_ADMIN_USERNAME "$ADMIN_USER"
        write_bootstrap_password
    fi
    info "Starting containers..."
    compose up -d --remove-orphans
    wait_for "the application server" app "server_listening"
    wait_for "the onion address" tor "Onion address:"
    : > "$MARKER"
    if helper "test -f /w/secrets/bootstrap_admin_password" 2>/dev/null; then
        warn "The one-time admin password file still exists; it is deleted on the first successful start."
    fi
    local onion
    onion="$(compose logs --no-color tor 2>/dev/null | grep -o 'Onion address: [a-z2-7]\{56\}\.onion' | tail -1 | awk '{print $3}')"
    echo
    echo -e "${GREEN}========================================${RESET}"
    echo -e "${GREEN}AFTERLIFE DEPLOYMENT COMPLETE${RESET}"
    echo -e "${GREEN}========================================${RESET}"
    echo "Admin username : ${ADMIN_USER:-<unchanged>}"
    echo -e "${CYAN}Onion address  : ${onion}${RESET}"
    echo
    echo "Clients (Tor must be running locally; no proxychains needed):"
    echo "  python3 client.py --host ${onion}"
    echo
    echo "Publish the address only through a channel you control and sign it"
    echo "(e.g. a PGP/minisign-signed announcement) so users can detect fake mirrors."
    echo
    echo -e "${YELLOW}Back up the onion key and master key NOW, encrypted and offline:${RESET}"
    echo "  ./backup_keys.sh"
    echo
    echo "Firewall (host): only SSH inbound is needed."
    echo "Logs: docker compose logs -f app   |   docker compose logs -f tor"
}

main "$@"
