#!/bin/bash
# AFTERLIFE container entrypoint.
# Runs as root: starts tor under debian-tor, waits for the hidden service
# hostname, then supervises the AFTERLIFE server under the afterlife user.
# If the server crashes it is restarted WITHOUT restarting tor so the .onion
# address stays reachable throughout.
set -e

ONION_FILE="/var/lib/tor/afterlife_hs/hostname"
TOR_WAIT_SECONDS=90
SERVER_PORT="${AFTERLIFE_PORT:-2077}"
# Validate SERVER_PORT before it is interpolated into the shell -c string below.
# An operator setting AFTERLIFE_PORT to a non-numeric value (e.g. by editing
# .env manually) would otherwise inject arbitrary shell commands.
if ! [[ "$SERVER_PORT" =~ ^[0-9]+$ ]] || (( SERVER_PORT < 1 || SERVER_PORT > 65535 )); then
    fatal "AFTERLIFE_PORT must be a number between 1 and 65535 (got: ${SERVER_PORT})."
fi
SERVER_MAX_RESTARTS=20      # give up after this many consecutive crashes
SERVER_RESTART_DELAY=3      # seconds to wait before restarting

log()   { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
fatal() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2; exit 1; }

log "Entrypoint started. PID=$$"

# ── Permissions ────────────────────────────────────────────────────────────────
# setup.sh chowns the volume-mounted directories on the host before the
# container starts (fix for user-namespace remapping on some VPS configs).
# These calls are a belt-and-suspenders fallback that silently continues on
# failure so the entrypoint never dies before producing any log output.
log "Applying permissions..."
chown debian-tor:debian-tor /var/lib/tor/afterlife_hs 2>/dev/null \
    || log "Warning: could not chown afterlife_hs (host-side chown handles this)."
chmod 700 /var/lib/tor/afterlife_hs 2>/dev/null \
    || log "Warning: could not chmod afterlife_hs."
chown debian-tor:debian-tor /var/lib/tor/data 2>/dev/null \
    || log "Warning: could not chown tor data dir."
chmod 700 /var/lib/tor/data 2>/dev/null \
    || log "Warning: could not chmod tor data dir."
chown -R afterlife:afterlife /app/data 2>/dev/null \
    || log "Warning: could not chown /app/data."

# ── Start Tor ──────────────────────────────────────────────────────────────────
log "Starting Tor hidden service..."
su -s /bin/sh debian-tor -c "tor -f /etc/tor/torrc" &
TOR_PID=$!
log "Tor started with PID ${TOR_PID}."

# ── Wait for .onion hostname ───────────────────────────────────────────────────
log "Waiting for hidden service hostname (up to ${TOR_WAIT_SECONDS}s)..."
elapsed=0
while [[ ! -s "$ONION_FILE" ]]; do
    if ! kill -0 "$TOR_PID" 2>/dev/null; then
        fatal "Tor process exited before creating the hidden service hostname."
    fi
    if (( elapsed >= TOR_WAIT_SECONDS )); then
        fatal "Hidden service hostname not created after ${TOR_WAIT_SECONDS}s."
    fi
    sleep 1
    (( elapsed++ ))
done

ONION_ADDR="$(cat "$ONION_FILE")"
log "========================================="
log "AFTERLIFE HIDDEN SERVICE READY"
log "========================================="
log "Onion address : ${ONION_ADDR}"
log "Client command: proxychains python3 client.py --host ${ONION_ADDR} --port ${SERVER_PORT}"
log "========================================="

# ── Cleanup trap ──────────────────────────────────────────────────────────────
# Registered here so it covers both tor and the server restart loop.
SERVER_PID=""
cleanup() {
    log "Shutting down..."
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
    kill "$TOR_PID" 2>/dev/null || true
    [[ -n "$SERVER_PID" ]] && wait "$SERVER_PID" 2>/dev/null || true
    wait "$TOR_PID" 2>/dev/null || true
}
trap cleanup EXIT TERM INT

# ── Server supervisor loop ────────────────────────────────────────────────────
# The server is restarted here on crash WITHOUT restarting Tor.
# This keeps the hidden service reachable during brief server failures
# instead of triggering a full container restart (which forces Tor to
# re-bootstrap and leaves port 2077 unreachable for 10-30 seconds).
restarts=0
while (( restarts < SERVER_MAX_RESTARTS )); do

    # Abort if Tor itself has died — no point running without it.
    if ! kill -0 "$TOR_PID" 2>/dev/null; then
        fatal "Tor process died unexpectedly."
    fi

    log "Starting AFTERLIFE server on 127.0.0.1:${SERVER_PORT} (attempt $((restarts + 1)))..."
    su -s /bin/sh afterlife -c \
        "python /app/server.py --host 127.0.0.1 --port ${SERVER_PORT}" &
    SERVER_PID=$!

    # Wait for the server process, capturing its exit code without
    # letting set -e kill the entrypoint on non-zero.
    server_exit=0
    wait "$SERVER_PID" || server_exit=$?

    if (( server_exit == 0 )); then
        log "Server exited normally (code 0)."
        exit 0
    fi

    # SIGTERM (143) or SIGINT (130) means intentional shutdown.
    if (( server_exit == 143 || server_exit == 130 )); then
        log "Server received shutdown signal (code ${server_exit})."
        exit 0
    fi

    restarts=$(( restarts + 1 ))
    log "Server crashed (exit code ${server_exit}). Restart ${restarts}/${SERVER_MAX_RESTARTS} in ${SERVER_RESTART_DELAY}s..."
    sleep "$SERVER_RESTART_DELAY"
done

fatal "Server crashed ${SERVER_MAX_RESTARTS} times. Giving up — check logs above."
