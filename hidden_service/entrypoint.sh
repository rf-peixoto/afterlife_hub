#!/bin/bash
# AFTERLIFE container entrypoint.
# Runs as root: starts the tor daemon under the debian-tor user,
# waits for the hidden service hostname to be generated, prints it,
# then starts the AFTERLIFE server under the afterlife user.
set -e

ONION_FILE="/var/lib/tor/afterlife_hs/hostname"
TOR_WAIT_SECONDS=60
SERVER_PORT="${AFTERLIFE_PORT:-2077}"

log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
fatal() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2; exit 1; }

# ── Permissions ────────────────────────────────────────────────────────────────
# The hidden service directory must be owned by debian-tor and mode 700,
# or Tor will refuse to start.
chown -R debian-tor:debian-tor /var/lib/tor
chmod 700 /var/lib/tor/afterlife_hs

# The app data directory is owned by the afterlife user.
chown -R afterlife:afterlife /app/data

# ── Start Tor ──────────────────────────────────────────────────────────────────
log "Starting Tor hidden service..."
su -s /bin/sh debian-tor -c "tor -f /etc/tor/torrc" &
TOR_PID=$!

# ── Wait for .onion hostname ───────────────────────────────────────────────────
log "Waiting for hidden service hostname (up to ${TOR_WAIT_SECONDS}s)..."
elapsed=0
while [[ ! -s "$ONION_FILE" ]]; do
    if ! kill -0 "$TOR_PID" 2>/dev/null; then
        fatal "Tor process exited before creating the hidden service hostname."
    fi
    if (( elapsed >= TOR_WAIT_SECONDS )); then
        fatal "Hidden service hostname not created after ${TOR_WAIT_SECONDS}s. Check Tor logs above."
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

# ── Trap: kill Tor when server exits ──────────────────────────────────────────
cleanup() {
    log "Shutting down Tor..."
    kill "$TOR_PID" 2>/dev/null || true
    wait "$TOR_PID" 2>/dev/null || true
}
trap cleanup EXIT TERM INT

# ── Start AFTERLIFE server ─────────────────────────────────────────────────────
log "Starting AFTERLIFE server on 127.0.0.1:${SERVER_PORT}..."
exec su -s /bin/sh afterlife -c "python /app/server.py --host 127.0.0.1 --port ${SERVER_PORT}"
