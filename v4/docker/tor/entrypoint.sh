#!/bin/sh
# Tor container entrypoint (runs as the unprivileged debian-tor user under tini).
# 1. Refuses to run without tor's proof-of-work module (otherwise the onion
#    service's DoS defense would be silently inactive).
# 2. Validates the configuration.
# 3. Runs tor and, unless disabled, the vanguards add-on. If either process
#    exits, the container exits and Docker restarts it — nothing can die silently.
set -eu

log() { printf '[%s] [tor-container] %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S')" "$*"; }

TORRC=/etc/tor/torrc
CTL_DIR=/tmp/torctl
umask 077
rm -rf "$CTL_DIR"
mkdir -m 0700 "$CTL_DIR"

if ! tor --list-modules 2>/dev/null | grep -qx 'pow: yes'; then
    if [ "${AFTERLIFE_ALLOW_NO_TOR_POW:-0}" = "1" ]; then
        log "WARNING: this tor build has NO proof-of-work module; running WITHOUT onion PoW defenses (AFTERLIFE_ALLOW_NO_TOR_POW=1)."
        grep -v '^HiddenServicePoW' /etc/tor/torrc > "$CTL_DIR/torrc"
        TORRC="$CTL_DIR/torrc"
    else
        log "FATAL: this tor build lacks the proof-of-work module (tor --list-modules shows 'pow: no')."
        log "Rebuild the image (it installs tor from deb.torproject.org) or set AFTERLIFE_ALLOW_NO_TOR_POW=1 to run without it."
        exit 1
    fi
fi

tor --verify-config -f "$TORRC" >/dev/null || { log "FATAL: tor configuration is invalid"; tor --verify-config -f "$TORRC"; exit 1; }
log "$(tor --version | head -1)"

tor -f "$TORRC" &
TOR_PID=$!

cleanup() {
    if [ -n "${VG_PID:-}" ]; then kill "$VG_PID" 2>/dev/null || true; fi
    kill "$TOR_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup TERM INT

# Announce the address once it exists (also readable on the host in ./tor-hs/hostname).
i=0
while [ ! -s /var/lib/tor/hs/hostname ]; do
    kill -0 "$TOR_PID" 2>/dev/null || { log "FATAL: tor exited during startup"; exit 1; }
    i=$((i + 1)); [ "$i" -gt 120 ] && { log "FATAL: onion hostname not created after 120s"; cleanup; exit 1; }
    sleep 1
done
log "Onion address: $(cat /var/lib/tor/hs/hostname)"

VG_PID=""
VG_FAILS=0
start_vanguards() {
    run-vanguards --control_socket /tmp/torctl/control --state /var/lib/tor/data/vanguards.state --loglevel NOTICE &
    VG_PID=$!
}

if [ "${AFTERLIFE_VANGUARDS:-1}" = "1" ]; then
    if ! command -v run-vanguards >/dev/null 2>&1 || ! run-vanguards --help >/dev/null 2>&1; then
        log "FATAL: AFTERLIFE_VANGUARDS=1 but vanguards cannot run (rebuild with INSTALL_VANGUARDS=1 or set AFTERLIFE_VANGUARDS=0)."
        cleanup; exit 1
    fi
    i=0
    while [ ! -S /tmp/torctl/control ]; do
        i=$((i + 1)); [ "$i" -gt 60 ] && { log "FATAL: tor control socket missing"; cleanup; exit 1; }
        sleep 1
    done
    start_vanguards
    log "vanguards started (layer-2/3 guard pinning, bandwidth and rendezvous guards)"
fi

# Supervise. If tor exits, the container exits and Docker restarts it. If
# vanguards exits, tor keeps serving (it still has built-in vanguards-lite) and
# vanguards is restarted with exponential backoff, logged loudly every time.
while :; do
    if ! kill -0 "$TOR_PID" 2>/dev/null; then log "tor exited; stopping container"; cleanup; exit 1; fi
    if [ -n "$VG_PID" ] && ! kill -0 "$VG_PID" 2>/dev/null; then
        VG_FAILS=$((VG_FAILS + 1))
        delay=$((5 * VG_FAILS)); [ "$delay" -gt 300 ] && delay=300
        log "WARNING: vanguards exited (failure #$VG_FAILS); onion service keeps running with tor's built-in vanguards-lite; restarting vanguards in ${delay}s"
        VG_PID=""
        sleep "$delay"
        start_vanguards
    fi
    sleep 5
done
