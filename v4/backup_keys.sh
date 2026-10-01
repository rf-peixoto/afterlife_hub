#!/usr/bin/env bash
# Encrypted backup of the two irreplaceable secrets:
#   ./tor-hs   the onion service key  (whoever holds it IS your .onion address)
#   ./secrets  the master key          (needed to read the database)
# The archive is encrypted with a passphrase (GnuPG, AES-256). Store it OFFLINE,
# separately from the server. Never copy these directories anywhere unencrypted.
# Works with Docker or Podman, rootful or rootless (the files are read from
# inside a helper container, because they belong to container uids).
#
# Restore on a new server: copy the project there, then BEFORE running setup.sh:
#   gpg -d afterlife-keys-*.tar.gz.gpg | tar -xzf - -C .    # recreates ./tor-hs and ./secrets
#   ./setup.sh                                               # assigns the right ownership
# The same .onion address comes back, and the master key matches your database
# backup if you restore ./data as well.
set -euo pipefail
umask 077

APP_IMAGE="afterlife-app:local"
command -v gpg >/dev/null 2>&1 || { echo "gpg is required (apt/dnf install gnupg2)." >&2; exit 1; }
[[ -d ./tor-hs && -d ./secrets ]] || { echo "Run from the AFTERLIFE project directory after setup." >&2; exit 1; }
docker image inspect "$APP_IMAGE" >/dev/null 2>&1 || { echo "Image $APP_IMAGE not found; run ./setup.sh first." >&2; exit 1; }

mkdir -p ./backups
out="./backups/afterlife-keys-$(date -u +%Y%m%dT%H%M%SZ).tar.gz.gpg"
echo "You will be asked for a passphrase. Use a long, unique one and do not store it with the backup."
docker run --rm --user 0 --network none --security-opt label=disable \
    -v "$PWD/tor-hs:/b/tor-hs:ro" -v "$PWD/secrets:/b/secrets:ro" \
    --entrypoint tar "$APP_IMAGE" -czf - -C /b --exclude=bootstrap_admin_password tor-hs secrets \
    | gpg --symmetric --cipher-algo AES256 --s2k-digest-algo SHA512 --s2k-count 65011712 -o "$out"
chmod 600 "$out"
echo "Encrypted backup written to: $out"
echo "SHA-256: $(sha256sum "$out" | cut -d' ' -f1)"
echo "Move it OFF this server, then delete the local copy:  shred -u $out"
