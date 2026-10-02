#!/usr/bin/env bash
# AFTERLIFE hard reset: removes THIS project's containers and images and all of
# its data, including the onion key (a new .onion address will be created).
# It never prunes images or build cache belonging to anything else on the host.
# Works with Docker or Podman, rootful or rootless (files owned by container
# uids are deleted from inside a helper container).
set -euo pipefail

RED="\033[1;31m"; YELLOW="\033[1;33m"; GREEN="\033[1;32m"; RESET="\033[0m"
APP_IMAGE="afterlife-app:local"

[[ -f docker-compose.yml ]] || { echo "Run from the AFTERLIFE project directory." >&2; exit 1; }

echo -e "${RED}========================================${RESET}"
echo -e "${RED}     AFTERLIFE HARD RESET${RESET}"
echo -e "${RED}========================================${RESET}"
echo -e "${YELLOW}This permanently deletes: the containers, this project's images,"
echo -e "./data (database, logs), ./secrets (master key), ./tor-hs (onion key), ./tor-data, ./run and .env.${RESET}"
echo -e "${YELLOW}Consider ./backup_keys.sh first.${RESET}"
read -rp "Type RESET to confirm: " confirmation
[[ "$confirmation" == "RESET" ]] || { echo "Aborted."; exit 0; }

env_args=()
[[ -f .env ]] && env_args=(--env-file .env)
docker compose "${env_args[@]}" down --remove-orphans || true

# Empty the directories from inside a container (their files belong to container uids).
mounts=()
for d in data secrets tor-hs tor-data run; do
    [[ -d "$d" ]] && mounts+=(-v "$PWD/$d:/w/$d")
done
if (( ${#mounts[@]} )) && docker image inspect "$APP_IMAGE" >/dev/null 2>&1; then
    docker run --rm --user 0 --network none --security-opt label=disable "${mounts[@]}" \
        --entrypoint /bin/sh "$APP_IMAGE" -c 'find /w -mindepth 2 -delete' || true
fi
for d in data secrets tor-hs tor-data run; do
    if [[ -d "$d" ]]; then
        rmdir "$d" 2>/dev/null || rm -rf -- "$d" 2>/dev/null || sudo rm -rf -- "$d"
    fi
done
rm -f .env .afterlife-installed

docker compose "${env_args[@]}" down --rmi local --remove-orphans >/dev/null 2>&1 || true
docker image rm afterlife-app:local afterlife-tor:local >/dev/null 2>&1 || true

echo -e "${GREEN}[OK] Reset complete. Run ./setup.sh to deploy a fresh instance.${RESET}"
