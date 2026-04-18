docker compose down
docker rm -f afterlife-server 2>/dev/null || true
docker rmi -f afterlife_hub-afterlife-server 2>/dev/null || true
docker image prune -f
docker builder prune -f
