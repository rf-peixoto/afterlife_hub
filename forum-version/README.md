# AFTERLIFE Hub
```{"ok":true,"message":"Welcome to AFTERLIFE","data":{"server":"AFTERLIFE","version":1}}```

A minimalist terminal-based freelance gig board, accessible exclusively through
the Tor network. No raw IP is ever exposed. Clients connect via a `.onion`
address; traffic never leaves the Tor overlay.

```
╔════════════════════════════════════════════════════════════════════════════╗
║                          A F T E R L I F E                                ║
║                      private freelancer terminal                           ║
╚════════════════════════════════════════════════════════════════════════════╝
```

---

## Features

- User registration and authentication
- Bootstrap admin account
- Session-based access control
- Job creation and browsing
- Private jobs protected by access token
- Reputation-gated jobs (author sets a minimum reputation to accept)
- Accept / withdraw job workflows
- Authored and accepted job tracking
- Direct encrypted chat between participants
- Block list and user isolation
- User rating and reputation system
- Admin moderation: ban users, delete jobs, terminate sessions
- Structured audit logging
- Per-IP rate limiting, login throttling, request validation
- Fernet encryption at rest for all sensitive fields
- SQLite persistence
- Tor hidden service — no port exposed to the internet

---

## Architecture

```
[ client machine ]                    [ VPS ]
  proxychains                           │
  python3 client.py                     │  Docker container
       │                                │  ┌─────────────────────────┐
       │  Tor network (.onion)          │  │  tor daemon             │
       └───────────────────────────────►│  │    ↓ forwards to        │
                                        │  │  server.py (127.0.0.1)  │
                                        │  └─────────────────────────┘
```

The server binds to `127.0.0.1` inside the container. Tor is the only path in.
The Docker host exposes no ports. `ufw` on the VPS allows only SSH inbound.

---

## Project files

```
server.py        core server — database, protocol, security
client.py        terminal client
setup.sh         deployment helper (run once on the VPS)
entrypoint.sh    container startup script (do not run manually)
Dockerfile       container build
docker-compose.yml
torrc            Tor hidden service configuration
```

---

## Server deployment

### Requirements

- A Linux VPS (Ubuntu 20.04+ recommended)
- Docker with the Compose plugin
- `ufw` for firewall management

### Steps

**1. Install Docker**

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker
```

**2. Copy the project files to your VPS**

```bash
scp server.py client.py Dockerfile docker-compose.yml \
    setup.sh entrypoint.sh torrc user@your-vps:~/afterlife/
```

Or clone from your repository if you have one.

**3. Run the setup script**

```bash
cd ~/afterlife
chmod +x setup.sh entrypoint.sh
./setup.sh
```

The script will:
- Ask for an admin username (3–12 chars) and password (min 12 chars)
- Create the `./data/` and `./tor-hs/` directories
- Build and start the Docker container
- Wait for Tor to generate the hidden service keys
- Print your `.onion` address

Example output:

```
[OK] Container is up and listening.
========================================
AFTERLIFE DEPLOYMENT COMPLETE
========================================
Admin username  : admin
Container name  : afterlife-server
Onion address   : xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion

Client command (requires proxychains + Tor):
  proxychains python3 client.py --host xxxx...xxxx.onion --port 2077
```

**4. Harden the firewall**

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw enable
```

Port 2077 is never exposed to the host — nothing to specifically block beyond
the default deny.

### Preserving your .onion address

The hidden service private key is stored in `./tor-hs/`. This directory
determines your `.onion` address. Back it up:

```bash
cp -r ./tor-hs/ ~/tor-hs-backup/
```

If you lose `./tor-hs/`, the address is gone permanently. If you keep it,
you can move the server to a new VPS and retain the same address.

### Useful commands

```bash
# Follow live server logs
docker logs -f afterlife-server

# Check the .onion address at any time
docker logs afterlife-server 2>&1 | grep "Onion address"

# Check the tor node connection status:
docker logs afterlife-server 2>&1 | grep -i "introduc\|circuit\|descriptor\|hs\|rendezvous\|service"

# Stop the server
docker compose down

# Restart
docker compose up -d
```

---

## Client setup

The client runs on your local machine, not on the VPS.

### Requirements

- Python 3.10+
- The `cryptography` package
- Tor (the daemon, not the browser)
- proxychains4

### Install dependencies

**Debian / Ubuntu**

```bash
sudo apt install tor proxychains4
pip install cryptography
```

**Arch**

```bash
sudo pacman -S tor proxychains-ng
pip install cryptography
```

**macOS (Homebrew)**

```bash
brew install tor proxychains-ng
pip install cryptography
```

### Configure proxychains

Open `/etc/proxychains4.conf` (or `/etc/proxychains.conf` on some systems) and
make sure the last line reads:

```
socks5  127.0.0.1  9050
```

Also check that `dynamic_chain` or `strict_chain` is set at the top. Comment
out `random_chain` if present.

### Start the Tor daemon

```bash
sudo systemctl start tor       # systemd
# or
tor &                          # manual
```

Verify it is running:

```bash
systemctl status tor
# or check the SOCKS port
ss -tlnp | grep 9050
```

### Connect

```bash
proxychains python3 client.py --host your_address.onion --port 2077
```

On first connection you will see the boot sequence and a prompt to log in or
register. Share the `.onion` address and port with your users — that is all
they need.

### Connection troubleshooting

| Symptom | Likely cause |
|---|---|
| `[proxychains] Strict chain ... timeout` | Tor is not running or not fully bootstrapped yet. Wait ~30s after starting tor and retry. |
| `[proxychains] Dynamic chain ... FAILED` | Wrong SOCKS port in proxychains.conf, or Tor is using a different port. |
| `[CONNECTION FAILURE] timed out` | The server is down, or the .onion address is wrong. Check `docker logs afterlife-server`. |
| `[CONNECTION FAILURE] connection refused` | The server is running but not accepting on that port. Verify `--port` matches the server. |

---

## Security notes

- All sensitive database fields (job titles, descriptions, messages, contact
  info) are encrypted at rest using Fernet symmetric encryption. The master key
  lives in `./data/master.key` — guard it. Anyone with this file can decrypt
  the database.
- Transport security is provided by Tor. All traffic between client and server
  is end-to-end encrypted through the onion routing layer. TLS on top of Tor
  is not required.
- The server never logs passwords or session tokens.
- Rate limiting and login throttling are active. Brute force attempts are
  blocked per IP and per `IP + nickname` pair.
- Sessions are single-instance per user — logging in from a new location
  invalidates the previous session.

---

## License

Unlicense — see `LICENSE`.
