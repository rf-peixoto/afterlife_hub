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
- Community forum: text-only threads and comments, with keyword search
- Reputation-gated forum (negative-reputation users cannot post or comment)
- Direct encrypted chat between participants
- Block list and user isolation (applies to jobs, chat, and the forum)
- Decimal reputation with trust-weighted (EigenTrust-lite) ratings, restricted to completed-job counterparties
- Anti-farm job-completion reputation (employer-weighted, per-day and per-pair diminishing returns)
- Trust ladder (reputation + account age + distinct job partners) with an initial read-only window and per-level daily quotas
- Invite / vouch registration with admin-controlled modes (open / invite-only / closed) and a global approval lock
- Memory-hard, reputation-adaptive proof-of-work (scrypt) on identity and write actions
- Brigade detection that freezes suspicious rating bursts for admin review
- Behavioral moderation flags (timing regularity, unseen-thread replies, cross-account duplicate content, coordinated registration) — reported, never auto-banning
- Admin moderation: registration controls, approval queue, reputation adjustment, flag/frozen-rating review, ban, wipe, delete
- Structured audit logging
- Server-wide circuit breaker + per-session rate limiting + request validation
- HMAC keyword search index (no full-table decryption on search)
- Fernet encryption at rest for all sensitive fields
- SQLite persistence
- Tor hidden service with network-layer PoW / intro DoS defenses — no port exposed to the internet

See [Bot & abuse resistance](#bot--abuse-resistance) for the full design.

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

## Forum

AFTERLIFE includes a simplified, MyBB-style community board reachable from the
main menu via the `forum` command. It is a single flat board of threads — no
categories, no sub-forums.

- **Threads** — any member can start a thread with a title and a body. Bodies
  may span multiple lines (up to 2096 characters). In the client, finish a body
  with a single `.` on its own line (or type `/cancel` to abort).
- **Comments** — members reply to threads with text comments. Threads are
  ordered by most recent activity.
- **Search** — keyword search matches thread titles and bodies (case
  insensitive substring match). Queries must be at least 3 characters, and
  results are paginated; this bounds the work done by the decrypt-based search.
- **Text only** — titles, bodies, and comments are restricted to the same
  ASCII text policy as the rest of the platform. Emoji, images, and the
  forbidden characters `' " \ / % +` are rejected.
- **Reputation gate** — users whose reputation has dropped to -10 or below can
  read and search the forum but cannot create threads or comment. Banned users
  cannot post at all.
- **Isolation** — the existing block system applies. Threads and replies from
  users you have blocked (in either direction) are hidden from you.
- **Encryption at rest** — thread titles, bodies, and comments are Fernet
  encrypted in the database exactly like job and chat content. Because the
  ciphertext is non-deterministic, search decrypts candidate rows in memory
  rather than querying plaintext.
- **Moderation** — admins can delete any thread (which removes its comments)
  or any individual comment.

Every action except `ping`, `register`, and `login` requires an authenticated
session — there is no anonymous browsing anywhere on the platform.

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
- All actions except `ping`, `register`, and `login` require an authenticated
  session. Because every Tor client reaches the server from `127.0.0.1`, a
  general per-session rate limiter (keyed on the session token) throttles each
  user independently of the shared global IP bucket. Forum writes and the
  (decrypt-heavy) thread search have their own stricter per-session limiters.
- Passwords are bounded to 8–64 characters; an over-length password at login is
  rejected before any hashing, closing a cheap CPU-exhaustion vector.
- Moderation is auditable: thread/comment IDs are recorded on create, comment,
  and delete events, and an unusual burst of negative ratings against a single
  user (more than five within 24 hours) raises an audit warning.
- Admins can `wipe_user`: this bans the account and deletes all of its jobs,
  threads, and comments while preserving the account row and existing chats.
- The job board, the forum thread board, and forum search are paginated (10
  items per page, newest first). The server reads and returns only one page at
  a time, so a single request can never force it to serialize or decrypt the
  entire table — closing a denial-of-service amplification vector.
- Registering, logging in, and changing another user's reputation each require
  the client to solve a fresh proof-of-work challenge (a SHA-256 leading-zero
  puzzle issued by the server). Verifying costs the server a single hash;
  solving costs the client roughly 2^difficulty hashes, and the challenge is
  one-time, so automation pays a CPU price on every attempt. Difficulty is
  tunable via AFTERLIFE_POW_DIFFICULTY (default 20).
- Sessions are single-instance per user — logging in from a new location
  invalidates the previous session.

---

## Bot & abuse resistance

The threat model is a Tor-only, text-only protocol with an open-source client.
Over that channel there is **no reliable way to distinguish a capable LLM agent
from a human** — no browser to fingerprint, no IP, and any challenge a human
passes a model can usually pass too. So the goal is not detection. It is to make
an automated account **cost as much, earn trust as slowly, and do as little
damage** as a human newcomer. A well-behaved bot that clears these bars is, in
practice, just a slow and expensive user.

Defenses are layered:

### Network layer (Tor)
`torrc` enables `HiddenServicePoWDefensesEnabled` (memory-hard Equi-X puzzle for
connecting clients, engaged under load) and `HiddenServiceEnableIntroDoSDefense`.
Because every client reaches the app as `127.0.0.1`, connection floods must be
absorbed here, not in the app. **Requires Tor 0.4.8+** (`tor --version`).

### Identity cost
- **Memory-hard, adaptive PoW.** Register / login / rate / write actions require
  a scrypt puzzle (GPU/ASIC-resistant). Difficulty is `base − ⌊rep/10⌋` and
  `base + ⌈|rep|⌉` for negative reputation, so trusted users are barely slowed
  and abusers pay exponentially more. Writes are exempt at reputation
  ≥ `AFTERLIFE_POW_WRITE_EXEMPT_REP`.
- **Registration modes** (admin): `open`, `invite` (invite-only), `closed`.
- **Approval lock** (admin): route *all* new accounts — free, invited or vouched
  — through a manual approval queue (`admin → pending / approve / reject`).
- **Global registration cap** per hour; excess is queued for approval.
- **Invites / vouching.** Trust-level-2 users (and admins) issue single-use,
  expiring invite codes. Banning or wiping an invitee **docks the inviter's
  reputation** and revokes their unused invites, so operators spend real trusted
  accounts.

### Trust ladder & quotas
Trust level is derived from **reputation + account age + distinct job partners**:
- **L0 (new):** read-only for the first `READONLY_WINDOW` (default 24h), then
  tight daily quotas, and PoW on every write.
- **L1 / L2:** progressively higher daily quotas; L2 can issue invites.
- **L3:** admin.

### Reputation that sybils can't mint
- Reputation is a **decimal** value; everyone starts at `0.0`.
- **Ratings** are only allowed between the two parties of a **completed job**,
  once per job, and are **weighted by the rater's own trust** (a new account's
  vote barely moves the needle). Admins can adjust reputation without limit to
  undo fake-rep attacks (`admin rep`).
- **Job-completion reputation is employer-weighted:** an employer with
  reputation ≤ 0 confers **nothing**, so you cannot mint reputation from
  fake employers — a genuinely reputable employer is the scarce resource you
  must spend. Repeat work with the *same* partner decays geometrically (real
  repeat collaboration still pays a little; farming one pair collapses to ~0),
  there is a per-day diminishing-returns curve and hard cap scaled by trust, and
  a per-employer daily granting cap.
- **Brigade detection acts:** a burst of negative ratings on one target is
  **frozen** (its effect withheld) and queued for admin review
  (`admin → frozen / resolve rating`).

### Behavioral signals (reported, never auto-enforced)
Custom clients are legitimate, so these only raise **moderation flags** for
admins — they never block a request or ban anyone:
- metronomic request timing, replies faster than a human could manage,
- comments on threads the session never opened,
- near-duplicate content (SimHash) posted from *different* accounts,
- clusters of accounts invited/registered within a short window.

> Canary/decoy traps were intentionally **not** added: with an open-source
> client and users who build their own, they would flag confused humans as often
> as bots — noise the operator asked to avoid.

### Quick fixes folded in
- Removed the per-IP global lockout (meaningless when all clients are
  `127.0.0.1`); replaced with per-session limits + a server-wide circuit breaker
  that sheds load without penalizing users.
- Replaced the login **lockout** (which let anyone lock any account) with
  **per-nickname PoW escalation** on failed logins.
- The PoW challenge store refuses new issuance when full instead of evicting
  challenges real users are solving; challenge issuance is itself rate-limited.
- Forum search uses an **HMAC keyword index** so it no longer decrypts every
  thread (whole-word, case-insensitive matching).

### Tuning
Key environment variables (see `docker-compose.yml`): `AFTERLIFE_POW_DIFFICULTY`
(base bits), `AFTERLIFE_POW_SCRYPT_N` / `_R` (memory cost),
`AFTERLIFE_POW_MAX_DIFFICULTY`, `AFTERLIFE_POW_WRITE_EXEMPT_REP`,
`AFTERLIFE_REG_MAX_PER_HOUR`, `AFTERLIFE_READONLY_WINDOW`.

---

## License

Unlicense — see `LICENSE`.
