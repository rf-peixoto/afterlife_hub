# AFTERLIFE Hub

A minimalist terminal freelance board and forum, reachable only as a Tor onion
service. Text-only, invite-capable, with end-to-end encrypted private chat.

```
╔════════════════════════════════════════════════════════════════════════════╗
║                          A F T E R L I F E                                 ║
║                      private freelancer terminal                           ║
╚════════════════════════════════════════════════════════════════════════════╝
```

---

## Architecture

```
 client.py ──SOCKS5h──► local Tor ══ Tor network ══► [ tor container ] ──unix socket──► [ app container ]
 (your machine)                                         onion service                   Python server
                                                        PoW + DoS defenses              NO network at all
                                                        vanguards                       read-only, non-root
```

* **Two containers.** `tor` is the only one with network access, and it only
  makes outbound connections to the Tor network. `app` runs with
  `network_mode: none`. It has no network interface except loopback, so even a
  compromised app cannot reach out and reveal the server's IP. The two talk over
  a unix socket in a volume that only they share.
* **No published ports.** Nothing listens on the host; only SSH needs to be open.
* **SELinux:** both containers run at one shared SELinux level, so Tor may
  connect to the app's socket while the files stay private to these two
  containers. This setting is ignored on hosts without SELinux.
* **Per-circuit identity.** Tor is configured with
  `HiddenServiceExportCircuitID haproxy`, so every connection starts with a
  PROXY header carrying the Tor circuit id. All per-client limits (requests,
  concurrent connections, proof-of-work challenges, login failures) are keyed on
  the circuit, not on a shared address that one client could exhaust for everyone.
* **Async front-end.** Every request must arrive complete within 15 s in
  total, and idle sockets are cheap, so slow-drip ("slowloris") connections
  cannot pin the server. Database and crypto work runs in a bounded worker pool.
  When the pool is full, new work is refused immediately instead of queueing.

## What is protected, and what is not

| Data | Protection | Who can read it |
|---|---|---|
| Private chat messages | **End-to-end encrypted** (X25519 + HKDF-SHA256 + ChaCha20-Poly1305) in the client | Only the two participants. The server stores ciphertext and cannot read or moderate it. |
| Jobs, forum threads, comments, system notices | Encrypted at rest (Fernet) with a master key kept in `./secrets`, separate from `./data` | The server/operator. A leaked copy of `./data` alone (backup, disk image) is unreadable. |
| Who talks to whom, when; job/rating relationships; nicknames | Not encrypted (needed to run the service) | The server/operator, and anyone who seizes the running server. |
| Passwords | PBKDF2-SHA256, 310k iterations | Nobody (one-way). |

Be honest with your users. **Anyone who takes control of the running server can
read everything except chat contents.** E2E keys use static X25519 keys with no
forward secrecy. Rotating keys (`keys → rotate`) limits exposure from a stolen
key file.

Logs run in privacy mode by default (`AFTERLIFE_LOG_PRIVACY=1`): chat, block and
key events are logged without the people involved. Logs rotate (10 MB × 5) and are
mode 0600. Repetitive noise (rejected requests, rate-limit hits) is collapsed to
one line per minute, so log floods cannot fill the disk.

---

## Server deployment

### Requirements

* A Linux VPS with **Docker** (Compose v2 plugin) **or Podman** (rootful or
  rootless, using the `docker` CLI shim with docker-compose or podman-compose).
  SELinux-enforcing hosts (Fedora/RHEL/Alma/Rocky) are supported.
* Outbound HTTPS from the server during builds (Docker Hub, PyPI,
  deb.torproject.org).

### Install

```bash
git clone <your repo> afterlife && cd afterlife     # or scp the project directory
./setup.sh
```

`setup.sh`:

1. Asks for the admin username and password (twice) and the base PoW
   difficulty. The password goes into a **one-time file** in `./secrets`. The
   server reads it on first start, creates the admin, and **deletes it**. It is
   never placed in `.env`, an environment variable, or an image, so it can't
   leak via `docker inspect` or `/proc`.
2. Creates `./data`, `./secrets`, `./run` (uid 10001) and `./tor-hs`, `./tor-data`
   (uid 10002), all mode 700. Ownership is set **from inside a helper
   container**, so it is correct on rootless engines, where container uids map to
   different host uids. You don't need sudo for this. Directories left behind by
   an older version are reclaimed once, which does use sudo.
3. Pins the base images **by digest** in `.env`, so rebuilds are reproducible.
   Re-pin later with `./setup.sh --update-images`.
4. Builds the images:
   * The Python dependencies are installed hash-locked (`--require-hashes`).
   * Tor comes from **deb.torproject.org**, whose signing key is checked against
     the published fingerprint `A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89`.
   * vanguards is no longer packaged in Debian 13, so the image downloads two
     exact files from PyPI (vanguards 0.3.1 and stem 1.8.2), checks them against
     pinned SHA-256 hashes, and uses them without pip or a build step.
5. Starts both containers and prints the `.onion` address.

Running `./setup.sh` again on an existing install rebuilds and upgrades it
without touching accounts.

The tor container **refuses to start** if its tor build lacks the
proof-of-work module (`tor --list-modules` → `pow: yes`), because the onion
service's DoS defense would otherwise be silently inactive. You can override
this with `AFTERLIFE_ALLOW_NO_TOR_POW=1`, which disables onion PoW and logs a
loud warning.

### Firewall

```bash
sudo ufw default deny incoming && sudo ufw default allow outgoing
sudo ufw allow ssh && sudo ufw enable
```

### Back up the keys (do this immediately)

Two secrets are irreplaceable:

* `./tor-hs/`: the onion key. **Whoever holds it *is* your .onion address**
  and can impersonate the service perfectly.
* `./secrets/master.key`: without it the database cannot be read.

```bash
./backup_keys.sh      # writes an AES-256 passphrase-encrypted archive to ./backups/
```

Move the archive off the server and keep it offline. Never copy these
directories anywhere unencrypted.

**Restore on a new server:** copy the project there, then *before* `./setup.sh` run

```bash
gpg -d afterlife-keys-*.tar.gz.gpg | tar -xzf - -C .   # recreates ./tor-hs and ./secrets
./setup.sh                                              # sets ownership; same .onion address
```

### Publishing your address safely

Fake look-alike onion services are the most common real-world attack on onion
communities. Publish the address through a channel you control and **sign it**
(PGP or minisign), so users can verify it. Users can pin it in their client
(see below).

### Operations

```bash
docker compose logs -f app          # application log (also ./data/server.log)
docker compose logs -f tor          # tor + vanguards
docker compose restart app          # restarting the app never restarts tor
./setup.sh --update-images          # pick up base-image security updates
./reset_docker.sh                   # DESTROY everything incl. the onion key (asks first)
```

Each container has one supervised job. If tor dies, its container exits and
Docker restarts it. If the app crashes, only the app restarts.
[vanguards](https://github.com/mikeperry-tor/vanguards) runs next to tor to resist
guard-discovery attacks. If vanguards fails, tor keeps serving (with its built-in
vanguards-lite) while vanguards is restarted with backoff and logged.

---

## Client setup

Requirements: Python 3.10+, `pip install cryptography`, and a running Tor:

* **Tor daemon:** `sudo apt install tor` / `brew install tor`, SOCKS on `127.0.0.1:9050`.
* **Or Tor Browser** running in the background: use `--socks 127.0.0.1:9150`.

```bash
python3 client.py --host <address>.onion
```

* **No proxychains.** The client speaks SOCKS5 to Tor itself and hands Tor the
  hostname, so the `.onion` name never touches local DNS. It also uses a random
  SOCKS username, so Tor keeps its circuits separate from your other apps.
* The client **validates the onion address** (length, v3 version byte, checksum),
  catching typos.
* **Address pinning:** the first time you connect to an address, the client asks
  you to confirm it and remembers it in `~/.afterlife/known_hosts.json`.
  Distributors can hard-pin it with `AFTERLIFE_ONION=<address>.onion`, and then
  any other address is refused.
* Everything the server sends is stripped of terminal control characters before
  it is printed.

### Your encryption keys

* Created at registration and stored at `~/.afterlife/keys/<onion>/<nick>.json`,
  **encrypted with your password** (scrypt + ChaCha20-Poly1305).
* **The server never has your private key.** Only your public key is uploaded.
  The path shown under `keys` is a file on *your* computer. The onion address in
  the folder name just keeps keys for different servers apart.
* **Back up and move keys with `keys → export`**, which writes a copy encrypted
  with a passphrase you choose. On another device, use `keys → import`. If you
  lose every copy, old messages can't be read and you must rotate to a new key
  (`keys → rotate`).
* Contacts' public keys are checked against their fingerprints and **stored
  locally** (`~/.afterlife/peers/`). After the first contact, encrypting and
  decrypting needs nothing from the server.
* Show your fingerprint (`keys`) to your contacts through another channel. The
  client pins each contact's key the first time it sees it. If a key changes,
  you get a loud warning, and the client won't send to the new key until you
  accept it. A changed key means either they reinstalled, or someone (possibly
  the server) is trying to intercept.
* Changing your password (`profile → password`) re-encrypts the key file.

---

## How the platform works

### Jobs

`open → (author marks done) → awaiting_confirmation → (worker confirms) → done`

* The worker can instead **dispute**: the job becomes `disputed` and goes to the
  admin queue (`admin → disputes / resolve dispute`).
* If the worker never responds, the job completes automatically after 7 days.
* Ratings and reputation unlock only for `done` jobs.
* A cancelled job must be reopened before it can be completed.
* Withdrawing from a job is final; you cannot accept it again.
* Private jobs show their description only with the unlock token.

### Reputation (sybil-resistant)

* Reputation **flows from accounts that already have it.** Admins are the trust
  seed. A positive rating from an account with reputation ≤ 0 adds nothing, so
  a ring of fresh accounts rating each other stays at 0.
* Repeated ratings between the same two people decay geometrically (×0.5 each).
  A positive rating back to someone who just rated you counts half. Each rater
  can give at most +3.0 per 24 h.
* Negative ratings: after 3 in 24 h, or once a target has lost 3.0 in 24 h,
  further ratings are frozen for admin review. A discarded rating stays
  recorded, so it can't be resubmitted.
* Job-completion reputation is weighted by the employer's reputation, decays
  per day and per pair, and is capped per employer per day. A job "completed"
  within 1 h of being posted earns nothing.

### Trust ladder and quotas

| Level | Requirement | Per 24 h (rolling) |
|---|---|---|
| L0 | new (first 24 h read-only) | 1 thread, 5 comments, 1 job, 3 accepts, 2 new chats, 50 messages |
| L1 | ≥ 24 h old, reputation ≥ 0 | 5 / 50 / 10 / 20 / 10 / 400 |
| L2 | ≥ 7 days, reputation ≥ 10, ≥ 3 distinct paying partners | 20 / 200 / 50 / 100 / 50 / 2000; may invite (≤ 3 per 30 days, ≤ 5 outstanding) |
| L3 | admin | unlimited |

Quotas and the read-only window are checked **before** you are asked to solve a
proof-of-work, so you never solve a puzzle for an action that would be refused.

### Proof-of-work

Memory-hard scrypt puzzles protect register, login, rate and the write actions
(posting, jobs, accepting, opening a chat). Each challenge:

* is **single-use**: it is consumed before verification, so every challenge
  costs the server at most one check;
* is **bound** to its purpose and subject (the login nickname, or the
  requesting account), so challenges cannot be shared or swapped;
* is rate-limited per circuit or account, with a cap on unsolved challenges per
  requester.

Difficulty rules:

* Base difficulty `AFTERLIFE_POW_DIFFICULTY`. Writes get −1 bit per +10
  reputation and +1 bit per negative point. Accounts at ≥ 5 reputation skip PoW
  on writes.
* **Registration** gets more expensive as signups in the last hour pass the
  soft cap. Nobody is forced into a queue.
* **Failed logins:** the guessing circuit pays up to +8 bits. Failures from
  anywhere add at most +3 bits to the account itself, so nobody can lock a user
  out. Malformed or over-long login attempts never count.

### Registration and moderation

* Modes: `open`, `invite`, `closed`.
* Approval lock: new accounts wait in a bounded queue (200), and pending
  accounts expire after 7 days. Rejecting a pending account deletes it and
  frees the nickname.
* **Nicknames** are unique ignoring case, underscores and look-alike characters
  (`Admin` = `adm1n` = `a_d_m_i_n`). Names such as admin, moderator, system and
  afterlife are reserved. Login is case-insensitive.
* **Moderation flags** (timing regularity, unseen-thread replies, fast replies,
  cross-account duplicate text, coordinated invites, disputes, rating bursts)
  are reported, never auto-enforced. Repeats of the same signal for the same
  user increment a counter instead of adding rows, so nobody can bury other
  flags. The admin list is paginated and sorted by severity.
* Ban and wipe:
  * Banning or wiping an invitee costs the inviter 2.0 reputation **once**.
  * Wiping removes the user's jobs and forum posts but keeps other users'
    completion history intact.
* Admins can change their password from the client (`profile → password`).

---

## Tuning

Set these in `.env` (single-quoted values), then run `docker compose up -d`.

| Variable | Default | Meaning |
|---|---|---|
| `AFTERLIFE_POW_DIFFICULTY` | 5 | base PoW bits (~20 ms per guess) |
| `AFTERLIFE_POW_MAX_DIFFICULTY` | 20 | ceiling |
| `AFTERLIFE_POW_WRITE_EXEMPT_REP` | 5 | reputation at which writes need no PoW |
| `AFTERLIFE_REG_MAX_PER_HOUR` | 20 | signups/hour before registration PoW rises |
| `AFTERLIFE_READONLY_WINDOW` | 86400 | new-account read-only seconds |
| `AFTERLIFE_LOG_PRIVACY` | 1 | omit social-graph details from logs |
| `AFTERLIFE_VANGUARDS` | 1 | run the vanguards add-on |
| `AFTERLIFE_ALLOW_NO_TOR_POW` | 0 | allow a tor build without the PoW module |

More knobs are in `afterlife_server/config.py`.

## Tests

```bash
pip install cryptography
python3 tests/test_security.py          # spins up real servers; ~2 minutes
```

There is a regression test for every issue in the security review. The tests
cover slowloris, challenge exhaustion, login-lockout escalation, PoW
reuse/binding, sybil reputation farming, queue floods, flag spam, log floods,
impersonation, E2E confidentiality and tampering, and SOCKS transport.

---

## Security changelog (v3 → v4)

| # | Issue | Fix |
|---|---|---|
| 1 | Slowloris: 32 idle sockets froze the server | asyncio front-end, one 15 s deadline per request, per-circuit connection cap |
| 2 | One shared pre-auth challenge bucket (everyone is 127.0.0.1) | Tor circuit IDs via PROXY header; all limits per circuit |
| 3 | Free login-difficulty escalation (over-long password, before PoW) | malformed attempts never count; per-circuit escalation; account-wide escalation capped at +3 bits |
| 4 | ~45% of forum posts crashed (unsigned 64-bit SimHash) | SimHash stored signed |
| 5 | `.strip()` on raw key bytes changed ~4.6% of keys; failed decryption returned "" | ASCII/base64 key file written atomically at 0600; startup canary; decryption failures logged loudly |
| 6 | One challenge accepted unlimited wrong answers | consumed before verification |
| 7 | Challenges not bound to the requester | bound to purpose + nickname/account |
| 8 | Sybil pairs minted reputation by rating each other | trust flows only from reputation holders; pair decay; reciprocity discount; daily rater budget |
| 9 | Registration cap pushed everyone into an unbounded approval queue | adaptive registration PoW; bounded, paginated, expiring queue; rejection frees the nickname |
| 10 | `accept_job` bypassed read-only, quotas and PoW; accept/withdraw loop spammed authors | quota + PoW + read-only check; no re-accept after withdraw |
| 11 | 200k-iteration PBKDF2 on private tokens inside the global DB lock | HMAC-SHA256 for high-entropy tokens |
| 12 | Global circuit breaker was a one-attacker kill switch | removed; per-circuit budgets and bounded worker admission |
| 13 | Moderation flags could be flooded | deduplicated counters, flag-once-per-session timing check, flags only for successful actions, severity-sorted paginated view |
| 14 | Discarded frozen ratings could be resubmitted | kept as `discarded` |
| 15 | Author alone could mark "done" and down-rate | worker confirmation, dispute and admin resolution; 24 h negative cap per target |
| 16 | Case-sensitive nicknames, nothing reserved | confusable-skeleton uniqueness, reserved names, distinct `[SYSTEM NOTICE]` rendering |
| 17 | Unpaginated threads and chats crashed clients | paginated posts and chats; message cursor; client handles oversize responses |
| 18 | Unbounded, world-readable logs exposing the social graph | rotation, 0600, flood suppression, privacy mode |
| 19 | Admin password in `.env`/env/`docker inspect`, re-applied every boot, `$` interpolated | one-time secret file, never re-applied, never promotes an existing user, `change_password`, single-quoted `.env` |
| 20 | Tor death went unnoticed | one supervised process per container; tor and vanguards supervised |
| 21 | Account state revealed before password check; `sleep` blocked worker threads | password always verified first (dummy hash for unknown users); no blocking sleeps |
| Low | PoW asked before validation, setup ignored the container name, reset pruned the host, client crashed on network errors, unchecked PoW parameters, NaN/Infinity, midnight quota burst, double inviter penalty | all fixed (see tests) |
| Tor/infra | Unpinned images and tor build, no circuit visibility, no vanguards, plaintext key backups, no onion pinning, overstated encryption, root container, proxychains DNS leaks | digest-pinned images, Tor Project repo with fingerprint check and PoW-module gate, circuit-ID export, vanguards, encrypted `backup_keys.sh`, client onion pinning and checksum, real E2E chat and honest docs, split hardened containers, native SOCKS5h client |

## License

Unlicense — see `LICENSE`.
