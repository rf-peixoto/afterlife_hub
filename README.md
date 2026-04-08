# AFTERLIFE

AFTERLIFE is a terminal-first freelancer hub with a TLS client/server split.

This repository contains:

- `server.py`: the hardened remote node.
- `client.py`: the terminal interface that connects to the server over TLS.
- `setup.sh`: Docker bootstrap that generates a local CA, signs the server certificate, writes `.env`, and starts the stack.

## Current moderation/admin model

The admin account can now:

- delete any job from the job details view;
- ban any non-admin user permanently from the main menu;
- force banned users out of existing sessions.

Behavior after a ban:

- the banned user cannot log in again;
- existing sessions are invalidated;
- open job acceptances from that user are removed;
- any open job where that user was selected is reset to no selected worker;
- historical jobs created by that user remain visible, but the author name is shown as `[banned] username`.

## Security model

The current version enforces these controls:

- mandatory TLS for all transport;
- operator-supplied bootstrap admin secret;
- encrypted storage for sensitive text fields with Fernet;
- per-IP request throttling;
- login throttling per `IP + nickname`;
- request-size and JSON-depth guards;
- bounded concurrency;
- strict input validation with allowlists;
- refusal of malformed values instead of attempting to sanitize them.

## Validation rules

Forbidden characters in validated text fields:

- `'`
- `"`
- `\`
- `/`
- `%`

Rules:

- nickname: `^[A-Za-z0-9_]{3,24}$`
- contact info: letters, digits, spaces, `@`, `.`, `-`, `_`, max 128
- title: restricted printable subset, max 32
- description: restricted printable subset, max 256
- reward: digits only, from 1 to 99999999

If a value does not match the expected format, the server rejects it.

## Quick Docker deployment

Run:

```bash
chmod +x setup.sh
./setup.sh
```

The script will ask for:

- admin username;
- admin password;
- public hostname or IP to place in the server certificate SAN;
- exposed port.

It then generates:

- `certs/ca.crt` → give this to clients as the trust anchor;
- `certs/server.crt` → server certificate;
- `certs/server.key` → server private key.

Client example after the stack is up:

```bash
python3 client.py --host YOUR_SERVER_NAME_OR_IP --port 2077 --cert certs/ca.crt
```

If the client connects by IP but the certificate was issued to a DNS name, pass the DNS name with `--server-name`.

## Manual local run

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Generate a CA and a server certificate signed by it, or use your own PKI.

Start the server:

```bash
export AFTERLIFE_BOOTSTRAP_ADMIN_USERNAME=admin
export AFTERLIFE_BOOTSTRAP_ADMIN_PASSWORD='replace_with_a_real_secret'
python3 server.py --host 0.0.0.0 --port 2077 --cert server.crt --key server.key
```

Start the client:

```bash
python3 client.py --host 127.0.0.1 --port 2077 --cert ca.crt
```

## CLI help

```bash
python3 server.py --help
python3 client.py --help
```

## Protocol actions

Current actions include:

- `ping`
- `register`
- `login`
- `logout`
- `profile`
- `list_jobs`
- `my_jobs`
- `my_accepts`
- `create_job`
- `job_details`
- `accept_job`
- `withdraw_job`
- `select_worker`
- `set_status`
- `delete_job` (admin)
- `ban_user` (admin)

## Docker notes

`docker-compose.yml` exposes the server on port `2077` inside the container and maps it to `${AFTERLIFE_EXPOSE_PORT}` on the host.

The mounted paths are:

- `./certs` → `/app/certs`
- `./data` → `/app/data`

## Remaining trade-offs

This is improved, but not magically complete. Relevant limits still include:

- no MFA;
- no full-database encryption like SQLCipher;
- no audit log integrity/signing;
- no account recovery workflow;
- certificate lifecycle and revocation remain operational tasks.
