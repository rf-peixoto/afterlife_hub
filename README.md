# AFTERLIFE

AFTERLIFE is a private hub for freelancers accessible directly via terminal. Post your request in the public journal or, for more sensitive tasks, in the private journal. Users must register with contact information, and job authors can see accepted users plus their stored contact info in the worker pool.

This package contains two applications:

- `server.py` - the remote job node that stores data, enforces validation, rate limiting, login throttling, connection caps, encrypted field storage, request-size guards, and mandatory TLS transport.
- `client.py` - the terminal UX application that connects to the server over TLS and provides the interactive interface.

## Important design notes

- This is a raw JSON-line protocol server over TLS.
- Sensitive user-generated fields are encrypted at rest using Fernet (`cryptography`).
- This is **not** full-database encryption like SQLCipher. Table structure and some metadata remain visible.
- The Fernet master key should be stored outside the main database path, ideally on a separate protected mount or external secret store. If disk theft or backup exposure is in scope, whole-database encryption is the better design.
- Transport is no longer plaintext. The server will not start without a certificate, and the client refuses insecure connections.

## Generate certificates

```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -sha256 -nodes -subj "/CN=YOUR_SERVER_IP"
```

## Features included

- register / login / logout
- mandatory `contact_info` during registration
- strict access controls
- open / done / cancelled jobs
- public and private jobs
- private job token auto-generated with `secrets.token_urlsafe(16)`
- selected worker logic
- reputation increments only when a selected worker is credited on a `done` job
- worker pool visible only to author or admin, including contact info for accepted users
- completed/accepted lists omit descriptions
- global per-IP rate limiting
- invalid-traffic throttling for malformed JSON
- login throttling per `IP + nickname`
- request line length limit
- client-side response size limit
- bounded concurrency with connection caps and a worker pool
- mandatory TLS on every request

## Validation rules

Forbidden characters in validated text fields:

- `'`
- `"`
- `\`
- `/`
- `%`

Nickname:
- 3 to 24 chars
- letters, digits, underscore only

Contact info:
- 1 to 128 chars
- letters, digits, spaces, `@`, `.`, `-`, `_` only

Title:
- 1 to 32 chars
- restricted printable subset

Description:
- 1 to 256 chars
- restricted printable subset

Reward:
- digits only
- range 1 to 99999999

## Bootstrap admin

The server no longer creates a bootstrap admin with a built-in default password.

On first run, if the bootstrap admin account does not exist, you **must** provide an operator secret through environment variables:

```bash
export AFTERLIFE_BOOTSTRAP_ADMIN_USERNAME=admin
export AFTERLIFE_BOOTSTRAP_ADMIN_PASSWORD='replace_this_with_a_real_secret'
```

The server refuses to start if the bootstrap account would otherwise be auto-provisioned with an unsafe default.

## TLS usage

You must provide a certificate on both sides.

### Server side

The server requires `--cert`.

- If your PEM file already contains both the certificate and the private key, `--cert` is enough.
- If the private key is stored separately, also pass `--key`.

Examples:

```bash
python3 server.py --cert server.pem
python3 server.py --host 0.0.0.0 --port 5050 --cert server.crt --key server.key
```

### Client side

The client also requires `--cert`, but here it is used as the trusted certificate or CA bundle for server validation.

Examples:

```bash
python3 client.py --cert server.pem
python3 client.py --host 10.10.10.5 --port 5050 --cert ca.pem
python3 client.py --host 10.10.10.5 --port 5050 --cert ca.pem --server-name afterlife.localhost
```

Use `--server-name` when the TCP connection is made to an IP but the certificate was issued for a hostname.

## Quick start

### 1. Install dependency

```bash
python3 -m pip install -r requirements.txt
```

### 2. Start the server

```bash
export AFTERLIFE_BOOTSTRAP_ADMIN_PASSWORD='replace_this_with_a_real_secret'
python3 server.py --host 0.0.0.0 --port 5050 --cert server.crt --key server.key
```

Default bind:

- host: `0.0.0.0`
- port: `5050`

You can still override defaults with environment variables:

```bash
AFTERLIFE_HOST=0.0.0.0 AFTERLIFE_PORT=6000 python3 server.py --cert server.pem
```

Other useful environment variables:

- `AFTERLIFE_DB_PATH`
- `AFTERLIFE_MASTER_KEY_PATH`
- `AFTERLIFE_LOG_PATH`
- `AFTERLIFE_MAX_REQUEST_LINE_BYTES`
- `AFTERLIFE_MAX_JSON_DEPTH`
- `AFTERLIFE_MAX_PARSE_ERRORS_PER_WINDOW`
- `AFTERLIFE_MAX_CONNECTIONS`
- `AFTERLIFE_MAX_WORKERS`

## Help output

Both applications include guided CLI help:

```bash
python3 server.py --help
python3 client.py --help
```

These help messages explain how `--cert`, `--key`, and `--server-name` should be used.

## Protocol overview

The server expects one JSON object per line and answers with one JSON object per line, inside a TLS session.

Example payload:

```json
{"action":"ping"}
```

Possible actions:

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

## Remaining security notes

Still relevant gaps and trade-offs:

- no MFA
- no message-level signing beyond TLS
- no moderation tooling beyond admin privileges
- certificate lifecycle is still an operational responsibility of the admin
- database field encryption is not a substitute for full-database encryption if the threat model includes disk or backup compromise

## Files

- `server.py`
- `client.py`
- `requirements.txt`
- `README.md`
- `Dockerfile`
- `docker-compose.yml`
