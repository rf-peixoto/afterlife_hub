# AFTERLIFE

AFTERLIFE is a private hub for freelancers accessible directly via terminal. Post your request in the public journal or, for more sensitive tasks, in the private journal. Leave your contact information in the description. Complete a job, get rep.

This package contains two applications:

- `server.py` - the remote job node that stores data, enforces validation, rate limiting, login throttling, access control, encrypted storage, and mandatory TLS transport.
- `client.py` - the terminal UX application that connects to the server over TLS and provides the interactive interface.

## Important design notes

- This is a raw JSON-line protocol server over TLS.
- Sensitive user-generated fields are encrypted at rest using Fernet (`cryptography`).
- This is **not** full-database encryption like SQLCipher. Table structure and some metadata remain visible.
- Transport is no longer plaintext. The server will not start without a certificate, and the client refuses insecure connections.

## Generate your Certificates:

`openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -sha256 -nodes -subj "/CN=YOUR_SERVER_IP"`

## Features included

- register / login / logout
- strict access controls
- open / done / cancelled jobs
- public and private jobs
- private job token auto-generated with `secrets.token_urlsafe(16)`
- selected worker logic
- reputation increments only when a selected worker is credited on a `done` job
- worker pool visible only to author or admin
- completed/accepted lists omit descriptions
- global per-IP rate limiting
- login throttling per `IP + nickname`
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

A bootstrap admin is created automatically on first run:

- username: `admin`
- password: `changeme`

Change or delete it before serious use.

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
./run_server.sh --host 0.0.0.0 --port 5050
```

Default bind:

- host: `0.0.0.0`
- port: `5050`

You can still override defaults with environment variables:

```bash
AFTERLIFE_HOST=0.0.0.0 AFTERLIFE_PORT=6000 python3 server.py --cert server.pem
```

Other optional environment variables:

- `AFTERLIFE_DB_PATH`
- `AFTERLIFE_MASTER_KEY_PATH`
- `AFTERLIFE_LOG_PATH`

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

## TODO

Stuff that need to be fixed:

- no MFA
- no message-level signing beyond TLS
- no moderation tooling beyond admin privileges
- certificate lifecycle is still an operational responsibility of the admin

## Files

- `server.py`
- `client.py`
- `requirements.txt`
- `README.md`
