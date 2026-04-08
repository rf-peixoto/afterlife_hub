# AFTERLIFE Hub

AFTERLIFE Hub is a minimalist remote freelancer platform with a cyberpunk terminal-style interface.

It is composed of two parts:

- **server** → hosts the application, database, users, and jobs
- **client** → connects remotely to the server so users can log in, post jobs, and manage their accounts

The platform includes:

- user registration and login
- mandatory bootstrap admin account
- job posting and browsing
- private jobs with controlled visibility
- admin moderation features
  - ban users
  - delete any job
- input validation and basic rate limiting
- terminal-first UX

---

## Quick start

Run the setup script:

```bash
chmod +x setup.sh
./setup.sh
```

The script will:

- install Python dependencies
- ask for the **admin username and password**
- create/update the mandatory admin account
- start the server

---

## Running manually

### Start server

```bash
python3 server.py
```

### Start client

```bash
python3 client.py
```

The client will ask for:

- server IP
- port

Then users can log in normally.

---

## Default workflow

1. Run `setup.sh` on the server
2. Create the admin credentials during setup
3. Start `client.py` from another machine
4. Connect to the server IP and port
5. Log in with the admin account

---

## Admin capabilities

The admin account can:

- ban users
- delete any job
- manage platform moderation

These commands are available automatically after logging in as admin.

---

## Notes

This version intentionally runs **without TLS/SSL** to keep deployment simple while the platform is under active development.

Do not expose it to the public internet without adding transport security and firewall rules.
