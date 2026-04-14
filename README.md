# AFTERLIFE Hub

Minimalist cyberpunk-style freelance work and trust marketplace with a terminal-first client/server architecture.

## Core features

* user registration and authentication
* bootstrap admin account
* session-based access control
* job creation and browsing
* private jobs protected by access token
* reputation-gated jobs
* accept / withdraw job workflows
* authored and accepted job tracking
* direct chat between participants
* block list and user isolation controls
* user rating / reputation updates
* moderation controls
  * ban users
  * delete jobs
  * delete sessions
* audit logging
* rate limiting and request validation
* SQLite persistence
* Docker / Docker Compose support


## Project structure

```text
server.py          # core server, database, security checks
client.py          # terminal client
setup.sh           # local setup helper
Dockerfile         # container build
Docker-compose.yml # deployment helper
requirements.txt   # dependencies
```

## Quick start

```bash
dos2unix *        # Code may contain /r characteres
chmod +x setup.sh
./setup.sh
```

