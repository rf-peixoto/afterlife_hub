#!/usr/bin/env python3
"""AFTERLIFE server entry point.

Plain JSON-over-TCP protocol (one request per connection, newline-terminated),
reachable only through a Tor onion service. See README.md for the threat model.
"""
from __future__ import annotations

import asyncio
import os
import sys

from afterlife_server import config as C
from afterlife_server.crypto import CryptoBox
from afterlife_server.db import Database
from afterlife_server.net import Server
from afterlife_server.util import log, setup_logging


def main() -> int:
    os.umask(0o077)
    setup_logging()
    try:
        crypto = CryptoBox(C.MASTER_KEY_PATH)
        db = Database(C.DB_PATH, crypto)
        db.ensure_bootstrap_admin(C.BOOTSTRAP_ADMIN_USERNAME, C.BOOTSTRAP_PASSWORD_FILE)
    except RuntimeError as exc:
        log(f"FATAL {exc}")
        return 2
    try:
        asyncio.run(Server(db).serve())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
