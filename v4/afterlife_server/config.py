"""Configuration. Every tunable is read once from the environment."""
from __future__ import annotations

import os
import re
from pathlib import Path


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        raise SystemExit(f"{name} must be an integer")


def _float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except ValueError:
        raise SystemExit(f"{name} must be a number")


def _bool(name: str, default: bool) -> bool:
    return os.environ.get(name, "1" if default else "0").strip().lower() in {"1", "true", "yes", "on"}


# ---------------------------------------------------------------- paths / net
DB_PATH = Path(os.environ.get("AFTERLIFE_DB_PATH", "./data/AFTERLIFE.db"))
# The master key lives in a SEPARATE directory from the database so a copy of
# ./data alone discloses nothing.
MASTER_KEY_PATH = Path(os.environ.get("AFTERLIFE_MASTER_KEY_PATH", "./secrets/master.key"))
# One-time bootstrap admin password file. Read on first boot, then deleted.
BOOTSTRAP_PASSWORD_FILE = Path(os.environ.get("AFTERLIFE_BOOTSTRAP_PASSWORD_FILE", "./secrets/bootstrap_admin_password"))
BOOTSTRAP_ADMIN_USERNAME = os.environ.get("AFTERLIFE_BOOTSTRAP_ADMIN_USERNAME", "").strip()
LOG_PATH = Path(os.environ.get("AFTERLIFE_LOG_PATH", "./data/server.log"))
LOG_MAX_BYTES = _int("AFTERLIFE_LOG_MAX_BYTES", 10 * 1024 * 1024)
LOG_BACKUPS = _int("AFTERLIFE_LOG_BACKUPS", 5)
# Privacy mode (default ON): do not record who chats with whom, chat ids, or
# per-request network identifiers in the log.
LOG_PRIVACY = _bool("AFTERLIFE_LOG_PRIVACY", True)

# Listen on a unix socket (production: shared only with the tor container) or TCP (dev).
UNIX_SOCKET = os.environ.get("AFTERLIFE_UNIX_SOCKET", "")
HOST = os.environ.get("AFTERLIFE_HOST", "127.0.0.1")
PORT = _int("AFTERLIFE_PORT", 2077)
# When enabled, every connection MUST begin with the PROXY header that tor emits
# with `HiddenServiceExportCircuitID haproxy`; connections without it are dropped.
REQUIRE_PROXY_HEADER = _bool("AFTERLIFE_REQUIRE_PROXY_HEADER", False)

# ---------------------------------------------------------------- connection limits
REQUEST_DEADLINE_SECONDS = _float("AFTERLIFE_REQUEST_DEADLINE", 15.0)   # whole request, not per recv
PROXY_HEADER_DEADLINE_SECONDS = 5.0
MAX_REQUEST_LINE_BYTES = _int("AFTERLIFE_MAX_REQUEST_LINE_BYTES", 8192)
MAX_JSON_DEPTH = 8
MAX_CONNECTIONS = _int("AFTERLIFE_MAX_CONNECTIONS", 1024)               # cheap with asyncio
MAX_CONN_PER_CIRCUIT = _int("AFTERLIFE_MAX_CONN_PER_CIRCUIT", 4)
MAX_WORKERS = _int("AFTERLIFE_MAX_WORKERS", 16)                         # DB / crypto threads
MAX_QUEUED_JOBS = _int("AFTERLIFE_MAX_QUEUED_JOBS", 256)                # work admitted to the pool

# Per-circuit request budget (all actions). Every Tor circuit is a separate key.
CIRCUIT_RATE_WINDOW = 60
CIRCUIT_RATE_MAX = _int("AFTERLIFE_CIRCUIT_RATE_MAX", 120)
SESSION_RATE_WINDOW = 60
SESSION_RATE_MAX = _int("AFTERLIFE_SESSION_RATE_MAX", 240)
MESSAGE_RATE_WINDOW = 30
MESSAGE_RATE_MAX = 10
FORUM_WRITE_WINDOW = 60
FORUM_WRITE_MAX = 10
SEARCH_RATE_WINDOW = 60
SEARCH_RATE_MAX = 10
CHALLENGE_RATE_WINDOW = 60
CHALLENGE_RATE_MAX = _int("AFTERLIFE_CHALLENGE_RATE_MAX", 30)            # per circuit / per session
SESSION_IDLE_SECONDS = 3600

# ---------------------------------------------------------------- text limits
MAX_TITLE_LEN = 32
MAX_DESC_LEN = 256
MAX_MESSAGE_LEN = 128                     # plaintext limit, enforced by clients for E2E
MAX_THREAD_TITLE_LEN = 100
MAX_THREAD_BODY_LEN = 2096
MAX_COMMENT_LEN = 1000
MAX_SEARCH_QUERY_LEN = 64
MIN_SEARCH_QUERY_LEN = 3
MAX_SEARCH_RESULTS = 50
SEARCH_MAX_CANDIDATES = 300
PAGE_SIZE = 10
POSTS_PAGE_SIZE = 20
MESSAGES_PAGE_SIZE = 50
ADMIN_PAGE_SIZE = 50
MIN_NICK_LEN = 3
MAX_NICK_LEN = 12
MIN_PASSWORD_LEN = 10
MAX_PASSWORD_LEN = 128
MAX_REWARD = 99_999_999
MAX_MIN_REPUTATION = 999_999
MAX_ID = 2**62
MAX_PAGE = 100_000
BAN_LABEL = "[banned]"

TEXT_CHARS = r"A-Za-z0-9 _.,:;!?()\-\[\]@"
ALLOWED_TEXT_RE = re.compile(rf"^[{TEXT_CHARS}]{{1,256}}$")
THREAD_TITLE_RE = re.compile(rf"^[{TEXT_CHARS}]{{1,100}}$")
THREAD_BODY_RE = re.compile(rf"^[{TEXT_CHARS}\n]{{1,2096}}$")
COMMENT_RE = re.compile(rf"^[{TEXT_CHARS}\n]{{1,1000}}$")
SEARCH_QUERY_RE = re.compile(rf"^[{TEXT_CHARS}]{{1,64}}$")
NICK_RE = re.compile(r"^[A-Za-z0-9_]{3,12}$")
INVITE_CODE_RE = re.compile(r"^[A-Za-z0-9_\-]{16,64}$")
PRIVATE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{16,64}$")
TOKEN_RE = re.compile(r"[a-z0-9]{3,}")
FORBIDDEN_CHARS = set("'\"\\/%+")

# Names that may never be registered (compared on the confusable "skeleton").
RESERVED_NICKS = {
    "admin", "administrator", "root", "system", "sysop", "mod", "moderator", "staff",
    "support", "afterlife", "server", "official", "security", "owner", "operator",
    "tor", "deleted", "unknown", "banned", "null", "none", "anonymous",
}

# ---------------------------------------------------------------- reputation / ratings
RATING_CHOICES = {"positive": 1, "negative": -1}
NEGATIVE_REP_POST_THRESHOLD = -10.0
NEGATIVE_RATING_BURST_WINDOW = 86400
NEGATIVE_RATING_BURST_LIMIT = 3
RATING_WEIGHT_FULL_AT = 10.0
NEGATIVE_RATING_MIN_WEIGHT = 0.1
RATING_PAIR_DECAY = 0.5          # nth rating between the same two users (any direction)
RATING_RECIPROCAL_FACTOR = 0.5   # rating someone who already rated you positively
RATER_DAILY_POSITIVE_BUDGET = 3.0
RATING_TARGET_DAILY_NEGATIVE_CAP = 3.0   # max reputation a target can lose to ratings per 24h

BASE_JOB_REP = 1.0
AUTHOR_WEIGHT_FULL_AT = 10.0
JOB_DAILY_DECAY = 0.6
JOB_PAIR_DECAY = 0.5
JOB_DAILY_CAP_BASE = 3
AUTHOR_GRANT_DAILY_CAP = 5.0
JOB_MIN_AGE_FOR_REP_SECONDS = _int("AFTERLIFE_JOB_MIN_AGE", 3600)   # instant "done" earns nothing
JOB_CONFIRM_TIMEOUT_SECONDS = _int("AFTERLIFE_JOB_CONFIRM_TIMEOUT", 7 * 86400)

# ---------------------------------------------------------------- trust ladder
TRUST_L1_MIN_AGE = _int("AFTERLIFE_TRUST_L1_AGE", 24 * 3600)
TRUST_L1_MIN_REP = 0.0
TRUST_L2_MIN_AGE = _int("AFTERLIFE_TRUST_L2_AGE", 7 * 86400)
TRUST_L2_MIN_REP = 10.0
TRUST_L2_MIN_PARTNERS = 3
READONLY_WINDOW = _int("AFTERLIFE_READONLY_WINDOW", 24 * 3600)

QUOTA_ACTIONS = ("create_thread", "post_comment", "create_job", "open_chat", "accept_job", "send_message")
DAILY_QUOTAS = {
    0: {"create_thread": 1, "post_comment": 5, "create_job": 1, "open_chat": 2, "accept_job": 3, "send_message": 50},
    1: {"create_thread": 5, "post_comment": 50, "create_job": 10, "open_chat": 10, "accept_job": 20, "send_message": 400},
    2: {"create_thread": 20, "post_comment": 200, "create_job": 50, "open_chat": 50, "accept_job": 100, "send_message": 2000},
    3: {a: 100_000 for a in QUOTA_ACTIONS},
}

# ---------------------------------------------------------------- invites
INVITE_MIN_TRUST_LEVEL = 2
INVITE_MAX_OUTSTANDING = 5
INVITE_MAX_PER_30_DAYS = _int("AFTERLIFE_INVITE_MAX_PER_30_DAYS", 3)
INVITE_TTL_SECONDS = _int("AFTERLIFE_INVITE_TTL_SECONDS", 14 * 86400)
INVITE_BAN_PENALTY = 2.0

# ---------------------------------------------------------------- registration
REGISTRATION_SOFT_CAP_PER_HOUR = _int("AFTERLIFE_REG_MAX_PER_HOUR", 20)
REGISTRATION_HARD_CAP_PER_HOUR = _int("AFTERLIFE_REG_HARD_MAX_PER_HOUR", 200)
REGISTRATION_EXTRA_BITS_MAX = 8
PENDING_QUEUE_MAX = _int("AFTERLIFE_PENDING_QUEUE_MAX", 200)
PENDING_EXPIRE_SECONDS = 7 * 86400
REG_MODE_OPEN, REG_MODE_INVITE, REG_MODE_CLOSED = "open", "invite", "closed"
VALID_REG_MODES = {REG_MODE_OPEN, REG_MODE_INVITE, REG_MODE_CLOSED}

# ---------------------------------------------------------------- proof of work
POW_SCRYPT_N = _int("AFTERLIFE_POW_SCRYPT_N", 1 << 13)
POW_SCRYPT_R = _int("AFTERLIFE_POW_SCRYPT_R", 8)
POW_SCRYPT_P = _int("AFTERLIFE_POW_SCRYPT_P", 1)
POW_SCRYPT_MAXMEM = 64 * 1024 * 1024
POW_BASE_DIFFICULTY = _int("AFTERLIFE_POW_DIFFICULTY", 5)
POW_MIN_DIFFICULTY = 1
POW_MAX_DIFFICULTY = _int("AFTERLIFE_POW_MAX_DIFFICULTY", 20)
POW_CHALLENGE_TTL = _int("AFTERLIFE_POW_TTL_SECONDS", 600)
POW_MAX_CHALLENGES = _int("AFTERLIFE_POW_MAX_CHALLENGES", 100_000)
POW_MAX_OUTSTANDING_PER_KEY = 10
POW_PREFIX_BYTES = 16
POW_WRITE_EXEMPT_REP = _float("AFTERLIFE_POW_WRITE_EXEMPT_REP", 5)
POW_WRITE_PURPOSES = {"create_job", "create_thread", "post_comment", "open_chat", "accept_job"}
POW_SESSION_PURPOSES = POW_WRITE_PURPOSES | {"rate_user"}
POW_PURPOSES = {"register", "login"} | POW_SESSION_PURPOSES
# Failed logins raise the login difficulty. The per-(nickname, circuit) part
# punishes the guesser; the global per-nickname part is capped low so a third
# party can never make an account's login expensive.
LOGIN_FAIL_WINDOW = 900
LOGIN_FAIL_CIRCUIT_MAX_EXTRA = 8
LOGIN_FAIL_GLOBAL_MAX_EXTRA = 3
LOGIN_FAIL_GLOBAL_STEP_EVERY = 5        # +1 global bit per 5 failures from anywhere

# ---------------------------------------------------------------- behavioural flags
TIMING_MIN_SAMPLES = 16
TIMING_REGULARITY_CV = 0.06
FAST_REPLY_SECONDS = 5
CONTENT_SIMHASH_WINDOW = 500
CONTENT_SIMHASH_MAX_HAMMING = 3
COORD_REGISTRATION_WINDOW = 600
ACTIVITY_HISTORY = 64
FLAG_DEDUPE_SECONDS = 6 * 3600
FLAG_RETENTION_SECONDS = 30 * 86400

# ---------------------------------------------------------------- E2E chat
E2E_PUBKEY_B64_LEN = 44                 # 32-byte X25519 key, standard base64
E2E_MAX_CIPHERTEXT_B64 = 400            # nonce(12)+ct(<=4*128 utf8 bytes is impossible: ASCII only)+tag(16)
E2E_KEY_ROTATIONS_PER_DAY = 3
