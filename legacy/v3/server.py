#!/usr/bin/env python3
"""AFTERLIFE server — plain TCP JSON protocol over a Tor hidden service.

This revision hardens the platform against bots, sybil identities and
LLM-driven automation. The strategy is NOT to try to detect "an AI" over a
text protocol with an open-source client (that is not reliably possible), but
to make an automated account cost as much, earn trust as slowly, and do as
little damage as a human newcomer. The layers:

  * Memory-hard, reputation-adaptive proof-of-work (scrypt) on identity and
    write actions. Difficulty falls 1 bit per +10 reputation and rises 1 bit
    per negative reputation point.
  * Invite / vouch registration with admin-controlled registration modes
    (open / invite-only / closed) and a global "approval lock" that routes all
    new accounts through a manual admin queue. Global registration rate cap.
  * Decimal reputation. Ratings are weighted by the rater's own trust
    (EigenTrust-style) and are only allowed between counterparties of a
    completed job, once per job. Admins can adjust reputation without limit.
  * Anti-farm job reputation: a completion only confers reputation in
    proportion to the *employer's* trust, with per-day and per-pair diminishing
    returns and a per-employer daily granting cap. Fake employers (reputation
    <= 0) confer nothing, so reputation cannot be minted from sybil jobs.
  * A trust ladder (level from reputation + account age + distinct job
    partners) with an initial read-only window and per-level daily quotas.
  * Brigade detection that acts: a burst of negative ratings is frozen (its
    effect withheld) and queued for admin review.
  * An HMAC keyword index so forum search no longer decrypts every row.
  * Behavioral signals (timing regularity, unseen-thread replies, cross-account
    near-duplicate content, coordinated registration) reported to a moderation
    queue — never auto-banning, so custom clients are not punished for being
    different.
  * Removal of the per-IP global lockout (every Tor client is 127.0.0.1) and of
    the login lockout DoS, replaced by per-session limits, a high server-wide
    circuit breaker, and per-nickname PoW escalation on failed logins.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import socket
import sqlite3
import statistics
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from cryptography.fernet import Fernet, InvalidToken

# =========================
# Configuration
# =========================
HOST = os.environ.get("AFTERLIFE_HOST", "127.0.0.1")
PORT = int(os.environ.get("AFTERLIFE_PORT", "2077"))
DB_PATH = Path(os.environ.get("AFTERLIFE_DB_PATH", "./AFTERLIFE.db"))
MASTER_KEY_PATH = Path(os.environ.get("AFTERLIFE_MASTER_KEY_PATH", "./master.key"))
LOG_PATH = Path(os.environ.get("AFTERLIFE_LOG_PATH", "./server.log"))

MAX_TITLE_LEN = 32
MAX_DESC_LEN = 256
MAX_MESSAGE_LEN = 128
MAX_THREAD_TITLE_LEN = 100
MAX_THREAD_BODY_LEN = 2096
MAX_THREAD_BODY_BYTES = 4096
MAX_COMMENT_LEN = 1000
MAX_SEARCH_QUERY_LEN = 64
MIN_SEARCH_QUERY_LEN = 3
MAX_SEARCH_RESULTS = 50
SEARCH_MAX_CANDIDATES = 300     # hard ceiling on rows decrypted per search
PAGE_SIZE = 10
MIN_NICK_LEN = 3
MAX_NICK_LEN = 12
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 64
MAX_REWARD = 99_999_999
MAX_MIN_REPUTATION = 999_999
BAN_LABEL = "[banned]"
MAX_REQUEST_LINE_BYTES = int(os.environ.get("AFTERLIFE_MAX_REQUEST_LINE_BYTES", "8192"))
MAX_JSON_DEPTH = int(os.environ.get("AFTERLIFE_MAX_JSON_DEPTH", "16"))
MAX_PARSE_ERRORS_PER_WINDOW = int(os.environ.get("AFTERLIFE_MAX_PARSE_ERRORS_PER_WINDOW", "50"))
MAX_CONNECTIONS = int(os.environ.get("AFTERLIFE_MAX_CONNECTIONS", "100"))
MAX_WORKERS = int(os.environ.get("AFTERLIFE_MAX_WORKERS", "32"))
MAX_INVITE_CODE_LEN = 128

FORBIDDEN_CHARS = set("'\"\\/%+")
ALLOWED_TEXT_RE = re.compile(r"^[A-Za-z0-9 _.,:;!?()\-\[\]@]{1,256}$")
MESSAGE_RE = re.compile(r"^[A-Za-z0-9 _.,:;!?()\-\[\]@]{1,128}$")
THREAD_TITLE_RE = re.compile(r"^[A-Za-z0-9 _.,:;!?()\-\[\]@]{1,100}$")
THREAD_BODY_RE = re.compile(r"^[A-Za-z0-9 _.,:;!?()\-\[\]@\n]{1,2096}$")
COMMENT_RE = re.compile(r"^[A-Za-z0-9 _.,:;!?()\-\[\]@\n]{1,1000}$")
SEARCH_QUERY_RE = re.compile(r"^[A-Za-z0-9 _.,:;!?()\-\[\]@]{1,64}$")
NICK_RE = re.compile(r"^[A-Za-z0-9_]{3,12}$")
INVITE_CODE_RE = re.compile(r"^[A-Za-z0-9_\-]{8,128}$")
TOKEN_RE = re.compile(r"[a-z0-9]{3,}")
RATING_CHOICES = {"positive": 1, "negative": -1}

# --- Throttling / sessions ---
SERVER_WINDOW_SECONDS = 10
SERVER_MAX_REQUESTS_PER_WINDOW = int(os.environ.get("AFTERLIFE_SERVER_MAX_RPS_WINDOW", "2000"))
READ_TIMEOUT_SECONDS = 180
SESSION_IDLE_SECONDS = 3600
PAIR_CHANGE_COOLDOWN_SECONDS = 86400
MESSAGE_RATE_WINDOW_SECONDS = 30
MESSAGE_RATE_MAX_MESSAGES = 10
SESSION_RATE_WINDOW_SECONDS = 60
SESSION_RATE_MAX_REQUESTS = 240
FORUM_WRITE_WINDOW_SECONDS = 60
FORUM_WRITE_MAX = 10
SEARCH_RATE_WINDOW_SECONDS = 60
SEARCH_RATE_MAX = 10
CHALLENGE_RATE_WINDOW_SECONDS = 60
CHALLENGE_RATE_MAX = 60         # per key (session token, or ip for pre-auth)

# --- Forum posting reputation gate ---
NEGATIVE_REP_POST_THRESHOLD = -10.0

# --- Brigade detection ---
NEGATIVE_RATING_BURST_WINDOW_SECONDS = 86400
NEGATIVE_RATING_BURST_LIMIT = 5

# --- Proof-of-work (memory-hard, adaptive) ---
# scrypt makes each guess memory-hard (GPU/ASIC gain is small); difficulty is
# the number of leading zero bits required of the scrypt digest. Cost to solve
# is ~2^difficulty scrypt evaluations; verification is a single evaluation.
POW_SCRYPT_N = int(os.environ.get("AFTERLIFE_POW_SCRYPT_N", str(1 << 13)))   # 8 MiB with r=8
POW_SCRYPT_R = int(os.environ.get("AFTERLIFE_POW_SCRYPT_R", "8"))
POW_SCRYPT_P = int(os.environ.get("AFTERLIFE_POW_SCRYPT_P", "1"))
POW_SCRYPT_MAXMEM = 256 * 1024 * 1024
POW_BASE_DIFFICULTY = int(os.environ.get("AFTERLIFE_POW_DIFFICULTY", "5"))
POW_MIN_DIFFICULTY = int(os.environ.get("AFTERLIFE_POW_MIN_DIFFICULTY", "1"))
POW_MAX_DIFFICULTY = int(os.environ.get("AFTERLIFE_POW_MAX_DIFFICULTY", "22"))
POW_CHALLENGE_TTL_SECONDS = int(os.environ.get("AFTERLIFE_POW_TTL_SECONDS", "300"))
POW_MAX_CHALLENGES = int(os.environ.get("AFTERLIFE_POW_MAX_CHALLENGES", "20000"))
POW_PREFIX_BYTES = 16
# Login failures escalate the login PoW for that nickname (no hard lockout).
LOGIN_FAIL_WINDOW_SECONDS = 900
LOGIN_FAIL_POW_STEP = 1         # +1 bit per recent failure
LOGIN_FAIL_POW_MAX_EXTRA = 12
# Writes by users at/above this reputation skip PoW (kept smooth for the trusted).
POW_WRITE_EXEMPT_REP = float(os.environ.get("AFTERLIFE_POW_WRITE_EXEMPT_REP", "5"))
POW_WRITE_PURPOSES = {"create_job", "create_thread", "post_comment", "open_chat"}
POW_PURPOSES = {"register", "login", "rate_user"} | POW_WRITE_PURPOSES

# --- Registration ---
REGISTRATION_GLOBAL_MAX_PER_HOUR = int(os.environ.get("AFTERLIFE_REG_MAX_PER_HOUR", "20"))
REG_MODE_OPEN = "open"
REG_MODE_INVITE = "invite"
REG_MODE_CLOSED = "closed"
VALID_REG_MODES = {REG_MODE_OPEN, REG_MODE_INVITE, REG_MODE_CLOSED}

# --- Invites / vouching ---
INVITE_MIN_TRUST_LEVEL = 2
INVITE_MAX_OUTSTANDING = 5
INVITE_TTL_SECONDS = int(os.environ.get("AFTERLIFE_INVITE_TTL_SECONDS", str(30 * 86400)))
INVITE_BAN_PENALTY = 2.0        # reputation the inviter loses if an invitee is banned/wiped

# --- Trust ladder ---
TRUST_L1_MIN_AGE_SECONDS = int(os.environ.get("AFTERLIFE_TRUST_L1_AGE", str(24 * 3600)))
TRUST_L1_MIN_REP = 0.0
TRUST_L2_MIN_AGE_SECONDS = int(os.environ.get("AFTERLIFE_TRUST_L2_AGE", str(7 * 86400)))
TRUST_L2_MIN_REP = 10.0
TRUST_L2_MIN_PARTNERS = 3
READONLY_WINDOW_SECONDS = int(os.environ.get("AFTERLIFE_READONLY_WINDOW", str(24 * 3600)))

# Per-trust-level daily quotas: (create_thread, post_comment, create_job, open_chat)
DAILY_QUOTAS = {
    0: {"create_thread": 1, "post_comment": 5, "create_job": 1, "open_chat": 2},
    1: {"create_thread": 5, "post_comment": 50, "create_job": 10, "open_chat": 20},
    2: {"create_thread": 20, "post_comment": 200, "create_job": 50, "open_chat": 100},
    3: {"create_thread": 10_000, "post_comment": 10_000, "create_job": 10_000, "open_chat": 10_000},
}

# --- Rating weighting (EigenTrust-lite) ---
RATING_WEIGHT_MIN = 0.1
RATING_WEIGHT_FULL_AT = 10.0    # rater reputation at which a rating counts fully

# --- Job-completion reputation (anti-farm) ---
BASE_JOB_REP = 1.0
AUTHOR_WEIGHT_FULL_AT = 10.0    # employer reputation at which grants are full-weight
JOB_DAILY_DECAY = 0.6           # nth rep-earning completion today -> BASE * decay^n
JOB_PAIR_DECAY = 0.5            # nth completion with the same employer -> * decay^n
JOB_DAILY_CAP_BASE = 3          # rep-earning completions/day for a normal user
AUTHOR_GRANT_DAILY_CAP = 5.0    # total reputation one employer can confer per day

# --- Behavioral flags (report only) ---
TIMING_MIN_SAMPLES = 8
TIMING_REGULARITY_CV = 0.06     # coefficient of variation below this = metronomic
FAST_REPLY_SECONDS = 5          # comment within N s of a thread's creation
CONTENT_SIMHASH_WINDOW = 500
CONTENT_SIMHASH_MAX_HAMMING = 3
COORD_REGISTRATION_WINDOW_SECONDS = 600
ACTIVITY_HISTORY = 64

BOOTSTRAP_ADMIN_USERNAME = os.environ.get("AFTERLIFE_BOOTSTRAP_ADMIN_USERNAME")
BOOTSTRAP_ADMIN_PASSWORD = os.environ.get("AFTERLIFE_BOOTSTRAP_ADMIN_PASSWORD")


def clear_bootstrap_admin_password() -> None:
    global BOOTSTRAP_ADMIN_PASSWORD
    os.environ.pop("AFTERLIFE_BOOTSTRAP_ADMIN_PASSWORD", None)
    BOOTSTRAP_ADMIN_PASSWORD = None


@dataclass
class AppContext:
    db_path: Path
    master_key_path: Path
    log_path: Path
    crypto: "CryptoBox"
    db: "Database"


APP: Optional[AppContext] = None


def get_app() -> AppContext:
    if APP is None:
        raise RuntimeError("Application context not initialized.")
    return APP


def get_db() -> "Database":
    return get_app().db


def get_crypto() -> "CryptoBox":
    return get_app().crypto


def get_log_path() -> Path:
    return get_app().log_path if APP is not None else LOG_PATH


# =========================
# Utilities
# =========================
print_lock = threading.Lock()


def sanitize_log_value(value: Any) -> str:
    text = str(value)
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = "".join(ch for ch in text if ch.isprintable())
    for ch in ("'", '"', "%", "|", "+"):
        text = text.replace(ch, "")
    text = re.sub(r"\s+", " ", text).strip()
    return text


def log(message: str) -> None:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    safe_message = sanitize_log_value(message)
    line = f"[{timestamp}] {safe_message}\n"
    log_path = get_log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(line)
    with print_lock:
        print(line, end="")


def audit_log(
    event: str,
    *,
    ip: Optional[str] = None,
    actor_nickname: Optional[str] = None,
    action: Optional[str] = None,
    target_user: Optional[str] = None,
    job_id: Optional[int] = None,
    chat_id: Optional[int] = None,
    thread_id: Optional[int] = None,
    post_id: Optional[int] = None,
    status: str = "INFO",
    details: Optional[str] = None,
) -> None:
    parts = [f"event={sanitize_log_value(event)}", f"status={sanitize_log_value(status)}"]
    if action is not None:
        parts.append(f"action={sanitize_log_value(action)}")
    if ip is not None:
        parts.append(f"ip={sanitize_log_value(ip)}")
    if actor_nickname:
        parts.append(f"actor={sanitize_log_value(actor_nickname)}")
    if target_user:
        parts.append(f"target_user={sanitize_log_value(target_user)}")
    if job_id is not None:
        parts.append(f"job_id={job_id}")
    if chat_id is not None:
        parts.append(f"chat_id={chat_id}")
    if thread_id is not None:
        parts.append(f"thread_id={thread_id}")
    if post_id is not None:
        parts.append(f"post_id={post_id}")
    if details:
        parts.append(f"details={sanitize_log_value(details)}")
    log(" ".join(parts))


def pbkdf2_hash(value: str, salt: Optional[bytes] = None) -> str:
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), salt, 200_000)
    return f"{base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def pbkdf2_verify(value: str, stored: str) -> bool:
    try:
        salt_b64, digest_b64 = stored.split("$", 1)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        digest = hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), salt, 200_000)
        return hmac.compare_digest(digest, expected)
    except Exception:
        return False


def derive_fernet_key(master_secret: bytes) -> bytes:
    digest = hashlib.sha256(master_secret).digest()
    return base64.urlsafe_b64encode(digest)


def day_epoch(ts: Optional[float] = None) -> int:
    return int((ts if ts is not None else time.time()) // 86400)


class CryptoBox:
    def __init__(self, master_path: Path) -> None:
        master_path.parent.mkdir(parents=True, exist_ok=True)
        if master_path.exists():
            master_secret = master_path.read_bytes().strip()
        else:
            master_secret = secrets.token_bytes(32)
            master_path.write_bytes(master_secret)
            try:
                os.chmod(master_path, 0o600)
            except OSError:
                pass
        self._master_secret = master_secret
        self.fernet = Fernet(derive_fernet_key(master_secret))
        # A separate, index-only key. HMAC(term) is deterministic so search can
        # find candidate rows without decrypting every stored thread.
        self._search_key = hashlib.sha256(master_secret + b"afterlife-search-index").digest()

    def enc(self, value: str) -> str:
        return self.fernet.encrypt(value.encode("utf-8")).decode("utf-8")

    def dec(self, value: Optional[str]) -> str:
        if not value:
            return ""
        try:
            return self.fernet.decrypt(value.encode("utf-8")).decode("utf-8")
        except InvalidToken:
            return ""

    def term_hmac(self, term: str) -> str:
        return hmac.new(self._search_key, term.encode("utf-8"), hashlib.sha256).hexdigest()


# =========================
# Proof-of-work primitives
# =========================
def leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        bits += 8 - byte.bit_length()
        break
    return bits


def pow_digest(prefix: str, nonce: str) -> bytes:
    """Memory-hard digest for the client puzzle. Salt is bound to the prefix so
    each challenge has an independent scrypt search space."""
    return hashlib.scrypt(
        f"{prefix}:{nonce}".encode("utf-8"),
        salt=prefix.encode("utf-8"),
        n=POW_SCRYPT_N,
        r=POW_SCRYPT_R,
        p=POW_SCRYPT_P,
        maxmem=POW_SCRYPT_MAXMEM,
        dklen=32,
    )


def pow_solution_ok(prefix: str, nonce: str, difficulty: int) -> bool:
    return leading_zero_bits(pow_digest(prefix, str(nonce))) >= difficulty


def clamp_difficulty(value: int) -> int:
    return max(POW_MIN_DIFFICULTY, min(POW_MAX_DIFFICULTY, int(value)))


def difficulty_for_reputation(rep: float) -> int:
    """-1 bit per +10 reputation; +1 bit per negative reputation point."""
    if rep >= 0:
        d = POW_BASE_DIFFICULTY - int(rep // 10)
    else:
        d = POW_BASE_DIFFICULTY + int(math.ceil(-rep))
    return clamp_difficulty(d)


# =========================
# Validation
# =========================
def has_forbidden_chars(value: str) -> bool:
    return any(ch in FORBIDDEN_CHARS for ch in value)


def validate_nickname(nickname: str) -> Optional[str]:
    if not NICK_RE.fullmatch(nickname):
        return "Nickname must be 3-12 chars and contain only letters, digits, and underscore."
    if has_forbidden_chars(nickname):
        return "Nickname contains forbidden characters."
    return None


def validate_password(password: str) -> Optional[str]:
    if len(password) < MIN_PASSWORD_LEN:
        return f"Password must be at least {MIN_PASSWORD_LEN} characters."
    if len(password) > MAX_PASSWORD_LEN:
        return f"Password must be at most {MAX_PASSWORD_LEN} characters."
    return None


def validate_invite_code(code: str) -> Optional[str]:
    if len(code) > MAX_INVITE_CODE_LEN or not INVITE_CODE_RE.fullmatch(code):
        return "Invalid invite code format."
    return None


def validate_title(title: str) -> Optional[str]:
    if not title or len(title) > MAX_TITLE_LEN:
        return f"Title must be 1-{MAX_TITLE_LEN} characters."
    if has_forbidden_chars(title):
        return "Title contains forbidden characters."
    if not ALLOWED_TEXT_RE.fullmatch(title):
        return "Title contains unsupported characters."
    return None


def validate_description(description: str) -> Optional[str]:
    if not description or len(description) > MAX_DESC_LEN:
        return f"Description must be 1-{MAX_DESC_LEN} characters."
    if has_forbidden_chars(description):
        return "Description contains forbidden characters."
    if not ALLOWED_TEXT_RE.fullmatch(description):
        return "Description contains unsupported characters."
    return None


def validate_message_text(message: str) -> Optional[str]:
    if not message or len(message) > MAX_MESSAGE_LEN:
        return f"Message must be 1-{MAX_MESSAGE_LEN} characters."
    if has_forbidden_chars(message):
        return "Message contains forbidden characters."
    if not MESSAGE_RE.fullmatch(message):
        return "Message contains unsupported characters."
    return None


def validate_thread_title(title: str) -> Optional[str]:
    if not title or len(title) > MAX_THREAD_TITLE_LEN:
        return f"Thread title must be 1-{MAX_THREAD_TITLE_LEN} characters."
    if has_forbidden_chars(title):
        return "Thread title contains forbidden characters."
    if not THREAD_TITLE_RE.fullmatch(title):
        return "Thread title contains unsupported characters."
    return None


def validate_thread_body(body: str) -> Optional[str]:
    if not body or len(body) > MAX_THREAD_BODY_LEN:
        return f"Thread body must be 1-{MAX_THREAD_BODY_LEN} characters."
    if len(body.encode("utf-8")) > MAX_THREAD_BODY_BYTES:
        return f"Thread body must be at most {MAX_THREAD_BODY_BYTES} bytes."
    if has_forbidden_chars(body):
        return "Thread body contains forbidden characters."
    if not THREAD_BODY_RE.fullmatch(body):
        return "Thread body contains unsupported characters (text only, no emoji or images)."
    return None


def validate_comment_text(body: str) -> Optional[str]:
    if not body or len(body) > MAX_COMMENT_LEN:
        return f"Comment must be 1-{MAX_COMMENT_LEN} characters."
    if has_forbidden_chars(body):
        return "Comment contains forbidden characters."
    if not COMMENT_RE.fullmatch(body):
        return "Comment contains unsupported characters (text only, no emoji or images)."
    return None


def validate_search_query(query: str) -> Optional[str]:
    if not query or len(query) < MIN_SEARCH_QUERY_LEN:
        return f"Search query must be at least {MIN_SEARCH_QUERY_LEN} characters."
    if len(query) > MAX_SEARCH_QUERY_LEN:
        return f"Search query must be at most {MAX_SEARCH_QUERY_LEN} characters."
    if has_forbidden_chars(query):
        return "Search query contains forbidden characters."
    if not SEARCH_QUERY_RE.fullmatch(query):
        return "Search query contains unsupported characters."
    return None


def parse_page(request: dict[str, Any]) -> int:
    try:
        page = int(request.get("page", 1))
    except (TypeError, ValueError):
        return 1
    return page if page >= 1 else 1


def pagination_meta(total: int, page: int, per_page: int = PAGE_SIZE) -> dict[str, Any]:
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(max(1, page), total_pages)
    return {
        "page": page,
        "per_page": per_page,
        "total": total,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
    }


def validate_reward(raw: str) -> Optional[str]:
    if not raw.isdigit():
        return "Reward must contain digits only."
    value = int(raw)
    if value < 1 or value > MAX_REWARD:
        return f"Reward must be between 1 and {MAX_REWARD}."
    return None


def validate_min_reputation(raw: str) -> Optional[str]:
    if raw.startswith("-"):
        sign = -1
        digits = raw[1:]
    else:
        sign = 1
        digits = raw
    if not digits.isdigit():
        return "Minimum reputation must be an integer."
    value = sign * int(digits)
    if value < -MAX_MIN_REPUTATION or value > MAX_MIN_REPUTATION:
        return f"Minimum reputation must be between {-MAX_MIN_REPUTATION} and {MAX_MIN_REPUTATION}."
    return None


def validate_rating_choice(value: str) -> Optional[str]:
    if value not in RATING_CHOICES:
        return "Rating must be positive or negative."
    return None


def json_depth(value: Any, depth: int = 0) -> int:
    if depth > MAX_JSON_DEPTH:
        return depth
    if isinstance(value, dict):
        if not value:
            return depth + 1
        return max(json_depth(v, depth + 1) for v in value.values())
    if isinstance(value, list):
        if not value:
            return depth + 1
        return max(json_depth(v, depth + 1) for v in value)
    return depth + 1


def ensure_request_shape(request: Any) -> Optional[str]:
    if not isinstance(request, dict):
        return "Request must be a JSON object."
    if json_depth(request) > MAX_JSON_DEPTH:
        return f"JSON nesting exceeds limit of {MAX_JSON_DEPTH}."
    return None


def tokenize(text: str) -> list[str]:
    return [t[:32] for t in TOKEN_RE.findall(text.lower())]


def simhash64(text: str) -> int:
    tokens = tokenize(text)
    if not tokens:
        return 0
    v = [0] * 64
    for token in tokens:
        h = int.from_bytes(hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest(), "big")
        for i in range(64):
            v[i] += 1 if (h >> i) & 1 else -1
    out = 0
    for i in range(64):
        if v[i] > 0:
            out |= (1 << i)
    return out


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


# =========================
# Trust ladder helpers
# =========================
def trust_level(rep: float, age_seconds: float, distinct_partners: int, is_admin: bool) -> int:
    if is_admin:
        return 3
    level = 0
    if age_seconds >= TRUST_L1_MIN_AGE_SECONDS and rep >= TRUST_L1_MIN_REP:
        level = 1
    if (level >= 1 and age_seconds >= TRUST_L2_MIN_AGE_SECONDS
            and rep >= TRUST_L2_MIN_REP and distinct_partners >= TRUST_L2_MIN_PARTNERS):
        level = 2
    return level


def rating_weight(rep: float) -> float:
    if rep <= 0:
        return RATING_WEIGHT_MIN
    return max(RATING_WEIGHT_MIN, min(1.0, rep / RATING_WEIGHT_FULL_AT))


def author_grant_weight(rep: float) -> float:
    """How much reputation an employer can confer. Fake/negative employers
    (rep <= 0) confer nothing, so reputation cannot be minted from sybil jobs."""
    if rep <= 0:
        return 0.0
    return min(1.0, rep / AUTHOR_WEIGHT_FULL_AT)


def daily_job_cap(worker_rep: float, level: int) -> int:
    if level <= 0:
        return 1
    return JOB_DAILY_CAP_BASE + int(max(0.0, worker_rep) // 20)


# =========================
# Database
# =========================
class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = threading.RLock()
        self._init_db()
        self._ensure_bootstrap_admin()
        clear_bootstrap_admin_password()

    def conn(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, check_same_thread=False)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA foreign_keys=ON")
        return con

    def _table_columns(self, con: sqlite3.Connection, name: str) -> set[str]:
        return {str(row["name"]) for row in con.execute(f"PRAGMA table_info({name})").fetchall()}

    def _rebuild_if_legacy(self, con: sqlite3.Connection) -> None:
        tables = {str(r[0]) for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if "users" in tables:
            user_columns = self._table_columns(con, "users")
            if "contact_info_enc" in user_columns:
                log("legacy_schema_detected aborting_startup reason=destructive_migration_disabled")
                raise RuntimeError("Legacy schema detected. Refusing to start with destructive migration disabled.")

    def _init_db(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.conn() as con:
            self._rebuild_if_legacy(con)
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    nickname TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    reputation REAL NOT NULL DEFAULT 0.0,
                    is_admin INTEGER NOT NULL DEFAULT 0,
                    is_banned INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'active',
                    invited_by INTEGER,
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY(invited_by) REFERENCES users(id) ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS invites (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code_hash TEXT NOT NULL UNIQUE,
                    issuer_id INTEGER,
                    used_by INTEGER,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    used_at INTEGER,
                    FOREIGN KEY(issuer_id) REFERENCES users(id) ON DELETE SET NULL,
                    FOREIGN KEY(used_by) REFERENCES users(id) ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS rate_counters (
                    user_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    day INTEGER NOT NULL,
                    count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (user_id, action, day),
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    author_id INTEGER NOT NULL,
                    title_enc TEXT NOT NULL,
                    description_enc TEXT NOT NULL,
                    reward INTEGER NOT NULL,
                    min_reputation INTEGER NOT NULL DEFAULT 0,
                    is_private INTEGER NOT NULL DEFAULT 0,
                    description_password_hash TEXT,
                    status TEXT NOT NULL DEFAULT 'open',
                    selected_worker_id INTEGER,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    FOREIGN KEY(author_id) REFERENCES users(id),
                    FOREIGN KEY(selected_worker_id) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS job_accepts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    UNIQUE(job_id, user_id),
                    FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS job_completions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id INTEGER NOT NULL,
                    author_id INTEGER NOT NULL,
                    worker_id INTEGER NOT NULL,
                    rep_gain REAL NOT NULL DEFAULT 0.0,
                    created_at INTEGER NOT NULL,
                    UNIQUE(job_id),
                    FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS reputation_ratings (
                    rater_id INTEGER NOT NULL,
                    target_id INTEGER NOT NULL,
                    job_id INTEGER NOT NULL,
                    rating_value INTEGER NOT NULL,
                    applied_delta REAL NOT NULL DEFAULT 0.0,
                    frozen INTEGER NOT NULL DEFAULT 0,
                    last_changed_at INTEGER NOT NULL,
                    PRIMARY KEY (rater_id, target_id, job_id),
                    FOREIGN KEY(rater_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(target_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS user_blocks (
                    blocker_id INTEGER NOT NULL,
                    blocked_id INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (blocker_id, blocked_id),
                    FOREIGN KEY(blocker_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(blocked_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS chats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_low_id INTEGER NOT NULL,
                    user_high_id INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    UNIQUE(user_low_id, user_high_id),
                    FOREIGN KEY(user_low_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(user_high_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id INTEGER NOT NULL,
                    sender_id INTEGER,
                    message_type TEXT NOT NULL,
                    body_enc TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY(chat_id) REFERENCES chats(id) ON DELETE CASCADE,
                    FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS message_reads (
                    message_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    read_at INTEGER NOT NULL,
                    PRIMARY KEY (message_id, user_id),
                    FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS threads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    author_id INTEGER NOT NULL,
                    title_enc TEXT NOT NULL,
                    body_enc TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    FOREIGN KEY(author_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS thread_posts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    thread_id INTEGER NOT NULL,
                    author_id INTEGER,
                    body_enc TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY(thread_id) REFERENCES threads(id) ON DELETE CASCADE,
                    FOREIGN KEY(author_id) REFERENCES users(id) ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS thread_search_terms (
                    thread_id INTEGER NOT NULL,
                    term_hmac TEXT NOT NULL,
                    PRIMARY KEY (thread_id, term_hmac),
                    FOREIGN KEY(thread_id) REFERENCES threads(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS content_fingerprints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    kind TEXT NOT NULL,
                    simhash INTEGER NOT NULL,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS moderation_flags (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    nickname TEXT,
                    kind TEXT NOT NULL,
                    detail TEXT,
                    resolved INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_search_term ON thread_search_terms(term_hmac);
                CREATE INDEX IF NOT EXISTS idx_fp_created ON content_fingerprints(created_at);
                CREATE INDEX IF NOT EXISTS idx_flags_resolved ON moderation_flags(resolved);
                """
            )
            self._migrate_schema(con)

    def _migrate_schema(self, con: sqlite3.Connection) -> None:
        job_columns = self._table_columns(con, "jobs")
        if "min_reputation" not in job_columns:
            con.execute("ALTER TABLE jobs ADD COLUMN min_reputation INTEGER NOT NULL DEFAULT 0")

    def _ensure_bootstrap_admin(self) -> None:
        with self.lock, self.conn() as con:
            if not BOOTSTRAP_ADMIN_USERNAME or not BOOTSTRAP_ADMIN_PASSWORD:
                admin_exists = con.execute("SELECT id FROM users WHERE is_admin = 1 LIMIT 1").fetchone()
                if admin_exists:
                    return
                raise RuntimeError(
                    "No admin account exists and AFTERLIFE_BOOTSTRAP_ADMIN_USERNAME / "
                    "AFTERLIFE_BOOTSTRAP_ADMIN_PASSWORD are not set. Set them to create the initial admin."
                )
            if len(BOOTSTRAP_ADMIN_PASSWORD) < 12:
                raise RuntimeError("Bootstrap admin password must be at least 12 characters.")
            if len(BOOTSTRAP_ADMIN_PASSWORD) > MAX_PASSWORD_LEN:
                raise RuntimeError(f"Bootstrap admin password must be at most {MAX_PASSWORD_LEN} characters.")
            nick_err = validate_nickname(BOOTSTRAP_ADMIN_USERNAME)
            if nick_err:
                raise RuntimeError(f"Invalid admin username: {nick_err}")
            existing = con.execute(
                "SELECT id, is_admin, is_banned FROM users WHERE nickname = ?",
                (BOOTSTRAP_ADMIN_USERNAME,),
            ).fetchone()
            now = int(time.time())
            if existing is not None:
                updates = ["password_hash = ?", "status = 'active'"]
                params: list[Any] = [pbkdf2_hash(BOOTSTRAP_ADMIN_PASSWORD)]
                if not bool(existing["is_admin"]):
                    updates.append("is_admin = 1")
                if bool(existing["is_banned"]):
                    updates.append("is_banned = 0")
                params.append(int(existing["id"]))
                con.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
                log(f"Bootstrap admin account {BOOTSTRAP_ADMIN_USERNAME} enforced on existing user.")
                return
            admin_exists = con.execute("SELECT id FROM users WHERE is_admin = 1 LIMIT 1").fetchone()
            if admin_exists:
                return
            con.execute(
                "INSERT INTO users (nickname, password_hash, reputation, is_admin, is_banned, status, created_at) "
                "VALUES (?, ?, 0.0, 1, 0, 'active', ?)",
                (BOOTSTRAP_ADMIN_USERNAME, pbkdf2_hash(BOOTSTRAP_ADMIN_PASSWORD), now),
            )
            log(f"Bootstrap admin account {BOOTSTRAP_ADMIN_USERNAME} created.")

    # ---- settings ----
    def get_setting(self, key: str, default: str) -> str:
        with self.lock, self.conn() as con:
            row = con.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
            return str(row["value"]) if row is not None else default

    def set_setting(self, key: str, value: str) -> None:
        with self.lock, self.conn() as con:
            con.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def registration_mode(self) -> str:
        return self.get_setting("registration_mode", REG_MODE_OPEN)

    def approval_required(self) -> bool:
        return self.get_setting("approval_required", "0") == "1"

    # ---- moderation flags ----
    def add_flag(self, user_id: Optional[int], nickname: Optional[str], kind: str, detail: str) -> None:
        with self.lock, self.conn() as con:
            con.execute(
                "INSERT INTO moderation_flags (user_id, nickname, kind, detail, resolved, created_at) "
                "VALUES (?, ?, ?, ?, 0, ?)",
                (user_id, nickname, kind, detail[:400], int(time.time())),
            )
        audit_log(event="moderation_flag", target_user=nickname, status="warn", details=f"{kind}: {detail}")

    def list_flags(self, include_resolved: bool = False) -> list[dict[str, Any]]:
        with self.lock, self.conn() as con:
            q = "SELECT * FROM moderation_flags"
            if not include_resolved:
                q += " WHERE resolved = 0"
            q += " ORDER BY created_at DESC LIMIT 200"
            rows = con.execute(q).fetchall()
            return [
                {
                    "id": int(r["id"]),
                    "user_id": r["user_id"],
                    "nickname": r["nickname"],
                    "kind": str(r["kind"]),
                    "detail": str(r["detail"] or ""),
                    "resolved": bool(r["resolved"]),
                    "created_at": int(r["created_at"]),
                }
                for r in rows
            ]

    def resolve_flag(self, flag_id: int) -> bool:
        with self.lock, self.conn() as con:
            cur = con.execute("UPDATE moderation_flags SET resolved = 1 WHERE id = ?", (flag_id,))
            return cur.rowcount > 0

    # ---- rate counters (daily quotas) ----
    def peek_counter(self, con: sqlite3.Connection, user_id: int, action: str) -> int:
        row = con.execute(
            "SELECT count FROM rate_counters WHERE user_id = ? AND action = ? AND day = ?",
            (user_id, action, day_epoch()),
        ).fetchone()
        return int(row["count"]) if row is not None else 0

    def bump_counter(self, con: sqlite3.Connection, user_id: int, action: str) -> None:
        con.execute(
            "INSERT INTO rate_counters (user_id, action, day, count) VALUES (?, ?, ?, 1) "
            "ON CONFLICT(user_id, action, day) DO UPDATE SET count = count + 1",
            (user_id, action, day_epoch()),
        )

    # ---- trust context ----
    def distinct_job_partners(self, con: sqlite3.Connection, user_id: int) -> int:
        row = con.execute(
            "SELECT COUNT(DISTINCT partner) AS c FROM ("
            "  SELECT CASE WHEN worker_id = ? THEN author_id ELSE worker_id END AS partner "
            "  FROM job_completions WHERE (worker_id = ? OR author_id = ?) AND rep_gain > 0"
            ")",
            (user_id, user_id, user_id),
        ).fetchone()
        return int(row["c"]) if row is not None else 0

    def trust_context(self, con: sqlite3.Connection, user_row: sqlite3.Row) -> dict[str, Any]:
        rep = float(user_row["reputation"])
        age = max(0, int(time.time()) - int(user_row["created_at"]))
        is_admin = bool(user_row["is_admin"])
        partners = self.distinct_job_partners(con, int(user_row["id"]))
        level = trust_level(rep, age, partners, is_admin)
        return {"reputation": rep, "age": age, "partners": partners, "level": level, "is_admin": is_admin}

    def enforce_write_quota(self, con: sqlite3.Connection, user_row: sqlite3.Row, action: str) -> Optional[str]:
        """Read-only window + per-trust-level daily quota. Returns an error
        string if the write must be rejected, else None (and bumps the counter)."""
        ctx = self.trust_context(con, user_row)
        if not ctx["is_admin"]:
            if ctx["age"] < READONLY_WINDOW_SECONDS:
                remaining = READONLY_WINDOW_SECONDS - ctx["age"]
                hours = max(1, remaining // 3600)
                return f"New accounts are read-only for the first {READONLY_WINDOW_SECONDS // 3600}h (~{hours}h left)."
        quota = DAILY_QUOTAS.get(ctx["level"], DAILY_QUOTAS[0]).get(action)
        if quota is not None:
            used = self.peek_counter(con, int(user_row["id"]), action)
            if used >= quota:
                return f"Daily limit reached for this action (trust level {ctx['level']}: {quota}/day). Try again tomorrow."
        self.bump_counter(con, int(user_row["id"]), action)
        return None

    # ---- users ----
    def _reg_count_last_hour(self, con: sqlite3.Connection) -> int:
        since = int(time.time()) - 3600
        row = con.execute("SELECT COUNT(*) AS c FROM users WHERE created_at >= ?", (since,)).fetchone()
        return int(row["c"]) if row is not None else 0

    def register_user(self, nickname: str, password: str, invite_code: Optional[str]) -> tuple[bool, str, dict[str, Any]]:
        """Create an account subject to registration mode, invite policy, global
        rate cap and the approval lock. Returns (ok, message, info)."""
        now = int(time.time())
        mode = self.registration_mode()
        with self.lock, self.conn() as con:
            if con.execute("SELECT 1 FROM users WHERE nickname = ?", (nickname,)).fetchone():
                return False, "Nickname already exists.", {}

            invite_row = None
            if invite_code:
                code_hash = hashlib.sha256(invite_code.encode("utf-8")).hexdigest()
                invite_row = con.execute("SELECT * FROM invites WHERE code_hash = ?", (code_hash,)).fetchone()
                if invite_row is None or bool(invite_row["revoked"]) or invite_row["used_by"] is not None:
                    return False, "Invite code is invalid, already used, or revoked.", {}
                if int(now) - int(invite_row["created_at"]) > INVITE_TTL_SECONDS:
                    return False, "Invite code has expired.", {}
                issuer = con.execute("SELECT is_banned FROM users WHERE id = ?", (invite_row["issuer_id"],)).fetchone()
                if issuer is not None and bool(issuer["is_banned"]):
                    return False, "Invite code is no longer valid.", {}

            if mode == REG_MODE_CLOSED and invite_row is None:
                return False, "Registration is closed. An invite code is required.", {}
            if mode == REG_MODE_INVITE and invite_row is None:
                return False, "Registration is invite-only. Provide a valid invite code.", {}

            # Global rate cap: excess registrations are forced into the approval
            # queue rather than rejected outright.
            over_rate = self._reg_count_last_hour(con) >= REGISTRATION_GLOBAL_MAX_PER_HOUR
            pending = self.approval_required() or over_rate
            status = "pending" if pending else "active"
            invited_by = int(invite_row["issuer_id"]) if invite_row is not None and invite_row["issuer_id"] is not None else None

            cur = con.execute(
                "INSERT INTO users (nickname, password_hash, reputation, is_admin, is_banned, status, invited_by, created_at) "
                "VALUES (?, ?, 0.0, 0, 0, ?, ?, ?)",
                (nickname, pbkdf2_hash(password), status, invited_by, now),
            )
            new_id = int(cur.lastrowid)
            if invite_row is not None:
                con.execute(
                    "UPDATE invites SET used_by = ?, used_at = ? WHERE id = ?",
                    (new_id, now, int(invite_row["id"])),
                )
            # Coordinated-registration signal (report only).
            if invited_by is not None:
                recent = con.execute(
                    "SELECT COUNT(*) AS c FROM users WHERE invited_by = ? AND created_at >= ?",
                    (invited_by, now - COORD_REGISTRATION_WINDOW_SECONDS),
                ).fetchone()
                if recent is not None and int(recent["c"]) >= 3:
                    con.execute(
                        "INSERT INTO moderation_flags (user_id, nickname, kind, detail, resolved, created_at) "
                        "VALUES (?, ?, 'coordinated_registration', ?, 0, ?)",
                        (invited_by, None, f"{int(recent['c'])} invitees registered within {COORD_REGISTRATION_WINDOW_SECONDS}s", now),
                    )
            msg = (
                "Registration received. An administrator must approve your account before you can log in."
                if pending else "User created."
            )
            return True, msg, {"pending": pending, "status": status}

    def authenticate(self, nickname: str, password: str) -> tuple[Optional[sqlite3.Row], str]:
        with self.lock, self.conn() as con:
            row = con.execute(
                "SELECT id, nickname, password_hash, reputation, is_admin, is_banned, status, created_at "
                "FROM users WHERE nickname = ?",
                (nickname,),
            ).fetchone()
            if row is None:
                return None, "invalid"
            if bool(row["is_banned"]):
                return None, "banned"
            if str(row["status"]) == "pending":
                return None, "pending"
            if str(row["status"]) == "rejected":
                return None, "rejected"
            if pbkdf2_verify(password, row["password_hash"]):
                return row, "ok"
            return None, "invalid"

    def get_user(self, user_id: int) -> Optional[sqlite3.Row]:
        with self.lock, self.conn() as con:
            return con.execute(
                "SELECT id, nickname, reputation, is_admin, is_banned, status, invited_by, created_at "
                "FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()

    def get_user_by_nickname(self, nickname: str) -> Optional[sqlite3.Row]:
        with self.lock, self.conn() as con:
            return con.execute(
                "SELECT id, nickname, reputation, is_admin, is_banned, status, invited_by, created_at "
                "FROM users WHERE nickname = ?",
                (nickname,),
            ).fetchone()

    def reputation_of(self, nickname: str) -> Optional[float]:
        row = self.get_user_by_nickname(nickname)
        return float(row["reputation"]) if row is not None else None

    # ---- admin: pending / approval ----
    def list_pending(self) -> list[dict[str, Any]]:
        with self.lock, self.conn() as con:
            rows = con.execute(
                "SELECT u.id, u.nickname, u.created_at, u.invited_by, i.nickname AS inviter "
                "FROM users u LEFT JOIN users i ON i.id = u.invited_by "
                "WHERE u.status = 'pending' ORDER BY u.created_at ASC",
            ).fetchall()
            return [
                {
                    "id": int(r["id"]),
                    "nickname": str(r["nickname"]),
                    "created_at": int(r["created_at"]),
                    "invited_by": r["inviter"],
                }
                for r in rows
            ]

    def set_user_status(self, actor_id: int, nickname: str, new_status: str) -> tuple[bool, str, Optional[int]]:
        if new_status not in {"active", "rejected"}:
            return False, "Invalid status.", None
        with self.lock, self.conn() as con:
            actor = con.execute("SELECT is_admin FROM users WHERE id = ?", (actor_id,)).fetchone()
            if actor is None or not bool(actor["is_admin"]):
                return False, "Not allowed.", None
            target = con.execute("SELECT id, status FROM users WHERE nickname = ?", (nickname,)).fetchone()
            if target is None:
                return False, "User not found.", None
            if str(target["status"]) != "pending":
                return False, "User is not awaiting approval.", int(target["id"])
            con.execute("UPDATE users SET status = ? WHERE id = ?", (new_status, int(target["id"])))
            verb = "approved" if new_status == "active" else "rejected"
            return True, f"User {verb}.", int(target["id"])

    # ---- invites ----
    def create_invite(self, issuer_id: int) -> tuple[bool, str, Optional[str]]:
        now = int(time.time())
        with self.lock, self.conn() as con:
            issuer = con.execute("SELECT * FROM users WHERE id = ?", (issuer_id,)).fetchone()
            if issuer is None or bool(issuer["is_banned"]) or str(issuer["status"]) != "active":
                return False, "Not allowed.", None
            ctx = self.trust_context(con, issuer)
            if not ctx["is_admin"] and ctx["level"] < INVITE_MIN_TRUST_LEVEL:
                return False, f"You need trust level {INVITE_MIN_TRUST_LEVEL} to issue invites.", None
            outstanding = con.execute(
                "SELECT COUNT(*) AS c FROM invites WHERE issuer_id = ? AND used_by IS NULL AND revoked = 0",
                (issuer_id,),
            ).fetchone()
            if not ctx["is_admin"] and int(outstanding["c"]) >= INVITE_MAX_OUTSTANDING:
                return False, f"You already have {INVITE_MAX_OUTSTANDING} unused invites outstanding.", None
            code = secrets.token_urlsafe(18)
            code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
            con.execute(
                "INSERT INTO invites (code_hash, issuer_id, revoked, created_at) VALUES (?, ?, 0, ?)",
                (code_hash, issuer_id, now),
            )
            return True, "Invite created. Store it securely — it is shown only once.", code

    def list_invites(self, issuer_id: int) -> list[dict[str, Any]]:
        with self.lock, self.conn() as con:
            rows = con.execute(
                "SELECT i.id, i.revoked, i.created_at, i.used_at, u.nickname AS used_by_nick "
                "FROM invites i LEFT JOIN users u ON u.id = i.used_by "
                "WHERE i.issuer_id = ? ORDER BY i.created_at DESC",
                (issuer_id,),
            ).fetchall()
            out = []
            for r in rows:
                if bool(r["revoked"]):
                    state = "revoked"
                elif r["used_by_nick"] is not None:
                    state = f"used by {r['used_by_nick']}"
                elif int(time.time()) - int(r["created_at"]) > INVITE_TTL_SECONDS:
                    state = "expired"
                else:
                    state = "unused"
                out.append({"id": int(r["id"]), "state": state, "created_at": int(r["created_at"])})
            return out

    def revoke_invite(self, issuer_id: int, invite_id: int, is_admin: bool) -> tuple[bool, str]:
        with self.lock, self.conn() as con:
            if is_admin:
                row = con.execute("SELECT id, used_by FROM invites WHERE id = ?", (invite_id,)).fetchone()
            else:
                row = con.execute("SELECT id, used_by FROM invites WHERE id = ? AND issuer_id = ?", (invite_id, issuer_id)).fetchone()
            if row is None:
                return False, "Invite not found."
            if row["used_by"] is not None:
                return False, "Invite has already been used."
            con.execute("UPDATE invites SET revoked = 1 WHERE id = ?", (invite_id,))
            return True, "Invite revoked."

    def _penalize_inviter_on_ban(self, con: sqlite3.Connection, banned_id: int) -> None:
        row = con.execute("SELECT invited_by FROM users WHERE id = ?", (banned_id,)).fetchone()
        if row is None or row["invited_by"] is None:
            return
        inviter_id = int(row["invited_by"])
        inviter = con.execute("SELECT is_admin FROM users WHERE id = ?", (inviter_id,)).fetchone()
        if inviter is not None and bool(inviter["is_admin"]):
            return
        con.execute("UPDATE users SET reputation = reputation - ? WHERE id = ?", (INVITE_BAN_PENALTY, inviter_id))
        con.execute("UPDATE invites SET revoked = 1 WHERE issuer_id = ? AND used_by IS NULL AND revoked = 0", (inviter_id,))

    def block_exists(self, con: sqlite3.Connection, user_a: int, user_b: int) -> bool:
        return con.execute(
            "SELECT 1 FROM user_blocks WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?) LIMIT 1",
            (user_a, user_b, user_b, user_a),
        ).fetchone() is not None

    def are_blocked(self, user_a: int, user_b: int) -> bool:
        with self.lock, self.conn() as con:
            return self.block_exists(con, user_a, user_b)

    # ---- jobs ----
    def create_job(self, author_row: sqlite3.Row, title: str, description: str, reward: int,
                   min_reputation: int, is_private: bool) -> tuple[bool, str, dict[str, Any]]:
        now = int(time.time())
        private_token = secrets.token_urlsafe(16) if is_private else ""
        password_hash = pbkdf2_hash(private_token) if is_private else None
        with self.lock, self.conn() as con:
            author_id = int(author_row["id"])
            quota_err = self.enforce_write_quota(con, author_row, "create_job")
            if quota_err:
                return False, quota_err, {}
            author = con.execute("SELECT reputation FROM users WHERE id = ?", (author_id,)).fetchone()
            author_reputation = float(author["reputation"]) if author is not None else 0.0
            effective_min_reputation = min(int(min_reputation), int(math.floor(author_reputation)))
            cur = con.execute(
                """
                INSERT INTO jobs (
                    author_id, title_enc, description_enc, reward, min_reputation, is_private,
                    description_password_hash, status, selected_worker_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'open', NULL, ?, ?)
                """,
                (
                    author_id,
                    get_crypto().enc(title),
                    get_crypto().enc(description),
                    reward,
                    effective_min_reputation,
                    1 if is_private else 0,
                    password_hash,
                    now,
                    now,
                ),
            )
            return True, "Job created.", {"job_id": cur.lastrowid, "private_token": private_token}

    def list_jobs(self, viewer_id: Optional[int], status: Optional[str] = None,
                  page: int = 1, per_page: int = PAGE_SIZE) -> tuple[list[dict[str, Any]], int, int]:
        with self.lock, self.conn() as con:
            params: list[Any] = []
            clauses: list[str] = []
            if status:
                clauses.append("j.status = ?")
                params.append(status)
            if viewer_id is not None:
                clauses.append(
                    "NOT EXISTS (SELECT 1 FROM user_blocks b WHERE (b.blocker_id = ? AND b.blocked_id = j.author_id) OR (b.blocker_id = j.author_id AND b.blocked_id = ?))"
                )
                params.extend([viewer_id, viewer_id])
            from_where = "FROM jobs j JOIN users u ON u.id = j.author_id "
            if clauses:
                from_where += "WHERE " + " AND ".join(clauses) + " "
            total = int(con.execute("SELECT COUNT(*) " + from_where, params).fetchone()[0])
            total_pages = max(1, (total + per_page - 1) // per_page)
            page = min(max(1, page), total_pages)
            offset = (page - 1) * per_page
            select = (
                "SELECT j.*, u.nickname AS author_nickname, u.is_banned AS author_is_banned, "
                "(SELECT COUNT(*) FROM job_accepts a WHERE a.job_id = j.id) AS accept_count "
                + from_where + "ORDER BY j.created_at DESC, j.id DESC LIMIT ? OFFSET ?"
            )
            rows = con.execute(select, params + [per_page, offset]).fetchall()
            viewer = self.get_user(viewer_id) if viewer_id else None
            items = [self._job_row_to_public_dict(row, viewer) for row in rows]
            return items, total, page

    def my_authored_jobs(self, user_id: int) -> list[dict[str, Any]]:
        with self.lock, self.conn() as con:
            rows = con.execute(
                "SELECT j.*, (SELECT COUNT(*) FROM job_accepts a WHERE a.job_id = j.id) AS accept_count FROM jobs j WHERE author_id = ? ORDER BY created_at DESC",
                (user_id,),
            ).fetchall()
            viewer = self.get_user(user_id)
            return [self._job_row_to_author_dict(row, viewer) for row in rows]

    def my_accepted_jobs(self, user_id: int) -> list[dict[str, Any]]:
        with self.lock, self.conn() as con:
            rows = con.execute(
                """
                SELECT j.*, u.nickname AS author_nickname, u.is_banned AS author_is_banned,
                       (SELECT COUNT(*) FROM job_accepts a WHERE a.job_id = j.id) AS accept_count
                FROM jobs j
                JOIN job_accepts ja ON ja.job_id = j.id
                JOIN users u ON u.id = j.author_id
                WHERE ja.user_id = ?
                ORDER BY j.created_at DESC
                """,
                (user_id,),
            ).fetchall()
            viewer = self.get_user(user_id)
            items: list[dict[str, Any]] = []
            for row in rows:
                item = self._job_row_to_public_dict(row, viewer)
                item["description"] = None
                items.append(item)
            return items

    def get_job(self, job_id: int) -> Optional[sqlite3.Row]:
        with self.lock, self.conn() as con:
            return con.execute(
                "SELECT j.*, u.nickname AS author_nickname, u.is_banned AS author_is_banned FROM jobs j JOIN users u ON u.id = j.author_id WHERE j.id = ?",
                (job_id,),
            ).fetchone()

    def get_job_for_viewer(self, job_id: int, viewer_id: Optional[int], unlock_token: Optional[str]) -> tuple[bool, str, Optional[dict[str, Any]]]:
        row = self.get_job(job_id)
        if row is None:
            return False, "Job not found.", None
        viewer = self.get_user(viewer_id) if viewer_id else None
        is_admin = bool(viewer and viewer["is_admin"])
        is_author = bool(viewer_id and row["author_id"] == viewer_id)
        if viewer_id is not None and not is_author and not is_admin and self.are_blocked(viewer_id, int(row["author_id"])):
            return False, "Job not found.", None
        data = self._job_row_to_public_dict(row, viewer)
        can_view_description = False
        if not row["is_private"]:
            can_view_description = True
        elif is_admin or is_author:
            can_view_description = True
        elif unlock_token and row["description_password_hash"] and pbkdf2_verify(unlock_token, row["description_password_hash"]):
            can_view_description = True
        data["description_visible"] = can_view_description
        data["description"] = get_crypto().dec(row["description_enc"]) if can_view_description else None
        with self.lock, self.conn() as con:
            accepted = con.execute(
                "SELECT 1 FROM job_accepts WHERE job_id = ? AND user_id = ?",
                (job_id, viewer_id or -1),
            ).fetchone() is not None
            data["viewer_has_accepted"] = accepted
            if is_author or is_admin:
                workers = con.execute(
                    "SELECT u.id, u.nickname, u.reputation, u.is_banned FROM job_accepts a JOIN users u ON u.id = a.user_id WHERE a.job_id = ? ORDER BY a.created_at ASC",
                    (job_id,),
                ).fetchall()
                data["worker_pool"] = [
                    {
                        "id": int(w["id"]),
                        "nickname": str(w["nickname"]),
                        "reputation": round(float(w["reputation"]), 3),
                        "is_banned": bool(w["is_banned"]),
                    }
                    for w in workers
                ]
            else:
                data["worker_pool"] = None
        data["is_author"] = is_author
        data["is_admin"] = is_admin
        data["selected_worker_id"] = row["selected_worker_id"]
        return True, "OK", data

    def accept_job(self, job_id: int, user_id: int, private_token: Optional[str]) -> tuple[bool, str]:
        with self.lock, self.conn() as con:
            row = con.execute(
                "SELECT author_id, status, min_reputation, is_private, description_password_hash FROM jobs WHERE id = ?",
                (job_id,),
            ).fetchone()
            user = con.execute("SELECT reputation, is_banned FROM users WHERE id = ?", (user_id,)).fetchone()
            if row is None or user is None:
                return False, "Job not found."
            if bool(user["is_banned"]):
                return False, "Not allowed."
            if row["status"] != "open":
                return False, "Job is not open."
            if row["author_id"] == user_id:
                return False, "Author cannot accept own job."
            if self.block_exists(con, user_id, int(row["author_id"])):
                return False, "Not allowed."
            if float(user["reputation"]) < float(row["min_reputation"]):
                return False, "Not enough reputation."
            if bool(row["is_private"]):
                if not private_token or not row["description_password_hash"] or not pbkdf2_verify(private_token, str(row["description_password_hash"])):
                    return False, "Invalid private token."
            try:
                con.execute(
                    "INSERT INTO job_accepts (job_id, user_id, created_at) VALUES (?, ?, ?)",
                    (job_id, user_id, int(time.time())),
                )
            except sqlite3.IntegrityError:
                return False, "You already accepted this job."
            chat_id = self.ensure_chat_between_users(con, int(row["author_id"]), user_id)
            author = con.execute("SELECT nickname FROM users WHERE id = ?", (int(row["author_id"]),)).fetchone()
            worker = con.execute("SELECT nickname FROM users WHERE id = ?", (user_id,)).fetchone()
            title_row = con.execute("SELECT title_enc FROM jobs WHERE id = ?", (job_id,)).fetchone()
            title = get_crypto().dec(title_row["title_enc"]) if title_row is not None else ""
            if worker is not None and author is not None:
                self.insert_system_message(con, chat_id, f"{worker['nickname']} accepted your job {title}")
            return True, "Job accepted."

    def withdraw_accept(self, job_id: int, user_id: int) -> tuple[bool, str]:
        with self.lock, self.conn() as con:
            row = con.execute("SELECT status, selected_worker_id FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if row is None:
                return False, "Job not found."
            if row["status"] != "open":
                return False, "Cannot withdraw from a closed job."
            if row["selected_worker_id"] == user_id:
                return False, "Selected worker cannot withdraw unless the author changes selection first."
            cur = con.execute("DELETE FROM job_accepts WHERE job_id = ? AND user_id = ?", (job_id, user_id))
            if cur.rowcount == 0:
                return False, "You had not accepted this job."
            return True, "Acceptance withdrawn."

    def set_selected_worker(self, job_id: int, actor_id: int, worker_id: int) -> tuple[bool, str]:
        with self.lock, self.conn() as con:
            job = con.execute("SELECT author_id, status FROM jobs WHERE id = ?", (job_id,)).fetchone()
            actor = con.execute("SELECT is_admin FROM users WHERE id = ?", (actor_id,)).fetchone()
            if job is None or actor is None:
                return False, "Job or actor not found."
            if job["status"] != "open":
                return False, "Cannot select a worker for a closed job."
            if actor_id != job["author_id"] and not bool(actor["is_admin"]):
                return False, "Not allowed."
            accepted = con.execute(
                "SELECT 1 FROM job_accepts WHERE job_id = ? AND user_id = ?",
                (job_id, worker_id),
            ).fetchone()
            if accepted is None:
                return False, "Worker is not in the pool."
            banned_worker = con.execute("SELECT is_banned FROM users WHERE id = ?", (worker_id,)).fetchone()
            if banned_worker is None or bool(banned_worker["is_banned"]):
                return False, "Worker is banned."
            if self.block_exists(con, int(job["author_id"]), worker_id):
                return False, "Not allowed."
            con.execute(
                "UPDATE jobs SET selected_worker_id = ?, updated_at = ? WHERE id = ?",
                (worker_id, int(time.time()), job_id),
            )
            return True, "Selected worker updated."

    def _grant_completion_reputation(self, con: sqlite3.Connection, job_id: int, author_id: int, worker_id: int) -> float:
        """Anti-farm reputation grant. See module docstring. Returns rep gained."""
        now = int(time.time())
        author = con.execute("SELECT reputation FROM users WHERE id = ?", (author_id,)).fetchone()
        worker = con.execute("SELECT reputation, is_admin, created_at FROM users WHERE id = ?", (worker_id,)).fetchone()
        if author is None or worker is None:
            return 0.0
        author_rep = float(author["reputation"])
        worker_rep = float(worker["reputation"])
        aw = author_grant_weight(author_rep)
        if aw <= 0:
            self._record_completion(con, job_id, author_id, worker_id, 0.0, now)
            return 0.0
        # Per-employer daily granting cap.
        granted_today = con.execute(
            "SELECT COALESCE(SUM(rep_gain), 0) AS s FROM job_completions WHERE author_id = ? AND created_at >= ?",
            (author_id, now - 86400),
        ).fetchone()
        if float(granted_today["s"]) >= AUTHOR_GRANT_DAILY_CAP:
            self._record_completion(con, job_id, author_id, worker_id, 0.0, now)
            return 0.0
        # Worker's rep-earning completions today (diminishing returns + hard cap).
        w_age = max(0, now - int(worker["created_at"]))
        w_partners = self.distinct_job_partners(con, worker_id)
        w_level = trust_level(worker_rep, w_age, w_partners, bool(worker["is_admin"]))
        n_today_row = con.execute(
            "SELECT COUNT(*) AS c FROM job_completions WHERE worker_id = ? AND rep_gain > 0 AND created_at >= ?",
            (worker_id, now - 86400),
        ).fetchone()
        n_today = int(n_today_row["c"]) if n_today_row is not None else 0
        if n_today >= daily_job_cap(worker_rep, w_level):
            self._record_completion(con, job_id, author_id, worker_id, 0.0, now)
            return 0.0
        pair_row = con.execute(
            "SELECT COUNT(*) AS c FROM job_completions WHERE author_id = ? AND worker_id = ? AND rep_gain > 0",
            (author_id, worker_id),
        ).fetchone()
        pair_n = int(pair_row["c"]) if pair_row is not None else 0
        gain = BASE_JOB_REP * aw * (JOB_DAILY_DECAY ** n_today) * (JOB_PAIR_DECAY ** pair_n)
        # Do not exceed the employer's remaining daily budget.
        gain = min(gain, AUTHOR_GRANT_DAILY_CAP - float(granted_today["s"]))
        gain = round(max(0.0, gain), 4)
        self._record_completion(con, job_id, author_id, worker_id, gain, now)
        if gain > 0:
            con.execute("UPDATE users SET reputation = reputation + ? WHERE id = ?", (gain, worker_id))
        return gain

    def _record_completion(self, con: sqlite3.Connection, job_id: int, author_id: int, worker_id: int, gain: float, now: int) -> None:
        con.execute(
            "INSERT OR IGNORE INTO job_completions (job_id, author_id, worker_id, rep_gain, created_at) VALUES (?, ?, ?, ?, ?)",
            (job_id, author_id, worker_id, gain, now),
        )

    def set_job_status(self, job_id: int, actor_id: int, new_status: str) -> tuple[bool, str]:
        if new_status not in {"done", "cancelled", "open"}:
            return False, "Invalid status."
        with self.lock, self.conn() as con:
            job = con.execute(
                "SELECT author_id, status, selected_worker_id FROM jobs WHERE id = ?",
                (job_id,),
            ).fetchone()
            actor = con.execute("SELECT is_admin FROM users WHERE id = ?", (actor_id,)).fetchone()
            if job is None or actor is None:
                return False, "Job or actor not found."
            if actor_id != job["author_id"] and not bool(actor["is_admin"]):
                return False, "Not allowed."
            if new_status == "done" and not job["selected_worker_id"]:
                return False, "Select a worker before marking as done."
            if job["status"] == "done" and new_status != "done":
                return False, "Done jobs cannot be reopened or cancelled."
            con.execute(
                "UPDATE jobs SET status = ?, updated_at = ? WHERE id = ?",
                (new_status, int(time.time()), job_id),
            )
            if job["status"] != "done" and new_status == "done":
                gain = self._grant_completion_reputation(con, job_id, int(job["author_id"]), int(job["selected_worker_id"]))
                return True, f"Job status set to done. Worker earned {gain:.3f} reputation."
            return True, f"Job status set to {new_status}."

    def _job_row_to_public_dict(self, row: sqlite3.Row, viewer: Optional[sqlite3.Row]) -> dict[str, Any]:
        author_is_banned = bool(row["author_is_banned"]) if "author_is_banned" in row.keys() else False
        author_nickname = str(row["author_nickname"])
        author_display = f"{BAN_LABEL} {author_nickname}" if author_is_banned else author_nickname
        viewer_rep = round(float(viewer["reputation"]), 3) if viewer is not None else None
        min_rep = int(row["min_reputation"]) if "min_reputation" in row.keys() else 0
        insufficient = viewer_rep is not None and viewer_rep < min_rep and viewer is not None and int(viewer["id"]) != int(row["author_id"])
        return {
            "id": int(row["id"]),
            "title": get_crypto().dec(row["title_enc"]),
            "reward": int(row["reward"]),
            "min_reputation": min_rep,
            "is_private": bool(row["is_private"]),
            "status": str(row["status"]),
            "author_id": int(row["author_id"]),
            "author_nickname": author_nickname,
            "author_is_banned": author_is_banned,
            "author_display": author_display,
            "accept_count": int(row["accept_count"]) if "accept_count" in row.keys() else 0,
            "created_at": int(row["created_at"]),
            "updated_at": int(row["updated_at"]),
            "viewer_reputation": viewer_rep,
            "not_enough_reputation": insufficient,
        }

    def _job_row_to_author_dict(self, row: sqlite3.Row, viewer: Optional[sqlite3.Row]) -> dict[str, Any]:
        return {
            "id": int(row["id"]),
            "title": get_crypto().dec(row["title_enc"]),
            "reward": int(row["reward"]),
            "min_reputation": int(row["min_reputation"]),
            "is_private": bool(row["is_private"]),
            "status": str(row["status"]),
            "accept_count": int(row["accept_count"]) if "accept_count" in row.keys() else 0,
            "selected_worker_id": row["selected_worker_id"],
            "created_at": int(row["created_at"]),
            "updated_at": int(row["updated_at"]),
            "viewer_reputation": round(float(viewer["reputation"]), 3) if viewer is not None else None,
            "not_enough_reputation": False,
        }

    def ban_user(self, actor_id: int, nickname: str) -> tuple[bool, str, Optional[int]]:
        with self.lock, self.conn() as con:
            actor = con.execute("SELECT id, is_admin, nickname FROM users WHERE id = ?", (actor_id,)).fetchone()
            if actor is None or not bool(actor["is_admin"]):
                return False, "Not allowed.", None
            target = con.execute("SELECT id, nickname, is_admin, is_banned FROM users WHERE nickname = ?", (nickname,)).fetchone()
            if target is None:
                return False, "User not found.", None
            if bool(target["is_admin"]):
                return False, "Admin accounts cannot be banned.", None
            if bool(target["is_banned"]):
                return False, "User is already banned.", int(target["id"])
            con.execute("UPDATE users SET is_banned = 1 WHERE id = ?", (target["id"],))
            con.execute("DELETE FROM job_accepts WHERE user_id = ?", (target["id"],))
            con.execute("UPDATE jobs SET selected_worker_id = NULL, updated_at = ? WHERE selected_worker_id = ? AND status = 'open'", (int(time.time()), target["id"]))
            self._penalize_inviter_on_ban(con, int(target["id"]))
            return True, "User banned permanently.", int(target["id"])

    def wipe_user(self, actor_id: int, nickname: str) -> tuple[bool, str, Optional[int]]:
        now = int(time.time())
        with self.lock, self.conn() as con:
            actor = con.execute("SELECT id, is_admin FROM users WHERE id = ?", (actor_id,)).fetchone()
            if actor is None or not bool(actor["is_admin"]):
                return False, "Not allowed.", None
            target = con.execute("SELECT id, nickname, is_admin FROM users WHERE nickname = ?", (nickname,)).fetchone()
            if target is None:
                return False, "User not found.", None
            if bool(target["is_admin"]):
                return False, "Admin accounts cannot be wiped.", None
            tid = int(target["id"])
            con.execute("UPDATE users SET is_banned = 1 WHERE id = ?", (tid,))
            con.execute("DELETE FROM job_accepts WHERE user_id = ?", (tid,))
            con.execute("UPDATE jobs SET selected_worker_id = NULL, updated_at = ? WHERE selected_worker_id = ? AND status = 'open'", (now, tid))
            jobs_deleted = con.execute("DELETE FROM jobs WHERE author_id = ?", (tid,)).rowcount
            threads_deleted = con.execute("DELETE FROM threads WHERE author_id = ?", (tid,)).rowcount
            comments_deleted = con.execute("DELETE FROM thread_posts WHERE author_id = ?", (tid,)).rowcount
            self._penalize_inviter_on_ban(con, tid)
            detail = f"jobs={jobs_deleted} threads={threads_deleted} comments={comments_deleted}"
            return True, f"User wiped and banned. Removed {detail}.", tid

    def count_recent_negative_ratings(self, con: sqlite3.Connection, target_id: int, since_ts: int) -> int:
        row = con.execute(
            "SELECT COUNT(*) AS c FROM reputation_ratings "
            "WHERE target_id = ? AND rating_value < 0 AND frozen = 0 AND last_changed_at >= ?",
            (target_id, since_ts),
        ).fetchone()
        return int(row["c"]) if row is not None else 0

    def delete_job(self, actor_id: int, job_id: int) -> tuple[bool, str]:
        with self.lock, self.conn() as con:
            actor = con.execute("SELECT id, is_admin FROM users WHERE id = ?", (actor_id,)).fetchone()
            if actor is None or not bool(actor["is_admin"]):
                return False, "Not allowed."
            cur = con.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
            if cur.rowcount == 0:
                return False, "Job not found."
            return True, "Job deleted."

    # ---- ratings ----
    def rate_user_for_job(self, rater_id: int, target_nickname: str, choice: str, job_id: int) -> tuple[bool, str, Optional[int], bool]:
        """Rate a counterparty of a completed job. Returns (ok, msg, target_id, frozen)."""
        rating_value = RATING_CHOICES[choice]
        now = int(time.time())
        with self.lock, self.conn() as con:
            rater = con.execute("SELECT id, is_banned, reputation FROM users WHERE id = ?", (rater_id,)).fetchone()
            target = con.execute("SELECT id, nickname, is_admin, is_banned FROM users WHERE nickname = ?", (target_nickname,)).fetchone()
            if rater is None or bool(rater["is_banned"]):
                return False, "Not allowed.", None, False
            if target is None or bool(target["is_banned"]):
                return False, "Operation not allowed.", None, False
            target_id = int(target["id"])
            if target_id == rater_id:
                return False, "You cannot rate yourself.", None, False
            if self.block_exists(con, rater_id, target_id):
                return False, "Operation not allowed.", target_id, False
            job = con.execute(
                "SELECT j.author_id, j.selected_worker_id, j.status FROM jobs j WHERE j.id = ?",
                (job_id,),
            ).fetchone()
            if job is None:
                return False, "Job not found.", target_id, False
            if str(job["status"]) != "done":
                return False, "You can only rate after the job is completed.", target_id, False
            author_id = int(job["author_id"])
            worker_id = int(job["selected_worker_id"]) if job["selected_worker_id"] is not None else -1
            pair = {author_id, worker_id}
            if rater_id not in pair or target_id not in pair or rater_id == target_id:
                return False, "You can only rate the other party of a job you completed together.", target_id, False
            existing = con.execute(
                "SELECT 1 FROM reputation_ratings WHERE rater_id = ? AND target_id = ? AND job_id = ?",
                (rater_id, target_id, job_id),
            ).fetchone()
            if existing is not None:
                return False, "You already rated this user for this job.", target_id, False

            weight = rating_weight(float(rater["reputation"]))
            applied = round(rating_value * weight, 4)

            # Brigade check BEFORE applying: if this negative rating would exceed
            # the burst threshold, freeze it (withhold its effect) for review.
            frozen = 0
            if rating_value < 0:
                since = now - NEGATIVE_RATING_BURST_WINDOW_SECONDS
                recent = self.count_recent_negative_ratings(con, target_id, since)
                if recent >= NEGATIVE_RATING_BURST_LIMIT:
                    frozen = 1

            con.execute(
                "INSERT INTO reputation_ratings (rater_id, target_id, job_id, rating_value, applied_delta, frozen, last_changed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (rater_id, target_id, job_id, rating_value, applied if not frozen else 0.0, frozen, now),
            )
            if not frozen:
                con.execute("UPDATE users SET reputation = reputation + ? WHERE id = ?", (applied, target_id))
            if frozen:
                con.execute(
                    "INSERT INTO moderation_flags (user_id, nickname, kind, detail, resolved, created_at) "
                    "VALUES (?, ?, 'rating_brigade', ?, 0, ?)",
                    (target_id, str(target["nickname"]), f"negative-rating burst on target; rating frozen (job {job_id})", now),
                )
            msg = "Rating recorded (held for review due to a rating burst)." if frozen else f"Rating set to {choice} (weight {weight:.2f})."
            return True, msg, target_id, bool(frozen)

    def admin_adjust_reputation(self, actor_id: int, nickname: str, delta: float) -> tuple[bool, str, Optional[int]]:
        with self.lock, self.conn() as con:
            actor = con.execute("SELECT is_admin FROM users WHERE id = ?", (actor_id,)).fetchone()
            if actor is None or not bool(actor["is_admin"]):
                return False, "Not allowed.", None
            target = con.execute("SELECT id FROM users WHERE nickname = ?", (nickname,)).fetchone()
            if target is None:
                return False, "User not found.", None
            con.execute("UPDATE users SET reputation = reputation + ? WHERE id = ?", (round(delta, 4), int(target["id"])))
            return True, f"Adjusted reputation of {nickname} by {delta:+.3f}.", int(target["id"])

    def list_frozen_ratings(self) -> list[dict[str, Any]]:
        with self.lock, self.conn() as con:
            rows = con.execute(
                "SELECT r.rowid AS rid, r.rater_id, r.target_id, r.job_id, r.rating_value, r.last_changed_at, "
                "ur.nickname AS rater_nick, ut.nickname AS target_nick "
                "FROM reputation_ratings r "
                "JOIN users ur ON ur.id = r.rater_id JOIN users ut ON ut.id = r.target_id "
                "WHERE r.frozen = 1 ORDER BY r.last_changed_at DESC LIMIT 200",
            ).fetchall()
            return [
                {
                    "rater": str(r["rater_nick"]),
                    "target": str(r["target_nick"]),
                    "rater_id": int(r["rater_id"]),
                    "target_id": int(r["target_id"]),
                    "job_id": int(r["job_id"]),
                    "rating_value": int(r["rating_value"]),
                    "created_at": int(r["last_changed_at"]),
                }
                for r in rows
            ]

    def resolve_frozen_rating(self, actor_id: int, rater_id: int, target_id: int, job_id: int, apply: bool) -> tuple[bool, str]:
        with self.lock, self.conn() as con:
            actor = con.execute("SELECT is_admin FROM users WHERE id = ?", (actor_id,)).fetchone()
            if actor is None or not bool(actor["is_admin"]):
                return False, "Not allowed."
            row = con.execute(
                "SELECT rating_value, frozen FROM reputation_ratings WHERE rater_id = ? AND target_id = ? AND job_id = ?",
                (rater_id, target_id, job_id),
            ).fetchone()
            if row is None or not bool(row["frozen"]):
                return False, "Frozen rating not found."
            if apply:
                rater = con.execute("SELECT reputation FROM users WHERE id = ?", (rater_id,)).fetchone()
                weight = rating_weight(float(rater["reputation"])) if rater is not None else RATING_WEIGHT_MIN
                applied = round(int(row["rating_value"]) * weight, 4)
                con.execute(
                    "UPDATE reputation_ratings SET frozen = 0, applied_delta = ? WHERE rater_id = ? AND target_id = ? AND job_id = ?",
                    (applied, rater_id, target_id, job_id),
                )
                con.execute("UPDATE users SET reputation = reputation + ? WHERE id = ?", (applied, target_id))
                return True, "Frozen rating applied."
            con.execute(
                "DELETE FROM reputation_ratings WHERE rater_id = ? AND target_id = ? AND job_id = ?",
                (rater_id, target_id, job_id),
            )
            return True, "Frozen rating discarded."

    def set_block(self, blocker_id: int, target_nickname: str, should_block: bool) -> tuple[bool, str, Optional[int]]:
        now = int(time.time())
        with self.lock, self.conn() as con:
            blocker = con.execute("SELECT id, is_banned FROM users WHERE id = ?", (blocker_id,)).fetchone()
            target = con.execute("SELECT id, nickname, is_admin, is_banned FROM users WHERE nickname = ?", (target_nickname,)).fetchone()
            if blocker is None or bool(blocker["is_banned"]):
                return False, "Not allowed.", None
            if target is None:
                return False, "Operation not allowed.", None
            if int(target["id"]) == blocker_id:
                return False, "You cannot block yourself.", None
            if bool(target["is_admin"]):
                return False, "Admins cannot be blocked.", int(target["id"])
            if should_block:
                try:
                    con.execute(
                        "INSERT INTO user_blocks (blocker_id, blocked_id, created_at) VALUES (?, ?, ?)",
                        (blocker_id, int(target["id"]), now),
                    )
                except sqlite3.IntegrityError:
                    return False, "User is already blocked.", int(target["id"])
                return True, "User blocked.", int(target["id"])
            cur = con.execute("DELETE FROM user_blocks WHERE blocker_id = ? AND blocked_id = ?", (blocker_id, int(target["id"])))
            if cur.rowcount == 0:
                return False, "User was not blocked.", int(target["id"])
            return True, "User unblocked.", int(target["id"])

    def list_blocks(self, user_id: int) -> list[dict[str, Any]]:
        with self.lock, self.conn() as con:
            rows = con.execute(
                "SELECT u.id, u.nickname, u.reputation, u.is_banned, b.created_at FROM user_blocks b JOIN users u ON u.id = b.blocked_id WHERE b.blocker_id = ? ORDER BY u.nickname ASC",
                (user_id,),
            ).fetchall()
            return [
                {
                    "id": int(row["id"]),
                    "nickname": str(row["nickname"]),
                    "reputation": round(float(row["reputation"]), 3),
                    "is_banned": bool(row["is_banned"]),
                    "created_at": int(row["created_at"]),
                }
                for row in rows
            ]

    # ---- chat ----
    def ensure_chat_between_users(self, con: sqlite3.Connection, user_a: int, user_b: int) -> int:
        low, high = sorted((int(user_a), int(user_b)))
        row = con.execute(
            "SELECT id FROM chats WHERE user_low_id = ? AND user_high_id = ?",
            (low, high),
        ).fetchone()
        now = int(time.time())
        if row is not None:
            con.execute("UPDATE chats SET updated_at = ? WHERE id = ?", (now, int(row["id"])))
            return int(row["id"])
        cur = con.execute(
            "INSERT INTO chats (user_low_id, user_high_id, created_at, updated_at) VALUES (?, ?, ?, ?)",
            (low, high, now, now),
        )
        return int(cur.lastrowid)

    def insert_system_message(self, con: sqlite3.Connection, chat_id: int, text: str) -> int:
        now = int(time.time())
        cur = con.execute(
            "INSERT INTO messages (chat_id, sender_id, message_type, body_enc, created_at) VALUES (?, NULL, 'system', ?, ?)",
            (chat_id, get_crypto().enc(text), now),
        )
        con.execute("UPDATE chats SET updated_at = ? WHERE id = ?", (now, chat_id))
        return int(cur.lastrowid)

    def open_chat_by_nickname(self, actor_row: sqlite3.Row, target_nickname: str) -> tuple[bool, str, Optional[dict[str, Any]]]:
        with self.lock, self.conn() as con:
            actor_id = int(actor_row["id"])
            actor = con.execute("SELECT id, nickname, is_banned FROM users WHERE id = ?", (actor_id,)).fetchone()
            target = con.execute("SELECT id, nickname, is_admin, is_banned FROM users WHERE nickname = ?", (target_nickname,)).fetchone()
            if actor is None or bool(actor["is_banned"]):
                return False, "Operation not allowed.", None
            if target is None or bool(target["is_banned"]):
                return False, "Operation not allowed.", None
            if int(target["id"]) == actor_id:
                return False, "You cannot open a chat with yourself.", None
            if self.block_exists(con, actor_id, int(target["id"])):
                return False, "Operation not allowed.", None
            # Opening a NEW chat is quota-limited; replying to an existing one is not.
            existing_chat = con.execute(
                "SELECT id FROM chats WHERE user_low_id = ? AND user_high_id = ?",
                tuple(sorted((actor_id, int(target["id"])))),
            ).fetchone()
            if existing_chat is None:
                quota_err = self.enforce_write_quota(con, actor_row, "open_chat")
                if quota_err:
                    return False, quota_err, None
            chat_id = self.ensure_chat_between_users(con, actor_id, int(target["id"]))
            row = con.execute("SELECT COUNT(*) AS count FROM messages WHERE chat_id = ?", (chat_id,)).fetchone()
            if row is not None and int(row["count"]) == 0:
                self.insert_system_message(con, chat_id, f"{actor['nickname']} started a conversation with you")
            return True, "Chat ready.", self.get_chat_summary_for_user(con, chat_id, actor_id)

    def get_chat_summary_for_user(self, con: sqlite3.Connection, chat_id: int, viewer_id: int) -> Optional[dict[str, Any]]:
        row = con.execute(
            "SELECT c.*, u1.nickname AS low_name, u2.nickname AS high_name FROM chats c JOIN users u1 ON u1.id = c.user_low_id JOIN users u2 ON u2.id = c.user_high_id WHERE c.id = ?",
            (chat_id,),
        ).fetchone()
        if row is None:
            return None
        if viewer_id not in {int(row["user_low_id"]), int(row["user_high_id"])}:
            return None
        other_id = int(row["user_high_id"]) if int(row["user_low_id"]) == viewer_id else int(row["user_low_id"])
        other_name = str(row["high_name"]) if int(row["user_low_id"]) == viewer_id else str(row["low_name"])
        last = con.execute(
            "SELECT body_enc, message_type, sender_id, created_at FROM messages WHERE chat_id = ? ORDER BY id DESC LIMIT 1",
            (chat_id,),
        ).fetchone()
        unread = con.execute(
            "SELECT COUNT(*) AS count FROM messages m LEFT JOIN message_reads r ON r.message_id = m.id AND r.user_id = ? WHERE m.chat_id = ? AND (m.sender_id IS NULL OR m.sender_id != ?) AND r.message_id IS NULL",
            (viewer_id, chat_id, viewer_id),
        ).fetchone()
        return {
            "chat_id": int(row["id"]),
            "other_user_id": other_id,
            "other_nickname": other_name,
            "created_at": int(row["created_at"]),
            "updated_at": int(row["updated_at"]),
            "last_message": get_crypto().dec(last["body_enc"]) if last is not None else "",
            "last_message_type": str(last["message_type"]) if last is not None else "",
            "last_message_at": int(last["created_at"]) if last is not None else None,
            "unread_count": int(unread["count"]) if unread is not None else 0,
        }

    def list_chats(self, user_id: int) -> list[dict[str, Any]]:
        with self.lock, self.conn() as con:
            rows = con.execute(
                "SELECT id FROM chats WHERE user_low_id = ? OR user_high_id = ? ORDER BY updated_at DESC",
                (user_id, user_id),
            ).fetchall()
            items: list[dict[str, Any]] = []
            for row in rows:
                item = self.get_chat_summary_for_user(con, int(row["id"]), user_id)
                if item is not None:
                    items.append(item)
            return items

    def get_chat_for_participant(self, con: sqlite3.Connection, chat_id: int, user_id: int) -> Optional[sqlite3.Row]:
        return con.execute(
            "SELECT * FROM chats WHERE id = ? AND (user_low_id = ? OR user_high_id = ?)",
            (chat_id, user_id, user_id),
        ).fetchone()

    def list_messages(self, user_id: int, chat_id: int) -> tuple[bool, str, Optional[dict[str, Any]]]:
        with self.lock, self.conn() as con:
            chat = self.get_chat_for_participant(con, chat_id, user_id)
            if chat is None:
                return False, "Chat not found.", None
            other_id = int(chat["user_high_id"]) if int(chat["user_low_id"]) == user_id else int(chat["user_low_id"])
            if self.block_exists(con, user_id, other_id):
                return False, "Chat not found.", None
            other = con.execute("SELECT nickname FROM users WHERE id = ?", (other_id,)).fetchone()
            rows = con.execute(
                """
                SELECT m.id, m.sender_id, m.message_type, m.body_enc, m.created_at,
                       u.nickname AS sender_nickname,
                       CASE WHEN r.message_id IS NOT NULL THEN 1 ELSE 0 END AS is_read
                FROM messages m
                LEFT JOIN users u ON u.id = m.sender_id
                LEFT JOIN message_reads r ON r.message_id = m.id AND r.user_id = ?
                WHERE m.chat_id = ?
                ORDER BY m.created_at ASC, m.id ASC
                """,
                (user_id, chat_id),
            ).fetchall()
            unread_ids: list[int] = []
            items: list[dict[str, Any]] = []
            for row in rows:
                is_read = bool(row["is_read"])
                if (row["sender_id"] is None or int(row["sender_id"]) != user_id) and not is_read:
                    unread_ids.append(int(row["id"]))
                sender_name = str(row["sender_nickname"]) if row["sender_nickname"] is not None else "system"
                items.append(
                    {
                        "id": int(row["id"]),
                        "chat_id": chat_id,
                        "sender_id": int(row["sender_id"]) if row["sender_id"] is not None else None,
                        "sender_nickname": sender_name,
                        "message_type": str(row["message_type"]),
                        "body": get_crypto().dec(row["body_enc"]),
                        "created_at": int(row["created_at"]),
                        "is_read": is_read,
                    }
                )
            now = int(time.time())
            for msg_id in unread_ids:
                con.execute(
                    "INSERT OR IGNORE INTO message_reads (message_id, user_id, read_at) VALUES (?, ?, ?)",
                    (msg_id, user_id, now),
                )
            return True, "OK", {
                "chat_id": chat_id,
                "other_nickname": str(other["nickname"]) if other is not None else "unknown",
                "messages": items,
            }

    def read_message(self, user_id: int, message_id: int) -> tuple[bool, str, Optional[dict[str, Any]]]:
        with self.lock, self.conn() as con:
            row = con.execute(
                "SELECT m.id, m.chat_id, m.sender_id, m.message_type, m.body_enc, m.created_at FROM messages m JOIN chats c ON c.id = m.chat_id WHERE m.id = ? AND (c.user_low_id = ? OR c.user_high_id = ?)",
                (message_id, user_id, user_id),
            ).fetchone()
            if row is None:
                return False, "Message not found.", None
            chat = self.get_chat_for_participant(con, int(row["chat_id"]), user_id)
            if chat is None:
                return False, "Message not found.", None
            other_id = int(chat["user_high_id"]) if int(chat["user_low_id"]) == user_id else int(chat["user_low_id"])
            if self.block_exists(con, user_id, other_id):
                return False, "Message not found.", None
            now = int(time.time())
            con.execute(
                "INSERT OR IGNORE INTO message_reads (message_id, user_id, read_at) VALUES (?, ?, ?)",
                (message_id, user_id, now),
            )
            sender_name = "system"
            if row["sender_id"] is not None:
                sender = con.execute("SELECT nickname FROM users WHERE id = ?", (int(row["sender_id"]),)).fetchone()
                sender_name = str(sender["nickname"]) if sender is not None else "unknown"
            return True, "OK", {
                "id": int(row["id"]),
                "chat_id": int(row["chat_id"]),
                "sender_id": int(row["sender_id"]) if row["sender_id"] is not None else None,
                "sender_nickname": sender_name,
                "message_type": str(row["message_type"]),
                "body": get_crypto().dec(row["body_enc"]),
                "created_at": int(row["created_at"]),
            }

    def send_message(self, sender_id: int, chat_id: int, body: str) -> tuple[bool, str, Optional[int]]:
        with self.lock, self.conn() as con:
            chat = self.get_chat_for_participant(con, chat_id, sender_id)
            if chat is None:
                return False, "Chat not found.", None
            other_id = int(chat["user_high_id"]) if int(chat["user_low_id"]) == sender_id else int(chat["user_low_id"])
            if self.block_exists(con, sender_id, other_id):
                return False, "Not allowed.", None
            now = int(time.time())
            cur = con.execute(
                "INSERT INTO messages (chat_id, sender_id, message_type, body_enc, created_at) VALUES (?, ?, 'user', ?, ?)",
                (chat_id, sender_id, get_crypto().enc(body), now),
            )
            con.execute("UPDATE chats SET updated_at = ? WHERE id = ?", (now, chat_id))
            return True, "Message sent.", int(cur.lastrowid)

    # =========================
    # Forum
    # =========================
    def _user_can_post(self, con: sqlite3.Connection, user_id: int) -> tuple[bool, str]:
        row = con.execute("SELECT reputation, is_banned FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None or bool(row["is_banned"]):
            return False, "Not allowed."
        if float(row["reputation"]) <= NEGATIVE_REP_POST_THRESHOLD:
            return False, f"Users with reputation of {NEGATIVE_REP_POST_THRESHOLD:g} or below cannot post or comment on threads."
        return True, "OK"

    def _index_thread_terms(self, con: sqlite3.Connection, thread_id: int, *texts: str) -> None:
        terms: set[str] = set()
        for text in texts:
            for token in tokenize(text):
                if len(token) >= MIN_SEARCH_QUERY_LEN:
                    terms.add(token)
        for term in terms:
            con.execute(
                "INSERT OR IGNORE INTO thread_search_terms (thread_id, term_hmac) VALUES (?, ?)",
                (thread_id, get_crypto().term_hmac(term)),
            )

    def _thread_row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        author_is_banned = bool(row["author_is_banned"]) if "author_is_banned" in row.keys() else False
        author_nickname = str(row["author_nickname"])
        author_display = f"{BAN_LABEL} {author_nickname}" if author_is_banned else author_nickname
        return {
            "id": int(row["id"]),
            "title": get_crypto().dec(row["title_enc"]),
            "author_id": int(row["author_id"]),
            "author_nickname": author_nickname,
            "author_is_banned": author_is_banned,
            "author_display": author_display,
            "reply_count": int(row["reply_count"]) if "reply_count" in row.keys() else 0,
            "created_at": int(row["created_at"]),
            "updated_at": int(row["updated_at"]),
        }

    def create_thread(self, author_row: sqlite3.Row, title: str, body: str) -> tuple[bool, str, Optional[int]]:
        now = int(time.time())
        with self.lock, self.conn() as con:
            author_id = int(author_row["id"])
            allowed, reason = self._user_can_post(con, author_id)
            if not allowed:
                return False, reason, None
            quota_err = self.enforce_write_quota(con, author_row, "create_thread")
            if quota_err:
                return False, quota_err, None
            cur = con.execute(
                "INSERT INTO threads (author_id, title_enc, body_enc, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                (author_id, get_crypto().enc(title), get_crypto().enc(body), now, now),
            )
            thread_id = int(cur.lastrowid)
            self._index_thread_terms(con, thread_id, title, body)
            self._register_fingerprint(con, author_id, "thread", f"{title}\n{body}", now)
            return True, "Thread created.", thread_id

    def _register_fingerprint(self, con: sqlite3.Connection, user_id: int, kind: str, text: str, now: int) -> None:
        sh = simhash64(text)
        if sh == 0:
            return
        recent = con.execute(
            "SELECT user_id, simhash FROM content_fingerprints WHERE created_at >= ? ORDER BY id DESC LIMIT ?",
            (now - 7 * 86400, CONTENT_SIMHASH_WINDOW),
        ).fetchall()
        for r in recent:
            if r["user_id"] is not None and int(r["user_id"]) != user_id:
                if hamming(sh, int(r["simhash"])) <= CONTENT_SIMHASH_MAX_HAMMING:
                    con.execute(
                        "INSERT INTO moderation_flags (user_id, nickname, kind, detail, resolved, created_at) "
                        "VALUES (?, ?, 'cross_account_duplicate', ?, 0, ?)",
                        (user_id, None, f"{kind} near-duplicate of content from user {int(r['user_id'])}", now),
                    )
                    break
        con.execute(
            "INSERT INTO content_fingerprints (user_id, kind, simhash, created_at) VALUES (?, ?, ?, ?)",
            (user_id, kind, sh, now),
        )

    def _thread_block_clause(self, viewer_id: Optional[int]) -> tuple[str, list[Any]]:
        if viewer_id is None:
            return "", []
        clause = (
            "NOT EXISTS (SELECT 1 FROM user_blocks b WHERE "
            "(b.blocker_id = ? AND b.blocked_id = t.author_id) OR "
            "(b.blocker_id = t.author_id AND b.blocked_id = ?))"
        )
        return clause, [viewer_id, viewer_id]

    def list_threads(self, viewer_id: Optional[int], page: int = 1,
                     per_page: int = PAGE_SIZE) -> tuple[list[dict[str, Any]], int, int]:
        with self.lock, self.conn() as con:
            clause, params = self._thread_block_clause(viewer_id)
            from_where = "FROM threads t JOIN users u ON u.id = t.author_id "
            if clause:
                from_where += "WHERE " + clause + " "
            total = int(con.execute("SELECT COUNT(*) " + from_where, params).fetchone()[0])
            total_pages = max(1, (total + per_page - 1) // per_page)
            page = min(max(1, page), total_pages)
            offset = (page - 1) * per_page
            select = (
                "SELECT t.*, u.nickname AS author_nickname, u.is_banned AS author_is_banned, "
                "(SELECT COUNT(*) FROM thread_posts p WHERE p.thread_id = t.id) AS reply_count "
                + from_where + "ORDER BY t.updated_at DESC, t.id DESC LIMIT ? OFFSET ?"
            )
            rows = con.execute(select, params + [per_page, offset]).fetchall()
            return [self._thread_row_to_dict(row) for row in rows], total, page

    def search_threads(self, viewer_id: Optional[int], query_text: str, page: int = 1,
                       per_page: int = PAGE_SIZE) -> tuple[list[dict[str, Any]], int, int]:
        """Whole-word (case-insensitive) search backed by an HMAC keyword index.

        Query tokens are hashed with the index key; only threads containing ALL
        tokens are candidates, so we decrypt matching rows only (bounded by
        SEARCH_MAX_CANDIDATES) instead of the whole table. The decrypt step then
        confirms the tokens and applies block filtering.
        """
        tokens = [t for t in tokenize(query_text) if len(t) >= MIN_SEARCH_QUERY_LEN]
        with self.lock, self.conn() as con:
            if not tokens:
                return [], 0, 1
            hmacs = [get_crypto().term_hmac(t) for t in tokens]
            placeholders = ",".join("?" for _ in hmacs)
            candidate_rows = con.execute(
                f"SELECT thread_id FROM thread_search_terms WHERE term_hmac IN ({placeholders}) "
                "GROUP BY thread_id HAVING COUNT(DISTINCT term_hmac) = ? "
                "ORDER BY thread_id DESC LIMIT ?",
                hmacs + [len(hmacs), SEARCH_MAX_CANDIDATES],
            ).fetchall()
            candidate_ids = [int(r["thread_id"]) for r in candidate_rows]
            if not candidate_ids:
                return [], 0, 1
            clause, params = self._thread_block_clause(viewer_id)
            id_placeholders = ",".join("?" for _ in candidate_ids)
            base = (
                "SELECT t.*, u.nickname AS author_nickname, u.is_banned AS author_is_banned, "
                "(SELECT COUNT(*) FROM thread_posts p WHERE p.thread_id = t.id) AS reply_count "
                "FROM threads t JOIN users u ON u.id = t.author_id "
                f"WHERE t.id IN ({id_placeholders}) "
            )
            row_params: list[Any] = list(candidate_ids)
            if clause:
                base += "AND " + clause + " "
                row_params += params
            base += "ORDER BY t.updated_at DESC, t.id DESC"
            rows = con.execute(base, row_params).fetchall()
            matches = [self._thread_row_to_dict(row) for row in rows][:MAX_SEARCH_RESULTS]
            total = len(matches)
            total_pages = max(1, (total + per_page - 1) // per_page)
            page = min(max(1, page), total_pages)
            start = (page - 1) * per_page
            return matches[start:start + per_page], total, page

    def get_thread_for_viewer(self, thread_id: int, viewer_id: Optional[int]) -> tuple[bool, str, Optional[dict[str, Any]]]:
        with self.lock, self.conn() as con:
            row = con.execute(
                "SELECT t.*, u.nickname AS author_nickname, u.is_banned AS author_is_banned "
                "FROM threads t JOIN users u ON u.id = t.author_id WHERE t.id = ?",
                (thread_id,),
            ).fetchone()
            if row is None:
                return False, "Thread not found.", None
            viewer = self.get_user(viewer_id) if viewer_id else None
            is_admin = bool(viewer and viewer["is_admin"])
            is_author = bool(viewer_id and int(row["author_id"]) == viewer_id)
            if viewer_id is not None and not is_author and not is_admin and self.block_exists(con, viewer_id, int(row["author_id"])):
                return False, "Thread not found.", None
            data = self._thread_row_to_dict(row)
            data["body"] = get_crypto().dec(row["body_enc"])
            data["is_author"] = is_author
            data["is_admin"] = is_admin
            post_rows = con.execute(
                "SELECT p.id, p.author_id, p.body_enc, p.created_at, "
                "u.nickname AS author_nickname, u.is_banned AS author_is_banned "
                "FROM thread_posts p LEFT JOIN users u ON u.id = p.author_id "
                "WHERE p.thread_id = ? ORDER BY p.created_at ASC, p.id ASC",
                (thread_id,),
            ).fetchall()
            posts: list[dict[str, Any]] = []
            for p in post_rows:
                p_author_id = int(p["author_id"]) if p["author_id"] is not None else None
                if (
                    viewer_id is not None
                    and not is_admin
                    and p_author_id is not None
                    and p_author_id != viewer_id
                    and self.block_exists(con, viewer_id, p_author_id)
                ):
                    continue
                author_nick = str(p["author_nickname"]) if p["author_nickname"] is not None else "[deleted user]"
                author_banned = bool(p["author_is_banned"]) if p["author_is_banned"] is not None else False
                posts.append(
                    {
                        "id": int(p["id"]),
                        "author_id": p_author_id,
                        "author_nickname": author_nick,
                        "author_display": f"{BAN_LABEL} {author_nick}" if author_banned else author_nick,
                        "body": get_crypto().dec(p["body_enc"]),
                        "created_at": int(p["created_at"]),
                    }
                )
            data["posts"] = posts
            data["created_at_raw"] = int(row["created_at"])
            return True, "OK", data

    def thread_created_at(self, con: sqlite3.Connection, thread_id: int) -> Optional[int]:
        row = con.execute("SELECT created_at FROM threads WHERE id = ?", (thread_id,)).fetchone()
        return int(row["created_at"]) if row is not None else None

    def add_thread_post(self, author_row: sqlite3.Row, thread_id: int, body: str) -> tuple[bool, str, Optional[int]]:
        now = int(time.time())
        with self.lock, self.conn() as con:
            author_id = int(author_row["id"])
            allowed, reason = self._user_can_post(con, author_id)
            if not allowed:
                return False, reason, None
            thread = con.execute("SELECT id, author_id, created_at FROM threads WHERE id = ?", (thread_id,)).fetchone()
            if thread is None:
                return False, "Thread not found.", None
            if self.block_exists(con, author_id, int(thread["author_id"])):
                return False, "Not allowed.", None
            quota_err = self.enforce_write_quota(con, author_row, "post_comment")
            if quota_err:
                return False, quota_err, None
            cur = con.execute(
                "INSERT INTO thread_posts (thread_id, author_id, body_enc, created_at) VALUES (?, ?, ?, ?)",
                (thread_id, author_id, get_crypto().enc(body), now),
            )
            con.execute("UPDATE threads SET updated_at = ? WHERE id = ?", (now, thread_id))
            # Fast-reply behavioral signal (report only).
            if not bool(author_row["is_admin"]) and now - int(thread["created_at"]) <= FAST_REPLY_SECONDS and int(thread["author_id"]) != author_id:
                con.execute(
                    "INSERT INTO moderation_flags (user_id, nickname, kind, detail, resolved, created_at) "
                    "VALUES (?, ?, 'fast_reply', ?, 0, ?)",
                    (author_id, str(author_row["nickname"]), f"comment {now - int(thread['created_at'])}s after thread {thread_id} created", now),
                )
            self._register_fingerprint(con, author_id, "comment", body, now)
            return True, "Comment posted.", int(cur.lastrowid)

    def delete_thread(self, actor_id: int, thread_id: int) -> tuple[bool, str]:
        with self.lock, self.conn() as con:
            actor = con.execute("SELECT id, is_admin FROM users WHERE id = ?", (actor_id,)).fetchone()
            if actor is None or not bool(actor["is_admin"]):
                return False, "Not allowed."
            cur = con.execute("DELETE FROM threads WHERE id = ?", (thread_id,))
            if cur.rowcount == 0:
                return False, "Thread not found."
            return True, "Thread deleted."

    def delete_thread_post(self, actor_id: int, post_id: int) -> tuple[bool, str]:
        with self.lock, self.conn() as con:
            actor = con.execute("SELECT id, is_admin FROM users WHERE id = ?", (actor_id,)).fetchone()
            if actor is None or not bool(actor["is_admin"]):
                return False, "Not allowed."
            cur = con.execute("DELETE FROM thread_posts WHERE id = ?", (post_id,))
            if cur.rowcount == 0:
                return False, "Comment not found."
            return True, "Comment deleted."


db: Database


# =========================
# Sessions / throttling
# =========================
@dataclass
class Session:
    token: str
    user_id: int
    nickname: str
    is_admin: bool
    last_seen: float
    # Behavioral tracking (in-memory, report-only).
    request_times: deque = field(default_factory=lambda: deque(maxlen=ACTIVITY_HISTORY))
    viewed_threads: set = field(default_factory=set)


class SessionStore:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.sessions: dict[str, Session] = {}

    def create(self, user_row: sqlite3.Row) -> Session:
        token = secrets.token_urlsafe(24)
        session = Session(
            token=token,
            user_id=int(user_row["id"]),
            nickname=str(user_row["nickname"]),
            is_admin=bool(user_row["is_admin"]),
            last_seen=time.time(),
        )
        with self.lock:
            doomed = [existing for existing, current in self.sessions.items() if current.user_id == session.user_id]
            for existing in doomed:
                self.sessions.pop(existing, None)
            self.sessions[token] = session
        return session

    def get(self, token: Optional[str]) -> Optional[Session]:
        if not token:
            return None
        with self.lock:
            session = self.sessions.get(token)
            if not session:
                return None
            if time.time() - session.last_seen > SESSION_IDLE_SECONDS:
                self.sessions.pop(token, None)
                return None
            session.last_seen = time.time()
            return session

    def delete(self, token: Optional[str]) -> None:
        if not token:
            return
        with self.lock:
            self.sessions.pop(token, None)

    def delete_user_sessions(self, user_id: int) -> None:
        with self.lock:
            doomed = [token for token, session in self.sessions.items() if session.user_id == user_id]
            for token in doomed:
                self.sessions.pop(token, None)


class ChallengeManager:
    """Issues and verifies one-time, memory-hard proof-of-work challenges with a
    per-challenge difficulty (so the difficulty cannot be downgraded by the
    client). When the store is full, new issuance is refused rather than evicting
    challenges real users are currently solving."""

    def __init__(self, ttl_seconds: int, max_size: int) -> None:
        self.lock = threading.Lock()
        self.ttl = ttl_seconds
        self.max_size = max_size
        self.store: dict[str, dict[str, Any]] = {}

    def _cleanup(self, now: float) -> None:
        expired = [cid for cid, c in self.store.items() if c["expires_at"] <= now]
        for cid in expired:
            self.store.pop(cid, None)

    def issue(self, purpose: str, difficulty: int) -> Optional[dict[str, Any]]:
        now = time.time()
        with self.lock:
            self._cleanup(now)
            if len(self.store) >= self.max_size:
                return None
            challenge_id = secrets.token_hex(16)
            prefix = secrets.token_hex(POW_PREFIX_BYTES)
            self.store[challenge_id] = {
                "prefix": prefix,
                "difficulty": int(difficulty),
                "purpose": purpose,
                "expires_at": now + self.ttl,
            }
            return {
                "challenge_id": challenge_id,
                "prefix": prefix,
                "difficulty": int(difficulty),
                "algorithm": "scrypt-leading-zero-bits",
                "scrypt": {"n": POW_SCRYPT_N, "r": POW_SCRYPT_R, "p": POW_SCRYPT_P, "dklen": 32},
                "expires_in": self.ttl,
            }

    def consume(self, challenge_id: str, nonce: str, purpose: str) -> tuple[bool, str]:
        now = time.time()
        with self.lock:
            self._cleanup(now)
            challenge = self.store.get(challenge_id)
            if challenge is None:
                return False, "Challenge not found or expired. Request a new one."
            if challenge["purpose"] != purpose:
                return False, "Challenge was issued for a different action."
            if challenge["expires_at"] <= now:
                self.store.pop(challenge_id, None)
                return False, "Challenge expired. Request a new one."
            prefix = challenge["prefix"]
            difficulty = int(challenge["difficulty"])
        # scrypt verification is done outside the lock (it is memory-hard).
        if not pow_solution_ok(prefix, str(nonce), difficulty):
            return False, "Invalid proof-of-work solution."
        with self.lock:
            # Re-check and consume (one-time use).
            if challenge_id not in self.store:
                return False, "Challenge already consumed or expired."
            self.store.pop(challenge_id, None)
        return True, "OK"


class SlidingWindowLimiter:
    def __init__(self, window_seconds: int, max_events: int) -> None:
        self.window_seconds = window_seconds
        self.max_events = max_events
        self.lock = threading.Lock()
        self.events: dict[str, list[float]] = {}

    def _cleanup_bucket(self, key: str, now: float) -> list[float]:
        bucket = self.events.get(key, [])
        bucket = [ts for ts in bucket if now - ts <= self.window_seconds]
        if bucket:
            self.events[key] = bucket
        else:
            self.events.pop(key, None)
        return bucket

    def allow(self, key: str) -> tuple[bool, int]:
        now = time.time()
        with self.lock:
            bucket = self._cleanup_bucket(key, now)
            if len(bucket) >= self.max_events:
                retry_after = max(1, int(self.window_seconds - (now - bucket[0])))
                return False, retry_after
            bucket.append(now)
            self.events[key] = bucket
            stale = [k for k, v in self.events.items() if not v or now - v[-1] > self.window_seconds]
            for k in stale:
                self.events.pop(k, None)
            return True, 0


class LoginFailTracker:
    """Tracks recent failed logins per nickname to escalate the login PoW.
    There is NO hard lockout — a hard lockout keyed on nickname would let anyone
    lock out any account (all Tor clients share one IP)."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.failures: dict[str, list[float]] = {}

    def _recent(self, nickname: str, now: float) -> list[float]:
        bucket = [ts for ts in self.failures.get(nickname, []) if now - ts <= LOGIN_FAIL_WINDOW_SECONDS]
        if bucket:
            self.failures[nickname] = bucket
        else:
            self.failures.pop(nickname, None)
        return bucket

    def extra_difficulty(self, nickname: str) -> int:
        now = time.time()
        with self.lock:
            n = len(self._recent(nickname, now))
        return min(LOGIN_FAIL_POW_MAX_EXTRA, n * LOGIN_FAIL_POW_STEP)

    def fail(self, nickname: str) -> None:
        now = time.time()
        with self.lock:
            bucket = self._recent(nickname, now)
            bucket.append(now)
            self.failures[nickname] = bucket

    def success(self, nickname: str) -> None:
        with self.lock:
            self.failures.pop(nickname, None)


sessions = SessionStore()
server_limiter = SlidingWindowLimiter(SERVER_WINDOW_SECONDS, SERVER_MAX_REQUESTS_PER_WINDOW)
parse_error_limiter = SlidingWindowLimiter(SERVER_WINDOW_SECONDS, MAX_PARSE_ERRORS_PER_WINDOW)
message_rate_limiter = SlidingWindowLimiter(MESSAGE_RATE_WINDOW_SECONDS, MESSAGE_RATE_MAX_MESSAGES)
session_rate_limiter = SlidingWindowLimiter(SESSION_RATE_WINDOW_SECONDS, SESSION_RATE_MAX_REQUESTS)
forum_write_limiter = SlidingWindowLimiter(FORUM_WRITE_WINDOW_SECONDS, FORUM_WRITE_MAX)
search_rate_limiter = SlidingWindowLimiter(SEARCH_RATE_WINDOW_SECONDS, SEARCH_RATE_MAX)
challenge_rate_limiter = SlidingWindowLimiter(CHALLENGE_RATE_WINDOW_SECONDS, CHALLENGE_RATE_MAX)
login_fail_tracker = LoginFailTracker()
challenges = ChallengeManager(POW_CHALLENGE_TTL_SECONDS, POW_MAX_CHALLENGES)


# =========================
# Protocol server
# =========================
def ok(data: Optional[dict[str, Any]] = None, message: str = "OK") -> dict[str, Any]:
    return {"ok": True, "message": message, "data": data or {}}


def err(message: str, code: str = "error", retry_after: Optional[int] = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"ok": False, "error": code, "message": message}
    if retry_after is not None:
        payload["retry_after"] = retry_after
    return payload


def parse_bool_field(value: Any, field_name: str) -> tuple[Optional[bool], Optional[str]]:
    if isinstance(value, bool):
        return value, None
    return None, f"{field_name} must be a boolean true/false value."


VALID_ACTIONS = {
    "ping", "get_challenge", "register", "login", "logout", "profile",
    "list_jobs", "my_jobs", "my_accepts", "create_job", "job_details",
    "accept_job", "withdraw_job", "select_worker", "set_status", "delete_job",
    "ban_user", "rate_user", "block_user", "unblock_user", "list_blocks",
    "open_chat", "list_chats", "list_messages", "read_message", "send_message",
    "create_thread", "list_threads", "search_threads", "thread_details",
    "post_comment", "delete_thread", "delete_comment", "wipe_user",
    # Invites / vouching
    "create_invite", "list_invites", "revoke_invite",
    # Admin: registration control & moderation
    "admin_get_settings", "admin_set_registration_mode", "admin_set_approval_lock",
    "admin_list_pending", "admin_approve_user", "admin_reject_user",
    "admin_rep", "admin_list_flags", "admin_resolve_flag",
    "admin_list_frozen_ratings", "admin_resolve_rating",
}


def require_session(request: dict[str, Any]) -> tuple[Optional[Session], Optional[dict[str, Any]]]:
    session = sessions.get(request.get("session_token"))
    if not session:
        return None, err("Authentication required.", "auth_required")
    allowed, retry = session_rate_limiter.allow(session.token)
    if not allowed:
        audit_log(event="session_rate_limited", actor_nickname=session.nickname, status="blocked", details=f"retry_after={retry}s")
        return None, err("Too many requests. Slow down.", "rate_limited", retry)
    user = get_db().get_user(session.user_id)
    if user is None:
        sessions.delete(session.token)
        return None, err("User not found.", "auth_required")
    if bool(user["is_banned"]) or str(user["status"]) != "active":
        sessions.delete(session.token)
        return None, err("Invalid credentials.", "login_failed")
    session.is_admin = bool(user["is_admin"])
    # Record activity for behavioral analysis.
    session.request_times.append(time.time())
    _behavioral_timing_check(session)
    return session, None


def _behavioral_timing_check(session: Session) -> None:
    """Metronomic-timing signal (report only)."""
    if session.is_admin or len(session.request_times) < TIMING_MIN_SAMPLES:
        return
    times = list(session.request_times)
    intervals = [b - a for a, b in zip(times, times[1:]) if b - a > 0]
    if len(intervals) < TIMING_MIN_SAMPLES - 1:
        return
    mean = statistics.fmean(intervals)
    if mean <= 0:
        return
    cv = statistics.pstdev(intervals) / mean
    if cv < TIMING_REGULARITY_CV:
        # Flag once per session-ish: only when the deque just filled a boundary.
        if len(session.request_times) == ACTIVITY_HISTORY:
            get_db().add_flag(session.user_id, session.nickname, "metronomic_timing",
                              f"request interval CV={cv:.3f} over {len(intervals)} samples")


def _current_user_row(session: Session) -> Optional[sqlite3.Row]:
    return get_db().get_user(session.user_id)


def require_pow(request: dict[str, Any], purpose: str) -> Optional[dict[str, Any]]:
    challenge_id = request.get("challenge_id")
    nonce = request.get("nonce")
    if not challenge_id or nonce is None:
        return err("Proof-of-work required. Call get_challenge and submit challenge_id and nonce.", "challenge_failed")
    accepted, message = challenges.consume(str(challenge_id), str(nonce), purpose)
    if not accepted:
        return err(message, "challenge_failed")
    return None


def require_write_pow(request: dict[str, Any], session: Session, purpose: str) -> Optional[dict[str, Any]]:
    """PoW on write actions, but exempt users at/above the trusted-reputation
    threshold so established members are not slowed down."""
    user = get_db().get_user(session.user_id)
    rep = float(user["reputation"]) if user is not None else 0.0
    if bool(session.is_admin) or rep >= POW_WRITE_EXEMPT_REP:
        return None
    return require_pow(request, purpose)


def _challenge_difficulty(purpose: str, request: dict[str, Any]) -> int:
    if purpose == "register":
        return clamp_difficulty(POW_BASE_DIFFICULTY)
    if purpose == "login":
        nickname = str(request.get("nickname", "")).strip()
        return clamp_difficulty(POW_BASE_DIFFICULTY + login_fail_tracker.extra_difficulty(nickname))
    # Session-based purposes: difficulty adapts to the caller's reputation.
    session = sessions.get(request.get("session_token"))
    if session is None:
        return clamp_difficulty(POW_BASE_DIFFICULTY)
    user = get_db().get_user(session.user_id)
    rep = float(user["reputation"]) if user is not None else 0.0
    return difficulty_for_reputation(rep)


def handle_request(request: dict[str, Any], ip: str) -> dict[str, Any]:
    shape_problem = ensure_request_shape(request)
    if shape_problem:
        audit_log(event="request_rejected", action="invalid_shape", ip=ip, status="fail", details=shape_problem)
        return err(shape_problem, "bad_request")

    action = request.get("action")
    if not isinstance(action, str):
        audit_log(event="request_rejected", action="missing_action", ip=ip, status="fail", details="Missing action.")
        return err("Missing action.", "bad_request")
    if action not in VALID_ACTIONS:
        audit_log(event="request_rejected", action=str(action), ip=ip, status="fail", details="Unknown action.")
        return err("Unknown action.", "unknown_action")

    if action == "ping":
        return ok({"server": "AFTERLIFE", "version": 2}, "Welcome to AFTERLIFE")

    if action == "get_challenge":
        purpose = str(request.get("purpose", ""))
        if purpose not in POW_PURPOSES:
            return err("Invalid challenge purpose.", "validation_error")
        # Rate-limit challenge issuance: per session when authenticated, else per ip.
        session = sessions.get(request.get("session_token"))
        limit_key = session.token if session is not None else f"ip:{ip}:{purpose}"
        allowed, retry = challenge_rate_limiter.allow(limit_key)
        if not allowed:
            return err("Requesting challenges too fast. Slow down.", "rate_limited", retry)
        difficulty = _challenge_difficulty(purpose, request)
        issued = challenges.issue(purpose, difficulty)
        if issued is None:
            return err("Server is busy issuing challenges. Try again shortly.", "server_busy", 5)
        return ok(issued, "Solve the proof-of-work challenge.")

    if action == "register":
        nickname = str(request.get("nickname", "")).strip()
        password = str(request.get("password", ""))
        invite_code = request.get("invite_code")
        invite_code = str(invite_code).strip() if invite_code else None
        problem = validate_nickname(nickname) or validate_password(password)
        if not problem and invite_code:
            problem = validate_invite_code(invite_code)
        if problem:
            audit_log(event="user_register", action=action, ip=ip, actor_nickname=nickname or None, status="fail", details=problem)
            return err(problem, "validation_error")
        pow_failure = require_pow(request, "register")
        if pow_failure:
            audit_log(event="user_register", action=action, ip=ip, actor_nickname=nickname or None, status="fail", details="pow_failed")
            return pow_failure
        success, message, info = get_db().register_user(nickname, password, invite_code)
        audit_log(event="user_register", action=action, ip=ip, actor_nickname=nickname or None, status="success" if success else "fail", details=message)
        return ok({"pending": info.get("pending", False)}, message) if success else err(message, "register_failed")

    if action == "login":
        nickname = str(request.get("nickname", "")).strip()
        password = str(request.get("password", ""))
        if len(password) > MAX_PASSWORD_LEN:
            login_fail_tracker.fail(nickname)
            audit_log(event="login_failed", action=action, ip=ip, actor_nickname=nickname or None, status="fail", details="invalid credentials")
            return err("Invalid credentials.", "login_failed")
        pow_failure = require_pow(request, "login")
        if pow_failure:
            audit_log(event="login_failed", action=action, ip=ip, actor_nickname=nickname or None, status="fail", details="pow_failed")
            return pow_failure
        user, reason = get_db().authenticate(nickname, password)
        if user is None:
            if reason == "pending":
                return err("Your account is awaiting administrator approval.", "account_pending")
            if reason == "rejected":
                return err("Your registration was not approved.", "account_rejected")
            login_fail_tracker.fail(nickname)
            time.sleep(1.0)
            audit_log(event="login_failed", action=action, ip=ip, actor_nickname=nickname or None, status="fail", details="invalid credentials")
            return err("Invalid credentials.", "login_failed")
        login_fail_tracker.success(nickname)
        session = sessions.create(user)
        audit_log(event="login_success", action=action, ip=ip, actor_nickname=session.nickname, status="success")
        return ok({"session_token": session.token, "nickname": session.nickname, "reputation": round(float(user["reputation"]), 3), "is_admin": bool(user["is_admin"]), "is_banned": bool(user["is_banned"])}, "Login successful.")

    if action == "logout":
        session = sessions.get(request.get("session_token"))
        if session:
            audit_log(event="logout", action=action, ip=ip, actor_nickname=session.nickname, status="success")
        sessions.delete(request.get("session_token"))
        return ok(message="Logged out.")

    if action == "profile":
        session, failure = require_session(request)
        if failure:
            return failure
        user = get_db().get_user(session.user_id)
        if user is None:
            return err("User not found.", "not_found")
        with get_db().lock, get_db().conn() as con:
            ctx = get_db().trust_context(con, user)
        return ok({
            "nickname": str(user["nickname"]),
            "reputation": round(float(user["reputation"]), 3),
            "trust_level": ctx["level"],
            "distinct_job_partners": ctx["partners"],
            "created_at": int(user["created_at"]),
            "is_admin": bool(user["is_admin"]),
            "is_banned": bool(user["is_banned"]),
            "pow_difficulty": difficulty_for_reputation(float(user["reputation"])),
        })

    if action == "list_jobs":
        session, failure = require_session(request)
        if failure:
            return failure
        status = request.get("status")
        if status is not None and status not in {"open", "done", "cancelled"}:
            return err("Invalid status filter.", "validation_error")
        items, total, page = get_db().list_jobs(viewer_id=session.user_id, status=status, page=parse_page(request))
        return ok({"jobs": items, "pagination": pagination_meta(total, page)})

    if action == "my_jobs":
        session, failure = require_session(request)
        if failure:
            return failure
        return ok({"jobs": get_db().my_authored_jobs(session.user_id)})

    if action == "my_accepts":
        session, failure = require_session(request)
        if failure:
            return failure
        return ok({"jobs": get_db().my_accepted_jobs(session.user_id)})

    if action == "create_job":
        session, failure = require_session(request)
        if failure:
            return failure
        pow_failure = require_write_pow(request, session, "create_job")
        if pow_failure:
            return pow_failure
        title = str(request.get("title", "")).strip()
        description = str(request.get("description", "")).strip()
        reward_raw = str(request.get("reward", "")).strip()
        min_rep_raw = str(request.get("min_reputation", "0")).strip()
        is_private, bool_problem = parse_bool_field(request.get("is_private", False), "is_private")
        problem = validate_title(title) or validate_description(description) or validate_reward(reward_raw) or validate_min_reputation(min_rep_raw) or bool_problem
        if problem:
            return err(problem, "validation_error")
        user = _current_user_row(session)
        success, message, result = get_db().create_job(user, title, description, int(reward_raw), int(min_rep_raw), bool(is_private))
        audit_log(event="job_create", action=action, ip=ip, actor_nickname=session.nickname, status="success" if success else "fail", details=message)
        return ok(result, message) if success else err(message, "create_failed")

    if action == "job_details":
        session, failure = require_session(request)
        if failure:
            return failure
        try:
            job_id_int = int(request.get("job_id"))
        except Exception:
            return err("Invalid job id.", "validation_error")
        unlock_token = request.get("unlock_token")
        success, message, data = get_db().get_job_for_viewer(job_id_int, session.user_id, str(unlock_token) if unlock_token else None)
        return ok(data, message) if success and data is not None else err(message, "not_found")

    if action == "accept_job":
        session, failure = require_session(request)
        if failure:
            return failure
        try:
            job_id = int(request.get("job_id"))
        except Exception:
            return err("Invalid job id.", "validation_error")
        private_token_raw = request.get("private_token")
        private_token = str(private_token_raw).strip() if private_token_raw is not None else None
        success, message = get_db().accept_job(job_id, session.user_id, private_token)
        audit_log(event="job_accept", action=action, ip=ip, actor_nickname=session.nickname, job_id=job_id, status="success" if success else "fail", details=message)
        return ok(message=message) if success else err(message, "accept_failed")

    if action == "withdraw_job":
        session, failure = require_session(request)
        if failure:
            return failure
        try:
            job_id = int(request.get("job_id"))
        except Exception:
            return err("Invalid job id.", "validation_error")
        success, message = get_db().withdraw_accept(job_id, session.user_id)
        audit_log(event="job_withdraw", action=action, ip=ip, actor_nickname=session.nickname, job_id=job_id, status="success" if success else "fail", details=message)
        return ok(message=message) if success else err(message, "withdraw_failed")

    if action == "select_worker":
        session, failure = require_session(request)
        if failure:
            return failure
        try:
            job_id = int(request.get("job_id"))
            worker_id = int(request.get("worker_id"))
        except Exception:
            return err("Invalid identifiers.", "validation_error")
        success, message = get_db().set_selected_worker(job_id, session.user_id, worker_id)
        worker = get_db().get_user(worker_id)
        worker_target = str(worker["nickname"]) if worker is not None else str(worker_id)
        audit_log(event="job_select_worker", action=action, ip=ip, actor_nickname=session.nickname, job_id=job_id, target_user=worker_target, status="success" if success else "fail", details=message)
        return ok(message=message) if success else err(message, "select_failed")

    if action == "set_status":
        session, failure = require_session(request)
        if failure:
            return failure
        try:
            job_id = int(request.get("job_id"))
        except Exception:
            return err("Invalid job id.", "validation_error")
        status = str(request.get("status", "")).strip().lower()
        success, message = get_db().set_job_status(job_id, session.user_id, status)
        audit_log(event="job_set_status", action=action, ip=ip, actor_nickname=session.nickname, job_id=job_id, status="success" if success else "fail", details=message)
        return ok(message=message) if success else err(message, "status_failed")

    if action == "delete_job":
        session, failure = require_session(request)
        if failure:
            return failure
        try:
            job_id = int(request.get("job_id"))
        except Exception:
            return err("Invalid job id.", "validation_error")
        success, message = get_db().delete_job(session.user_id, job_id)
        audit_log(event="job_delete", action=action, ip=ip, actor_nickname=session.nickname, job_id=job_id, status="success" if success else "fail", details=message)
        return ok(message=message) if success else err(message, "delete_failed")

    if action == "ban_user":
        session, failure = require_session(request)
        if failure:
            return failure
        nickname = str(request.get("nickname", "")).strip()
        problem = validate_nickname(nickname)
        if problem:
            return err(problem, "validation_error")
        success, message, banned_user_id = get_db().ban_user(session.user_id, nickname)
        if success and banned_user_id is not None:
            sessions.delete_user_sessions(banned_user_id)
            audit_log(event="user_ban", action=action, ip=ip, actor_nickname=session.nickname, target_user=nickname, status="success", details=message)
            return ok(message=message)
        audit_log(event="user_ban", action=action, ip=ip, actor_nickname=session.nickname, target_user=nickname, status="fail", details=message)
        return err(message, "ban_failed")

    if action == "rate_user":
        session, failure = require_session(request)
        if failure:
            return failure
        nickname = str(request.get("nickname", "")).strip()
        rating = str(request.get("rating", "")).strip().lower()
        problem = validate_nickname(nickname) or validate_rating_choice(rating)
        if problem:
            return err(problem, "validation_error")
        try:
            job_id = int(request.get("job_id"))
        except Exception:
            return err("A job id is required — you may only rate the counterparty of a completed job.", "validation_error")
        pow_failure = require_pow(request, "rate_user")
        if pow_failure:
            audit_log(event="user_rate", action=action, ip=ip, actor_nickname=session.nickname, target_user=nickname, status="fail", details="pow_failed")
            return pow_failure
        success, message, target_id, frozen = get_db().rate_user_for_job(session.user_id, nickname, rating, job_id)
        audit_log(event="user_rate", action=action, ip=ip, actor_nickname=session.nickname, target_user=nickname, job_id=job_id, status="success" if success else "fail", details=message)
        return ok({"frozen": frozen}, message) if success else err(message, "rating_failed")

    if action == "block_user":
        session, failure = require_session(request)
        if failure:
            return failure
        nickname = str(request.get("nickname", "")).strip()
        problem = validate_nickname(nickname)
        if problem:
            return err(problem, "validation_error")
        success, message, _ = get_db().set_block(session.user_id, nickname, True)
        audit_log(event="user_block", action=action, ip=ip, actor_nickname=session.nickname, target_user=nickname, status="success" if success else "fail", details=message)
        return ok(message=message) if success else err(message, "block_failed")

    if action == "unblock_user":
        session, failure = require_session(request)
        if failure:
            return failure
        nickname = str(request.get("nickname", "")).strip()
        problem = validate_nickname(nickname)
        if problem:
            return err(problem, "validation_error")
        success, message, _ = get_db().set_block(session.user_id, nickname, False)
        audit_log(event="user_unblock", action=action, ip=ip, actor_nickname=session.nickname, target_user=nickname, status="success" if success else "fail", details=message)
        return ok(message=message) if success else err(message, "unblock_failed")

    if action == "list_blocks":
        session, failure = require_session(request)
        if failure:
            return failure
        return ok({"blocks": get_db().list_blocks(session.user_id)})

    if action == "open_chat":
        session, failure = require_session(request)
        if failure:
            return failure
        nickname = str(request.get("nickname", "")).strip()
        problem = validate_nickname(nickname)
        if problem:
            return err(problem, "validation_error")
        pow_failure = require_write_pow(request, session, "open_chat")
        if pow_failure:
            return pow_failure
        user = _current_user_row(session)
        success, message, data = get_db().open_chat_by_nickname(user, nickname)
        audit_log(event="chat_open", action=action, ip=ip, actor_nickname=session.nickname, target_user=nickname, chat_id=(data or {}).get("chat_id") if data else None, status="success" if success else "fail", details=message)
        return ok(data, message) if success and data is not None else err(message, "chat_failed")

    if action == "list_chats":
        session, failure = require_session(request)
        if failure:
            return failure
        return ok({"chats": get_db().list_chats(session.user_id)})

    if action == "list_messages":
        session, failure = require_session(request)
        if failure:
            return failure
        try:
            chat_id = int(request.get("chat_id"))
        except Exception:
            return err("Invalid chat id.", "validation_error")
        success, message, data = get_db().list_messages(session.user_id, chat_id)
        return ok(data, message) if success and data is not None else err(message, "messages_failed")

    if action == "read_message":
        session, failure = require_session(request)
        if failure:
            return failure
        try:
            message_id = int(request.get("message_id"))
        except Exception:
            return err("Invalid message id.", "validation_error")
        success, message, data = get_db().read_message(session.user_id, message_id)
        return ok(data, message) if success and data is not None else err(message, "message_failed")

    if action == "send_message":
        session, failure = require_session(request)
        if failure:
            return failure
        allowed_msg, retry_msg = message_rate_limiter.allow(session.token)
        if not allowed_msg:
            audit_log(event="message_rate_limited", action=action, ip=ip, actor_nickname=session.nickname, status="blocked", details=f"retry_after={retry_msg}s")
            return err("Sending too fast. Slow down.", "rate_limited", retry_msg)
        try:
            chat_id = int(request.get("chat_id"))
        except Exception:
            return err("Invalid chat id.", "validation_error")
        body = str(request.get("message", "")).strip()
        problem = validate_message_text(body)
        if problem:
            return err(problem, "validation_error")
        success, message, message_id = get_db().send_message(session.user_id, chat_id, body)
        audit_log(event="message_send", action=action, ip=ip, actor_nickname=session.nickname, chat_id=chat_id, status="success" if success else "fail", details=message)
        return ok({"message_id": message_id}, message) if success else err(message, "send_failed")

    if action == "create_thread":
        session, failure = require_session(request)
        if failure:
            return failure
        allowed_w, retry_w = forum_write_limiter.allow(session.token)
        if not allowed_w:
            return err("Posting too fast. Slow down.", "rate_limited", retry_w)
        pow_failure = require_write_pow(request, session, "create_thread")
        if pow_failure:
            return pow_failure
        title = str(request.get("title", "")).strip()
        body = str(request.get("body", "")).replace("\r\n", "\n").replace("\r", "\n").strip()
        problem = validate_thread_title(title) or validate_thread_body(body)
        if problem:
            return err(problem, "validation_error")
        user = _current_user_row(session)
        success, message, thread_id = get_db().create_thread(user, title, body)
        audit_log(event="thread_create", action=action, ip=ip, actor_nickname=session.nickname, thread_id=thread_id, status="success" if success else "fail", details=message)
        return ok({"thread_id": thread_id}, message) if success else err(message, "thread_failed")

    if action == "list_threads":
        session, failure = require_session(request)
        if failure:
            return failure
        items, total, page = get_db().list_threads(viewer_id=session.user_id, page=parse_page(request))
        return ok({"threads": items, "pagination": pagination_meta(total, page)})

    if action == "search_threads":
        session, failure = require_session(request)
        if failure:
            return failure
        allowed_s, retry_s = search_rate_limiter.allow(session.token)
        if not allowed_s:
            return err("Searching too fast. Slow down.", "rate_limited", retry_s)
        query_text = str(request.get("query", "")).strip()
        problem = validate_search_query(query_text)
        if problem:
            return err(problem, "validation_error")
        items, total, page = get_db().search_threads(viewer_id=session.user_id, query_text=query_text, page=parse_page(request))
        return ok({"threads": items, "query": query_text, "pagination": pagination_meta(total, page)})

    if action == "thread_details":
        session, failure = require_session(request)
        if failure:
            return failure
        try:
            thread_id_int = int(request.get("thread_id"))
        except Exception:
            return err("Invalid thread id.", "validation_error")
        success, message, data = get_db().get_thread_for_viewer(thread_id_int, session.user_id)
        if success:
            session.viewed_threads.add(thread_id_int)
            data.pop("created_at_raw", None)
        return ok(data, message) if success and data is not None else err(message, "not_found")

    if action == "post_comment":
        session, failure = require_session(request)
        if failure:
            return failure
        allowed_w, retry_w = forum_write_limiter.allow(session.token)
        if not allowed_w:
            return err("Posting too fast. Slow down.", "rate_limited", retry_w)
        pow_failure = require_write_pow(request, session, "post_comment")
        if pow_failure:
            return pow_failure
        try:
            thread_id = int(request.get("thread_id"))
        except Exception:
            return err("Invalid thread id.", "validation_error")
        body = str(request.get("body", "")).replace("\r\n", "\n").replace("\r", "\n").strip()
        problem = validate_comment_text(body)
        if problem:
            return err(problem, "validation_error")
        # Sequence anomaly: replying to a thread this session never opened (report only).
        if thread_id not in session.viewed_threads and not session.is_admin:
            get_db().add_flag(session.user_id, session.nickname, "unseen_thread_comment",
                              f"comment on thread {thread_id} not fetched this session")
        user = _current_user_row(session)
        success, message, post_id = get_db().add_thread_post(user, thread_id, body)
        audit_log(event="thread_comment", action=action, ip=ip, actor_nickname=session.nickname, thread_id=thread_id, post_id=post_id, status="success" if success else "fail", details=message)
        return ok({"comment_id": post_id}, message) if success else err(message, "comment_failed")

    if action == "delete_thread":
        session, failure = require_session(request)
        if failure:
            return failure
        try:
            thread_id = int(request.get("thread_id"))
        except Exception:
            return err("Invalid thread id.", "validation_error")
        success, message = get_db().delete_thread(session.user_id, thread_id)
        audit_log(event="thread_delete", action=action, ip=ip, actor_nickname=session.nickname, thread_id=thread_id, status="success" if success else "fail", details=message)
        return ok(message=message) if success else err(message, "delete_failed")

    if action == "delete_comment":
        session, failure = require_session(request)
        if failure:
            return failure
        try:
            comment_id = int(request.get("comment_id"))
        except Exception:
            return err("Invalid comment id.", "validation_error")
        success, message = get_db().delete_thread_post(session.user_id, comment_id)
        audit_log(event="comment_delete", action=action, ip=ip, actor_nickname=session.nickname, post_id=comment_id, status="success" if success else "fail", details=message)
        return ok(message=message) if success else err(message, "delete_failed")

    if action == "wipe_user":
        session, failure = require_session(request)
        if failure:
            return failure
        nickname = str(request.get("nickname", "")).strip()
        problem = validate_nickname(nickname)
        if problem:
            return err(problem, "validation_error")
        success, message, wiped_id = get_db().wipe_user(session.user_id, nickname)
        if success and wiped_id is not None:
            sessions.delete_user_sessions(wiped_id)
            audit_log(event="user_wipe", action=action, ip=ip, actor_nickname=session.nickname, target_user=nickname, status="success", details=message)
            return ok(message=message)
        audit_log(event="user_wipe", action=action, ip=ip, actor_nickname=session.nickname, target_user=nickname, status="fail", details=message)
        return err(message, "wipe_failed")

    # ---- invites / vouching ----
    if action == "create_invite":
        session, failure = require_session(request)
        if failure:
            return failure
        success, message, code = get_db().create_invite(session.user_id)
        audit_log(event="invite_create", action=action, ip=ip, actor_nickname=session.nickname, status="success" if success else "fail", details=message)
        return ok({"invite_code": code}, message) if success else err(message, "invite_failed")

    if action == "list_invites":
        session, failure = require_session(request)
        if failure:
            return failure
        return ok({"invites": get_db().list_invites(session.user_id)})

    if action == "revoke_invite":
        session, failure = require_session(request)
        if failure:
            return failure
        try:
            invite_id = int(request.get("invite_id"))
        except Exception:
            return err("Invalid invite id.", "validation_error")
        success, message = get_db().revoke_invite(session.user_id, invite_id, session.is_admin)
        return ok(message=message) if success else err(message, "revoke_failed")

    # ---- admin: settings / moderation ----
    if action in {
        "admin_get_settings", "admin_set_registration_mode", "admin_set_approval_lock",
        "admin_list_pending", "admin_approve_user", "admin_reject_user", "admin_rep",
        "admin_list_flags", "admin_resolve_flag", "admin_list_frozen_ratings", "admin_resolve_rating",
    }:
        session, failure = require_session(request)
        if failure:
            return failure
        if not session.is_admin:
            return err("Admin only.", "not_allowed")

        if action == "admin_get_settings":
            return ok({
                "registration_mode": get_db().registration_mode(),
                "approval_required": get_db().approval_required(),
                "registration_max_per_hour": REGISTRATION_GLOBAL_MAX_PER_HOUR,
            })

        if action == "admin_set_registration_mode":
            mode = str(request.get("mode", "")).strip().lower()
            if mode not in VALID_REG_MODES:
                return err(f"Mode must be one of: {', '.join(sorted(VALID_REG_MODES))}.", "validation_error")
            get_db().set_setting("registration_mode", mode)
            audit_log(event="admin_registration_mode", action=action, ip=ip, actor_nickname=session.nickname, status="success", details=mode)
            return ok(message=f"Registration mode set to {mode}.")

        if action == "admin_set_approval_lock":
            enabled, bool_problem = parse_bool_field(request.get("enabled"), "enabled")
            if bool_problem:
                return err(bool_problem, "validation_error")
            get_db().set_setting("approval_required", "1" if enabled else "0")
            audit_log(event="admin_approval_lock", action=action, ip=ip, actor_nickname=session.nickname, status="success", details=str(enabled))
            return ok(message=f"Registration approval lock {'enabled' if enabled else 'disabled'}.")

        if action == "admin_list_pending":
            return ok({"pending": get_db().list_pending()})

        if action in {"admin_approve_user", "admin_reject_user"}:
            nickname = str(request.get("nickname", "")).strip()
            problem = validate_nickname(nickname)
            if problem:
                return err(problem, "validation_error")
            new_status = "active" if action == "admin_approve_user" else "rejected"
            success, message, uid = get_db().set_user_status(session.user_id, nickname, new_status)
            audit_log(event="admin_user_status", action=action, ip=ip, actor_nickname=session.nickname, target_user=nickname, status="success" if success else "fail", details=message)
            return ok(message=message) if success else err(message, "status_failed")

        if action == "admin_rep":
            nickname = str(request.get("nickname", "")).strip()
            problem = validate_nickname(nickname)
            if problem:
                return err(problem, "validation_error")
            try:
                delta = float(request.get("delta"))
            except Exception:
                return err("delta must be a number.", "validation_error")
            if not math.isfinite(delta) or abs(delta) > 1_000_000:
                return err("delta out of range.", "validation_error")
            success, message, _ = get_db().admin_adjust_reputation(session.user_id, nickname, delta)
            audit_log(event="admin_rep", action=action, ip=ip, actor_nickname=session.nickname, target_user=nickname, status="success" if success else "fail", details=message)
            return ok(message=message) if success else err(message, "rep_failed")

        if action == "admin_list_flags":
            include_resolved, _ = parse_bool_field(request.get("include_resolved", False), "include_resolved")
            return ok({"flags": get_db().list_flags(bool(include_resolved))})

        if action == "admin_resolve_flag":
            try:
                flag_id = int(request.get("flag_id"))
            except Exception:
                return err("Invalid flag id.", "validation_error")
            done = get_db().resolve_flag(flag_id)
            return ok(message="Flag resolved.") if done else err("Flag not found.", "not_found")

        if action == "admin_list_frozen_ratings":
            return ok({"frozen_ratings": get_db().list_frozen_ratings()})

        if action == "admin_resolve_rating":
            try:
                rater_id = int(request.get("rater_id"))
                target_id = int(request.get("target_id"))
                job_id = int(request.get("job_id"))
            except Exception:
                return err("rater_id, target_id and job_id are required.", "validation_error")
            apply_it, bool_problem = parse_bool_field(request.get("apply"), "apply")
            if bool_problem:
                return err(bool_problem, "validation_error")
            success, message = get_db().resolve_frozen_rating(session.user_id, rater_id, target_id, job_id, bool(apply_it))
            audit_log(event="admin_resolve_rating", action=action, ip=ip, actor_nickname=session.nickname, status="success" if success else "fail", details=message)
            return ok(message=message) if success else err(message, "resolve_failed")

    return err("Unknown action.", "unknown_action")


class ClientHandler:
    def __init__(self, conn: socket.socket, addr: tuple[str, int], server: "Server") -> None:
        self.conn = conn
        self.addr = addr
        self.server = server

    def run(self) -> None:
        ip = self.addr[0]
        try:
            # Server-wide circuit breaker (protects CPU/memory). NOT a per-user
            # limit: every Tor client shares 127.0.0.1, so this only sheds load
            # when the whole server is saturated. It never penalizes a user.
            allow, retry = server_limiter.allow("server")
            if not allow:
                self._send(err("Server is saturated. Try again shortly.", "server_busy", retry))
                return
            self.conn.settimeout(READ_TIMEOUT_SECONDS)
            data = b""
            while not data.endswith(b"\n"):
                chunk = self.conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > MAX_REQUEST_LINE_BYTES:
                    self._send(err("Request too large.", "bad_request"))
                    return
            if not data:
                return
            try:
                request = json.loads(data.decode("utf-8").strip())
            except Exception:
                allow_parse, retry_parse = parse_error_limiter.allow("server")
                if not allow_parse:
                    audit_log(event="parse_error_throttled", action="invalid_json", ip=ip, status="blocked", details=f"retry_after={retry_parse}s")
                    self._send(err("Too many invalid requests.", "rate_limited", retry_parse))
                    return
                audit_log(event="request_rejected", action="invalid_json", ip=ip, status="fail")
                self._send(err("Invalid JSON.", "bad_request"))
                return
            response = handle_request(request, ip)
            self._send(response)
        except socket.timeout:
            self._send(err("Request timed out.", "timeout"))
        except Exception as exc:
            log(f"handler_error ip={ip} details={exc}")
            self._send(err("Internal server error.", "server_error"))
        finally:
            try:
                self.conn.close()
            except OSError:
                pass
            self.server.release_connection()

    def _send(self, payload: dict[str, Any]) -> None:
        try:
            self.conn.sendall(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")
        except OSError:
            pass


class Server:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
        self.stop_event = threading.Event()
        self.active_connections = 0
        self.active_connections_lock = threading.Lock()

    def try_acquire_connection(self) -> bool:
        with self.active_connections_lock:
            if self.active_connections >= MAX_CONNECTIONS:
                return False
            self.active_connections += 1
            return True

    def release_connection(self) -> None:
        with self.active_connections_lock:
            if self.active_connections > 0:
                self.active_connections -= 1

    def serve(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(MAX_CONNECTIONS)
        log(f"server_listening host={self.host} port={self.port} pow=scrypt(n={POW_SCRYPT_N},r={POW_SCRYPT_R}) base_difficulty={POW_BASE_DIFFICULTY}")
        try:
            while not self.stop_event.is_set():
                try:
                    conn, addr = self.sock.accept()
                except OSError:
                    if self.stop_event.is_set():
                        break
                    raise
                if not self.try_acquire_connection():
                    audit_log(event="connection_rejected", action="accept", ip=addr[0], status="blocked", details="max_connections_reached")
                    try:
                        conn.sendall(json.dumps(err("Server busy.", "server_busy"), separators=(",", ":")).encode("utf-8") + b"\n")
                    except OSError:
                        pass
                    try:
                        conn.close()
                    except OSError:
                        pass
                    continue
                handler = ClientHandler(conn, addr, self)
                self.executor.submit(handler.run)
        finally:
            self.stop()

    def stop(self) -> None:
        self.stop_event.set()
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        self.executor.shutdown(wait=False, cancel_futures=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AFTERLIFE server – plain TCP JSON protocol.")
    parser.add_argument("--host", default=HOST, help=f"Host/IP to bind (default: {HOST})")
    parser.add_argument("--port", type=int, default=PORT, help=f"Port to bind (default: {PORT})")
    parser.add_argument("--db", default=str(DB_PATH), help=f"SQLite database path (default: {DB_PATH})")
    parser.add_argument("--master-key", default=str(MASTER_KEY_PATH), help=f"Master key path (default: {MASTER_KEY_PATH})")
    parser.add_argument("--log", default=str(LOG_PATH), help=f"Log path (default: {LOG_PATH})")
    return parser.parse_args()


def main() -> None:
    global APP
    args = parse_args()
    db_path = Path(args.db)
    master_key_path = Path(args.master_key)
    log_path = Path(args.log)
    APP = AppContext(
        db_path=db_path,
        master_key_path=master_key_path,
        log_path=log_path,
        crypto=CryptoBox(master_key_path),
        db=Database(db_path),
    )
    server = Server(args.host, args.port)
    try:
        server.serve()
    except KeyboardInterrupt:
        log("server_interrupt received")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
