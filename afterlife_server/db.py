"""Persistence and all business rules that touch the database."""
from __future__ import annotations

import base64
import binascii
import hashlib
import math
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

from . import config as C
from .crypto import CryptoBox, DecryptionError, pbkdf2_hash, pbkdf2_verify, DUMMY_PASSWORD_HASH
from .util import audit_log, clamp_page, hamming, log, nick_skeleton, simhash64, tokenize

Result = tuple[bool, str, Any]

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nickname TEXT NOT NULL UNIQUE,
    nick_skeleton TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    reputation REAL NOT NULL DEFAULT 0.0,
    is_admin INTEGER NOT NULL DEFAULT 0,
    is_banned INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'pending')),
    invited_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    inviter_penalized INTEGER NOT NULL DEFAULT 0,
    current_key_id INTEGER,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS user_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS invites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code_hash TEXT NOT NULL UNIQUE,
    issuer_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    used_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    used_at INTEGER
);
CREATE TABLE IF NOT EXISTS rate_counters (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    hour INTEGER NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, action, hour)
);
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id INTEGER NOT NULL REFERENCES users(id),
    title_enc TEXT NOT NULL,
    description_enc TEXT NOT NULL,
    reward INTEGER NOT NULL,
    min_reputation INTEGER NOT NULL DEFAULT 0,
    is_private INTEGER NOT NULL DEFAULT 0,
    private_token_hash TEXT,
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'awaiting_confirmation', 'done', 'disputed', 'cancelled')),
    selected_worker_id INTEGER REFERENCES users(id),
    done_requested_at INTEGER,
    removed INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_list ON jobs(removed, status, created_at);
CREATE TABLE IF NOT EXISTS job_accepts (
    job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    withdrawn INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (job_id, user_id)
);
CREATE TABLE IF NOT EXISTS job_completions (
    job_id INTEGER PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
    author_id INTEGER NOT NULL,
    worker_id INTEGER NOT NULL,
    rep_gain REAL NOT NULL DEFAULT 0.0,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS job_disputes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    worker_id INTEGER NOT NULL,
    resolved INTEGER NOT NULL DEFAULT 0,
    outcome TEXT,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS reputation_ratings (
    rater_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    rating_value INTEGER NOT NULL,
    applied_delta REAL NOT NULL DEFAULT 0.0,
    state TEXT NOT NULL CHECK (state IN ('applied', 'frozen', 'discarded')),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (rater_id, target_id, job_id)
);
CREATE INDEX IF NOT EXISTS idx_ratings_target ON reputation_ratings(target_id, created_at);
CREATE INDEX IF NOT EXISTS idx_ratings_rater ON reputation_ratings(rater_id, created_at);
CREATE TABLE IF NOT EXISTS user_blocks (
    blocker_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    blocked_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (blocker_id, blocked_id)
);
CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_low_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_high_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(user_low_id, user_high_id)
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    sender_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    message_type TEXT NOT NULL CHECK (message_type IN ('system', 'e2e')),
    body TEXT NOT NULL,
    sender_key_fp TEXT,
    recipient_key_fp TEXT,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id, id);
CREATE TABLE IF NOT EXISTS message_reads (
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    read_at INTEGER NOT NULL,
    PRIMARY KEY (message_id, user_id)
);
CREATE TABLE IF NOT EXISTS threads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title_enc TEXT NOT NULL,
    body_enc TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS thread_posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id INTEGER NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    author_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    body_enc TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_posts_thread ON thread_posts(thread_id, id);
CREATE TABLE IF NOT EXISTS thread_search_terms (
    thread_id INTEGER NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    term_hmac TEXT NOT NULL,
    PRIMARY KEY (thread_id, term_hmac)
);
CREATE INDEX IF NOT EXISTS idx_search_term ON thread_search_terms(term_hmac);
CREATE TABLE IF NOT EXISTS content_fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    kind TEXT NOT NULL,
    simhash INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fp_created ON content_fingerprints(created_at);
CREATE TABLE IF NOT EXISTS moderation_flags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    nickname TEXT,
    kind TEXT NOT NULL,
    detail TEXT,
    count INTEGER NOT NULL DEFAULT 1,
    resolved INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_flags_open ON moderation_flags(resolved, kind, user_id, last_seen_at);
"""

# Severity order for the admin flag view: real abuse signals first, noisy heuristics last.
FLAG_SEVERITY = {
    "job_dispute": 0, "rating_brigade": 1, "rating_target_cap": 1, "coordinated_registration": 2,
    "cross_account_duplicate": 3, "fast_reply": 4, "unseen_thread_comment": 5, "metronomic_timing": 6,
}


def _hour(ts: Optional[float] = None) -> int:
    return int((ts if ts is not None else time.time()) // 3600)


def trust_level(rep: float, age: float, partners: int, is_admin: bool) -> int:
    if is_admin:
        return 3
    level = 0
    if age >= C.TRUST_L1_MIN_AGE and rep >= C.TRUST_L1_MIN_REP:
        level = 1
    if level >= 1 and age >= C.TRUST_L2_MIN_AGE and rep >= C.TRUST_L2_MIN_REP and partners >= C.TRUST_L2_MIN_PARTNERS:
        level = 2
    return level


def rating_weight(rater_rep: float, rater_is_admin: bool, positive: bool) -> float:
    """Reputation flows only from accounts that already hold it (admins are the
    trust seed). A rater with no reputation cannot create reputation from
    nothing, which is what made sybil rings compound."""
    if rater_is_admin:
        return 1.0
    if positive:
        return 0.0 if rater_rep <= 0 else min(1.0, rater_rep / C.RATING_WEIGHT_FULL_AT)
    if rater_rep <= 0:
        return C.NEGATIVE_RATING_MIN_WEIGHT
    return max(C.NEGATIVE_RATING_MIN_WEIGHT, min(1.0, rater_rep / C.RATING_WEIGHT_FULL_AT))


def author_grant_weight(rep: float, is_admin: bool) -> float:
    if is_admin:
        return 1.0
    return 0.0 if rep <= 0 else min(1.0, rep / C.AUTHOR_WEIGHT_FULL_AT)


def daily_job_cap(worker_rep: float, level: int) -> int:
    return 1 if level <= 0 else C.JOB_DAILY_CAP_BASE + int(max(0.0, worker_rep) // 20)


def key_fingerprint(pub: bytes) -> str:
    return hashlib.sha256(b"afterlife-x25519-v1" + pub).hexdigest()[:32]


class Database:
    def __init__(self, path: Path, crypto: CryptoBox) -> None:
        self.path = path
        self.crypto = crypto
        self.lock = threading.RLock()
        self._local = threading.local()
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.tx() as con:
            con.executescript(SCHEMA)
        self._check_crypto_canary()

    # ------------------------------------------------------------ plumbing
    def _conn(self) -> sqlite3.Connection:
        con = getattr(self._local, "con", None)
        if con is None:
            con = sqlite3.connect(self.path, check_same_thread=False, timeout=30, isolation_level="DEFERRED")
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA foreign_keys=ON")
            con.execute("PRAGMA busy_timeout=30000")
            self._local.con = con
        return con

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self.lock:
            con = self._conn()
            with con:
                yield con

    def _check_crypto_canary(self) -> None:
        """Refuse to start with the wrong master key instead of serving blanks."""
        with self.tx() as con:
            row = con.execute("SELECT value FROM settings WHERE key = 'crypto_canary'").fetchone()
            if row is None:
                con.execute("INSERT INTO settings (key, value) VALUES ('crypto_canary', ?)", (self.crypto.enc("afterlife-canary-v2"),))
                return
            try:
                ok = self.crypto.dec(row["value"]) == "afterlife-canary-v2"
            except DecryptionError:
                ok = False
            if not ok:
                raise RuntimeError("The master key does not match this database (canary check failed). Refusing to start.")

    def dec(self, value: Optional[str]) -> str:
        try:
            return self.crypto.dec(value)
        except DecryptionError:
            log("decryption_failure stored ciphertext did not decrypt; data corruption or wrong key")
            return "[undecryptable]"

    # ------------------------------------------------------------ settings
    def get_setting(self, key: str, default: str) -> str:
        with self.tx() as con:
            row = con.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
            return str(row["value"]) if row is not None else default

    def set_setting(self, key: str, value: str) -> None:
        with self.tx() as con:
            con.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))

    def registration_mode(self) -> str:
        return self.get_setting("registration_mode", C.REG_MODE_OPEN)

    def approval_required(self) -> bool:
        return self.get_setting("approval_required", "0") == "1"

    # ------------------------------------------------------------ bootstrap admin
    def ensure_bootstrap_admin(self, username: str, password_file: Path) -> None:
        """First boot only: create the admin from a one-time password FILE (never
        an environment variable), then delete the file. An existing admin is
        never modified, and an existing non-admin is never promoted."""
        with self.tx() as con:
            admin = con.execute("SELECT id FROM users WHERE is_admin = 1 LIMIT 1").fetchone()
        if admin is not None:
            if password_file.exists():
                self._consume_password_file(password_file, used=False)
            return
        if not username or not password_file.exists():
            raise RuntimeError("No admin exists. Set AFTERLIFE_BOOTSTRAP_ADMIN_USERNAME and provide the one-time password file.")
        from .util import validate_nickname, validate_password
        err = validate_nickname(username)
        if err:
            raise RuntimeError(f"Invalid bootstrap admin username: {err}")
        password = password_file.read_text(encoding="utf-8").rstrip("\n")
        if len(password) < 12 or validate_password(password):
            raise RuntimeError("Bootstrap admin password must be 12-128 printable characters.")
        with self.tx() as con:
            clash = con.execute("SELECT id FROM users WHERE nick_skeleton = ?", (nick_skeleton(username),)).fetchone()
            if clash is not None:
                raise RuntimeError("Bootstrap admin username collides with an existing account. Refusing to promote it.")
            con.execute(
                "INSERT INTO users (nickname, nick_skeleton, password_hash, is_admin, status, created_at) VALUES (?, ?, ?, 1, 'active', ?)",
                (username, nick_skeleton(username), pbkdf2_hash(password), int(time.time())),
            )
        log(f"bootstrap_admin_created nickname={username}")
        self._consume_password_file(password_file, used=True)

    @staticmethod
    def _consume_password_file(path: Path, used: bool) -> None:
        try:
            path.unlink()
            log("bootstrap_password_file_deleted" if used else "bootstrap_password_file_ignored_and_deleted admin_already_exists")
        except OSError as exc:
            log(f"WARNING could not delete bootstrap password file ({exc.__class__.__name__}); delete it manually")

    # ------------------------------------------------------------ users
    def user(self, con: sqlite3.Connection, user_id: int) -> Optional[sqlite3.Row]:
        return con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    def get_user(self, user_id: int) -> Optional[sqlite3.Row]:
        with self.tx() as con:
            return self.user(con, user_id)

    def user_by_nick(self, con: sqlite3.Connection, nickname: str) -> Optional[sqlite3.Row]:
        return con.execute("SELECT * FROM users WHERE nickname = ? COLLATE NOCASE", (nickname,)).fetchone()

    def registrations_last_hour(self) -> int:
        with self.tx() as con:
            return int(con.execute("SELECT COUNT(*) FROM users WHERE created_at >= ?", (int(time.time()) - 3600,)).fetchone()[0])

    def registration_extra_bits(self) -> int:
        """Instead of forcing over-cap signups into a queue (which let anyone
        saturate it), registration simply gets more expensive under load."""
        n = self.registrations_last_hour()
        if n < C.REGISTRATION_SOFT_CAP_PER_HOUR:
            return 0
        return min(C.REGISTRATION_EXTRA_BITS_MAX, 1 + int(math.log2(n / max(1, C.REGISTRATION_SOFT_CAP_PER_HOUR))))

    def register_user(self, nickname: str, password: str, invite_code: Optional[str], public_key: Optional[str]) -> Result:
        now = int(time.time())
        pw_hash = pbkdf2_hash(password)
        mode = self.registration_mode()
        approval = self.approval_required()
        key_info = self._parse_pubkey(public_key) if public_key else None
        if public_key and key_info is None:
            return False, "Invalid public key.", {}
        with self.tx() as con:
            if con.execute("SELECT 1 FROM users WHERE nick_skeleton = ?", (nick_skeleton(nickname),)).fetchone():
                return False, "Nickname is unavailable (taken or too similar to an existing one).", {}
            if key_info is not None and con.execute("SELECT 1 FROM user_keys WHERE fingerprint = ?", (key_info[1],)).fetchone():
                return False, "That public key is already registered.", {}
            if int(con.execute("SELECT COUNT(*) FROM users WHERE created_at >= ?", (now - 3600,)).fetchone()[0]) >= C.REGISTRATION_HARD_CAP_PER_HOUR:
                return False, "Registration is temporarily saturated. Try again later.", {"retry_after": 600}
            invite = None
            if invite_code:
                invite = con.execute("SELECT * FROM invites WHERE code_hash = ?", (self.crypto.token_digest(invite_code),)).fetchone()
                if invite is None or invite["revoked"] or invite["used_by"] is not None:
                    return False, "Invite code is invalid, already used, or revoked.", {}
                if now - int(invite["created_at"]) > C.INVITE_TTL_SECONDS:
                    return False, "Invite code has expired.", {}
                issuer = self.user(con, int(invite["issuer_id"])) if invite["issuer_id"] is not None else None
                if issuer is None or issuer["is_banned"]:
                    return False, "Invite code is no longer valid.", {}
            if mode == C.REG_MODE_CLOSED and invite is None:
                return False, "Registration is closed. An invite code is required.", {}
            if mode == C.REG_MODE_INVITE and invite is None:
                return False, "Registration is invite-only. Provide a valid invite code.", {}
            status = "active"
            if approval:
                queued = int(con.execute("SELECT COUNT(*) FROM users WHERE status = 'pending'").fetchone()[0])
                if queued >= C.PENDING_QUEUE_MAX:
                    return False, "The approval queue is full. Try again later.", {"retry_after": 3600}
                status = "pending"
            invited_by = int(invite["issuer_id"]) if invite is not None else None
            cur = con.execute(
                "INSERT INTO users (nickname, nick_skeleton, password_hash, status, invited_by, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (nickname, nick_skeleton(nickname), pw_hash, status, invited_by, now),
            )
            uid = int(cur.lastrowid)
            if key_info is not None:
                self._store_key(con, uid, *key_info, now)
            if invite is not None:
                con.execute("UPDATE invites SET used_by = ?, used_at = ? WHERE id = ?", (uid, now, int(invite["id"])))
                recent = int(con.execute("SELECT COUNT(*) FROM users WHERE invited_by = ? AND created_at >= ?",
                                         (invited_by, now - C.COORD_REGISTRATION_WINDOW)).fetchone()[0])
                if recent >= 3:
                    self.add_flag(con, invited_by, None, "coordinated_registration", f"{recent} invitees registered within {C.COORD_REGISTRATION_WINDOW}s")
            pending = status == "pending"
            msg = "Registration received. An administrator must approve your account before you can log in." if pending else "User created."
            return True, msg, {"pending": pending}

    def authenticate(self, nickname: str, password: str) -> tuple[Optional[sqlite3.Row], str]:
        """The password is ALWAYS verified first (against a dummy hash when the
        user does not exist), so account state is never revealed without it."""
        with self.tx() as con:
            row = self.user_by_nick(con, nickname)
        ok = pbkdf2_verify(password, row["password_hash"] if row is not None else DUMMY_PASSWORD_HASH)
        if row is None or not ok:
            return None, "invalid"
        if row["is_banned"]:
            return None, "banned"
        if row["status"] == "pending":
            return None, "pending"
        return row, "ok"

    def change_password(self, user_id: int, old: str, new: str) -> Result:
        with self.tx() as con:
            row = self.user(con, user_id)
        if row is None or not pbkdf2_verify(old, row["password_hash"]):
            return False, "Current password is incorrect.", None
        new_hash = pbkdf2_hash(new)
        with self.tx() as con:
            con.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
        return True, "Password changed. Other sessions were signed out.", None

    # ------------------------------------------------------------ trust / quotas
    def distinct_partners(self, con: sqlite3.Connection, user_id: int) -> int:
        row = con.execute(
            "SELECT COUNT(DISTINCT CASE WHEN worker_id = ? THEN author_id ELSE worker_id END) "
            "FROM job_completions WHERE (worker_id = ? OR author_id = ?) AND rep_gain > 0",
            (user_id, user_id, user_id)).fetchone()
        return int(row[0] or 0)

    def trust_context(self, con: sqlite3.Connection, user: sqlite3.Row) -> dict[str, Any]:
        rep = float(user["reputation"])
        age = max(0, int(time.time()) - int(user["created_at"]))
        partners = self.distinct_partners(con, int(user["id"]))
        return {"reputation": rep, "age": age, "partners": partners, "is_admin": bool(user["is_admin"]),
                "level": trust_level(rep, age, partners, bool(user["is_admin"]))}

    def _used_24h(self, con: sqlite3.Connection, user_id: int, action: str) -> int:
        row = con.execute("SELECT COALESCE(SUM(count), 0) FROM rate_counters WHERE user_id = ? AND action = ? AND hour > ?",
                          (user_id, action, _hour() - 24)).fetchone()
        return int(row[0])

    def _write_block_reason(self, con: sqlite3.Connection, user: sqlite3.Row, action: str) -> Optional[str]:
        """Rolling 24h quotas (not calendar days, so no midnight double burst)."""
        ctx = self.trust_context(con, user)
        if not ctx["is_admin"] and ctx["age"] < C.READONLY_WINDOW:
            hours = max(1, (C.READONLY_WINDOW - ctx["age"]) // 3600)
            return f"New accounts are read-only for the first {C.READONLY_WINDOW // 3600}h (~{hours}h left)."
        quota = C.DAILY_QUOTAS.get(ctx["level"], C.DAILY_QUOTAS[0]).get(action)
        if quota is not None and self._used_24h(con, int(user["id"]), action) >= quota:
            return f"Limit reached for this action (trust level {ctx['level']}: {quota} per 24h). Try again later."
        return None

    def precheck_write(self, user_id: int, action: str) -> Optional[str]:
        """Read-only check used BEFORE asking the client for proof-of-work."""
        with self.tx() as con:
            user = self.user(con, user_id)
            if user is None or user["is_banned"]:
                return "Not allowed."
            if action in ("create_thread", "post_comment") and float(user["reputation"]) <= C.NEGATIVE_REP_POST_THRESHOLD:
                return f"Users with reputation of {C.NEGATIVE_REP_POST_THRESHOLD:g} or below cannot post or comment."
            return self._write_block_reason(con, user, action)

    def _consume_quota(self, con: sqlite3.Connection, user: sqlite3.Row, action: str) -> Optional[str]:
        reason = self._write_block_reason(con, user, action)
        if reason:
            return reason
        con.execute("INSERT INTO rate_counters (user_id, action, hour, count) VALUES (?, ?, ?, 1) "
                    "ON CONFLICT(user_id, action, hour) DO UPDATE SET count = count + 1", (int(user["id"]), action, _hour()))
        return None

    # ------------------------------------------------------------ moderation flags
    def add_flag(self, con: sqlite3.Connection, user_id: Optional[int], nickname: Optional[str], kind: str, detail: str) -> None:
        """Deduplicated: repeated signals of the same kind for the same user bump
        a counter on the open flag instead of inserting rows, so one actor can
        never bury other users' flags."""
        now = int(time.time())
        existing = con.execute(
            "SELECT id FROM moderation_flags WHERE resolved = 0 AND kind = ? AND user_id IS ? AND last_seen_at >= ? ORDER BY id DESC LIMIT 1",
            (kind, user_id, now - C.FLAG_DEDUPE_SECONDS)).fetchone()
        if existing is not None:
            con.execute("UPDATE moderation_flags SET count = count + 1, last_seen_at = ?, detail = ? WHERE id = ?",
                        (now, detail[:400], int(existing["id"])))
            return
        con.execute("INSERT INTO moderation_flags (user_id, nickname, kind, detail, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (user_id, nickname, kind, detail[:400], now, now))
        audit_log("moderation_flag", target=nickname or (f"user {user_id}" if user_id else None), status="warn", details=kind)

    def flag(self, user_id: Optional[int], nickname: Optional[str], kind: str, detail: str) -> None:
        with self.tx() as con:
            self.add_flag(con, user_id, nickname, kind, detail)

    def list_flags(self, include_resolved: bool, kind: Optional[str], page: int) -> tuple[list[dict[str, Any]], int, int]:
        where = [] if include_resolved else ["f.resolved = 0"]
        params: list[Any] = []
        if kind:
            where.append("f.kind = ?")
            params.append(kind)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        order = "CASE f.kind " + " ".join(f"WHEN '{k}' THEN {v}" for k, v in FLAG_SEVERITY.items()) + " ELSE 9 END"
        with self.tx() as con:
            total = int(con.execute(f"SELECT COUNT(*) FROM moderation_flags f {clause}", params).fetchone()[0])
            page, offset = clamp_page(total, page, C.ADMIN_PAGE_SIZE)
            rows = con.execute(
                f"SELECT f.*, u.nickname AS unick FROM moderation_flags f LEFT JOIN users u ON u.id = f.user_id {clause} "
                f"ORDER BY f.resolved ASC, {order} ASC, f.last_seen_at DESC LIMIT ? OFFSET ?",
                params + [C.ADMIN_PAGE_SIZE, offset]).fetchall()
        return [{"id": int(r["id"]), "user_id": r["user_id"], "nickname": r["nickname"] or r["unick"], "kind": str(r["kind"]),
                 "detail": str(r["detail"] or ""), "count": int(r["count"]), "resolved": bool(r["resolved"]),
                 "created_at": int(r["created_at"]), "last_seen_at": int(r["last_seen_at"])} for r in rows], total, page

    def resolve_flag(self, flag_id: int) -> bool:
        with self.tx() as con:
            return con.execute("UPDATE moderation_flags SET resolved = 1 WHERE id = ?", (flag_id,)).rowcount > 0

    # ------------------------------------------------------------ admin: pending
    def list_pending(self, page: int) -> tuple[list[dict[str, Any]], int, int]:
        with self.tx() as con:
            total = int(con.execute("SELECT COUNT(*) FROM users WHERE status = 'pending'").fetchone()[0])
            page, offset = clamp_page(total, page, C.ADMIN_PAGE_SIZE)
            rows = con.execute(
                "SELECT u.nickname, u.created_at, i.nickname AS inviter FROM users u LEFT JOIN users i ON i.id = u.invited_by "
                "WHERE u.status = 'pending' ORDER BY u.created_at ASC LIMIT ? OFFSET ?", (C.ADMIN_PAGE_SIZE, offset)).fetchall()
        return [{"nickname": str(r["nickname"]), "created_at": int(r["created_at"]), "invited_by": r["inviter"]} for r in rows], total, page

    def set_pending_status(self, nickname: str, approve: bool) -> Result:
        """Approve -> active. Reject -> the pending row is deleted, which frees the
        nickname (no permanent squatting). Pending accounts own no content."""
        with self.tx() as con:
            target = self.user_by_nick(con, nickname)
            if target is None:
                return False, "User not found.", None
            if target["status"] != "pending":
                return False, "User is not awaiting approval.", None
            if approve:
                con.execute("UPDATE users SET status = 'active' WHERE id = ?", (int(target["id"]),))
                return True, "User approved.", int(target["id"])
            con.execute("UPDATE invites SET used_by = NULL, used_at = NULL, revoked = 1 WHERE used_by = ?", (int(target["id"]),))
            con.execute("DELETE FROM users WHERE id = ?", (int(target["id"]),))
            return True, "Registration rejected; nickname released.", None

    # ------------------------------------------------------------ invites
    def create_invite(self, issuer_id: int) -> Result:
        now = int(time.time())
        with self.tx() as con:
            issuer = self.user(con, issuer_id)
            if issuer is None or issuer["is_banned"] or issuer["status"] != "active":
                return False, "Not allowed.", None
            ctx = self.trust_context(con, issuer)
            if not ctx["is_admin"]:
                if ctx["level"] < C.INVITE_MIN_TRUST_LEVEL:
                    return False, f"You need trust level {C.INVITE_MIN_TRUST_LEVEL} to issue invites.", None
                outstanding = int(con.execute("SELECT COUNT(*) FROM invites WHERE issuer_id = ? AND used_by IS NULL AND revoked = 0 AND created_at >= ?",
                                              (issuer_id, now - C.INVITE_TTL_SECONDS)).fetchone()[0])
                if outstanding >= C.INVITE_MAX_OUTSTANDING:
                    return False, f"You already have {C.INVITE_MAX_OUTSTANDING} unused invites outstanding.", None
                issued_30d = int(con.execute("SELECT COUNT(*) FROM invites WHERE issuer_id = ? AND created_at >= ?",
                                             (issuer_id, now - 30 * 86400)).fetchone()[0])
                if issued_30d >= C.INVITE_MAX_PER_30_DAYS:
                    return False, f"Invite limit reached ({C.INVITE_MAX_PER_30_DAYS} per 30 days).", None
            code = secrets.token_urlsafe(24)
            con.execute("INSERT INTO invites (code_hash, issuer_id, created_at) VALUES (?, ?, ?)", (self.crypto.token_digest(code), issuer_id, now))
            return True, "Invite created. Store it securely — it is shown only once.", code

    def list_invites(self, issuer_id: int) -> list[dict[str, Any]]:
        now = int(time.time())
        with self.tx() as con:
            rows = con.execute("SELECT i.id, i.revoked, i.created_at, u.nickname AS used_nick FROM invites i "
                               "LEFT JOIN users u ON u.id = i.used_by WHERE i.issuer_id = ? ORDER BY i.created_at DESC LIMIT 100",
                               (issuer_id,)).fetchall()
        out = []
        for r in rows:
            if r["revoked"]:
                state = "revoked"
            elif r["used_nick"] is not None:
                state = f"used by {r['used_nick']}"
            elif now - int(r["created_at"]) > C.INVITE_TTL_SECONDS:
                state = "expired"
            else:
                state = "unused"
            out.append({"id": int(r["id"]), "state": state, "created_at": int(r["created_at"])})
        return out

    def revoke_invite(self, issuer_id: int, invite_id: int, is_admin: bool) -> Result:
        with self.tx() as con:
            q = "SELECT id, used_by FROM invites WHERE id = ?" + ("" if is_admin else " AND issuer_id = ?")
            row = con.execute(q, (invite_id,) if is_admin else (invite_id, issuer_id)).fetchone()
            if row is None:
                return False, "Invite not found.", None
            if row["used_by"] is not None:
                return False, "Invite has already been used.", None
            con.execute("UPDATE invites SET revoked = 1 WHERE id = ?", (invite_id,))
            return True, "Invite revoked.", None

    def _penalize_inviter_once(self, con: sqlite3.Connection, banned: sqlite3.Row) -> None:
        if banned["invited_by"] is None or banned["inviter_penalized"]:
            return
        con.execute("UPDATE users SET inviter_penalized = 1 WHERE id = ?", (int(banned["id"]),))
        inviter = self.user(con, int(banned["invited_by"]))
        if inviter is None or inviter["is_admin"]:
            return
        con.execute("UPDATE users SET reputation = reputation - ? WHERE id = ?", (C.INVITE_BAN_PENALTY, int(inviter["id"])))
        con.execute("UPDATE invites SET revoked = 1 WHERE issuer_id = ? AND used_by IS NULL AND revoked = 0", (int(inviter["id"]),))

    # ------------------------------------------------------------ blocks
    def block_exists(self, con: sqlite3.Connection, a: int, b: int) -> bool:
        return con.execute("SELECT 1 FROM user_blocks WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?) LIMIT 1",
                           (a, b, b, a)).fetchone() is not None

    def set_block(self, blocker_id: int, nickname: str, block: bool) -> Result:
        with self.tx() as con:
            target = self.user_by_nick(con, nickname)
            if target is None or target["status"] != "active":
                return False, "User not found.", None
            tid = int(target["id"])
            if tid == blocker_id:
                return False, "You cannot block yourself.", None
            if target["is_admin"]:
                return False, "Admins cannot be blocked.", None
            if block:
                try:
                    con.execute("INSERT INTO user_blocks (blocker_id, blocked_id, created_at) VALUES (?, ?, ?)", (blocker_id, tid, int(time.time())))
                except sqlite3.IntegrityError:
                    return False, "User is already blocked.", None
                return True, "User blocked.", tid
            if con.execute("DELETE FROM user_blocks WHERE blocker_id = ? AND blocked_id = ?", (blocker_id, tid)).rowcount == 0:
                return False, "User was not blocked.", None
            return True, "User unblocked.", tid

    def list_blocks(self, user_id: int) -> list[dict[str, Any]]:
        with self.tx() as con:
            rows = con.execute("SELECT u.nickname, u.reputation FROM user_blocks b JOIN users u ON u.id = b.blocked_id "
                               "WHERE b.blocker_id = ? ORDER BY u.nickname LIMIT 500", (user_id,)).fetchall()
        return [{"nickname": str(r["nickname"]), "reputation": round(float(r["reputation"]), 3)} for r in rows]

    # ------------------------------------------------------------ jobs
    def create_job(self, author_id: int, title: str, description: str, reward: int, min_rep: int, is_private: bool) -> Result:
        now = int(time.time())
        token = secrets.token_urlsafe(18) if is_private else ""
        with self.tx() as con:
            author = self.user(con, author_id)
            if author is None or author["is_banned"]:
                return False, "Not allowed.", {}
            reason = self._consume_quota(con, author, "create_job")
            if reason:
                return False, reason, {}
            effective_min = min(int(min_rep), int(math.floor(float(author["reputation"])))) if not author["is_admin"] else int(min_rep)
            cur = con.execute(
                "INSERT INTO jobs (author_id, title_enc, description_enc, reward, min_reputation, is_private, private_token_hash, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (author_id, self.crypto.enc(title), self.crypto.enc(description), reward, effective_min, int(is_private),
                 self.crypto.token_digest(token) if is_private else None, now, now))
            return True, "Job created.", {"job_id": int(cur.lastrowid), "private_token": token, "min_reputation": effective_min}

    def _job_public(self, row: sqlite3.Row, viewer: Optional[sqlite3.Row]) -> dict[str, Any]:
        banned = bool(row["author_is_banned"]) if "author_is_banned" in row.keys() else False
        nick = str(row["author_nickname"]) if "author_nickname" in row.keys() else ""
        viewer_rep = round(float(viewer["reputation"]), 3) if viewer is not None else None
        min_rep = int(row["min_reputation"])
        return {
            "id": int(row["id"]), "title": self.dec(row["title_enc"]), "reward": int(row["reward"]), "min_reputation": min_rep,
            "is_private": bool(row["is_private"]), "status": str(row["status"]), "author_id": int(row["author_id"]),
            "author_nickname": nick, "author_is_banned": banned, "author_display": f"{C.BAN_LABEL} {nick}" if banned else nick,
            "accept_count": int(row["accept_count"]) if "accept_count" in row.keys() else 0,
            "created_at": int(row["created_at"]), "updated_at": int(row["updated_at"]),
            "viewer_reputation": viewer_rep,
            "not_enough_reputation": viewer is not None and viewer_rep is not None and viewer_rep < min_rep and int(viewer["id"]) != int(row["author_id"]),
        }

    _ACCEPT_COUNT = "(SELECT COUNT(*) FROM job_accepts a WHERE a.job_id = j.id AND a.withdrawn = 0) AS accept_count"

    def list_jobs(self, viewer_id: int, status: Optional[str], page: int) -> tuple[list[dict[str, Any]], int, int]:
        where = ["j.removed = 0",
                 "NOT EXISTS (SELECT 1 FROM user_blocks b WHERE (b.blocker_id = ? AND b.blocked_id = j.author_id) OR (b.blocker_id = j.author_id AND b.blocked_id = ?))"]
        params: list[Any] = [viewer_id, viewer_id]
        if status:
            where.append("j.status = ?")
            params.append(status)
        fw = "FROM jobs j JOIN users u ON u.id = j.author_id WHERE " + " AND ".join(where)
        with self.tx() as con:
            total = int(con.execute("SELECT COUNT(*) " + fw, params).fetchone()[0])
            page, offset = clamp_page(total, page, C.PAGE_SIZE)
            rows = con.execute(f"SELECT j.*, u.nickname AS author_nickname, u.is_banned AS author_is_banned, {self._ACCEPT_COUNT} "
                               + fw + " ORDER BY j.created_at DESC, j.id DESC LIMIT ? OFFSET ?", params + [C.PAGE_SIZE, offset]).fetchall()
            viewer = self.user(con, viewer_id)
            return [self._job_public(r, viewer) for r in rows], total, page

    def my_jobs(self, user_id: int, accepted: bool, page: int) -> tuple[list[dict[str, Any]], int, int]:
        if accepted:
            fw = ("FROM jobs j JOIN job_accepts ja ON ja.job_id = j.id JOIN users u ON u.id = j.author_id "
                  "WHERE ja.user_id = ? AND ja.withdrawn = 0 AND j.removed = 0")
        else:
            fw = "FROM jobs j JOIN users u ON u.id = j.author_id WHERE j.author_id = ? AND j.removed = 0"
        with self.tx() as con:
            total = int(con.execute("SELECT COUNT(*) " + fw, (user_id,)).fetchone()[0])
            page, offset = clamp_page(total, page, C.PAGE_SIZE)
            rows = con.execute(f"SELECT j.*, u.nickname AS author_nickname, u.is_banned AS author_is_banned, {self._ACCEPT_COUNT} "
                               + fw + " ORDER BY j.updated_at DESC LIMIT ? OFFSET ?", (user_id, C.PAGE_SIZE, offset)).fetchall()
            viewer = self.user(con, user_id)
            items = []
            for r in rows:
                d = self._job_public(r, viewer)
                d["selected_worker_id"] = r["selected_worker_id"]
                d["you_are_selected"] = r["selected_worker_id"] == user_id
                items.append(d)
            return items, total, page

    def job_for_viewer(self, job_id: int, viewer_id: int, unlock_token: Optional[str]) -> Result:
        with self.tx() as con:
            row = con.execute("SELECT j.*, u.nickname AS author_nickname, u.is_banned AS author_is_banned, " + self._ACCEPT_COUNT +
                              " FROM jobs j JOIN users u ON u.id = j.author_id WHERE j.id = ? AND j.removed = 0", (job_id,)).fetchone()
            if row is None:
                return False, "Job not found.", None
            viewer = self.user(con, viewer_id)
            is_admin = bool(viewer is not None and viewer["is_admin"])
            is_author = int(row["author_id"]) == viewer_id
            if not is_author and not is_admin and self.block_exists(con, viewer_id, int(row["author_id"])):
                return False, "Job not found.", None
            data = self._job_public(row, viewer)
            visible = (not row["is_private"]) or is_admin or is_author or (
                bool(unlock_token) and row["private_token_hash"] is not None
                and secrets.compare_digest(self.crypto.token_digest(unlock_token), str(row["private_token_hash"])))
            data["description_visible"] = visible
            data["description"] = self.dec(row["description_enc"]) if visible else None
            acc = con.execute("SELECT withdrawn FROM job_accepts WHERE job_id = ? AND user_id = ?", (job_id, viewer_id)).fetchone()
            data["viewer_has_accepted"] = acc is not None and not acc["withdrawn"]
            data["viewer_has_withdrawn"] = acc is not None and bool(acc["withdrawn"])
            data["viewer_is_selected"] = row["selected_worker_id"] == viewer_id
            if is_author or is_admin:
                workers = con.execute("SELECT u.id, u.nickname, u.reputation, u.is_banned FROM job_accepts a JOIN users u ON u.id = a.user_id "
                                      "WHERE a.job_id = ? AND a.withdrawn = 0 ORDER BY a.created_at LIMIT 200", (job_id,)).fetchall()
                data["worker_pool"] = [{"id": int(w["id"]), "nickname": str(w["nickname"]), "reputation": round(float(w["reputation"]), 3),
                                        "is_banned": bool(w["is_banned"])} for w in workers]
            else:
                data["worker_pool"] = None
            data.update({"is_author": is_author, "is_admin": is_admin, "selected_worker_id": row["selected_worker_id"],
                         "done_requested_at": row["done_requested_at"]})
            return True, "OK", data

    def accept_job(self, job_id: int, user_id: int, private_token: Optional[str]) -> Result:
        with self.tx() as con:
            job = con.execute("SELECT * FROM jobs WHERE id = ? AND removed = 0", (job_id,)).fetchone()
            user = self.user(con, user_id)
            if job is None or user is None:
                return False, "Job not found.", None
            if user["is_banned"]:
                return False, "Not allowed.", None
            if job["status"] != "open":
                return False, "Job is not open.", None
            if int(job["author_id"]) == user_id:
                return False, "Author cannot accept own job.", None
            if self.block_exists(con, user_id, int(job["author_id"])):
                return False, "Not allowed.", None
            if float(user["reputation"]) < float(job["min_reputation"]):
                return False, "Not enough reputation.", None
            if job["is_private"]:
                if not private_token or not secrets.compare_digest(self.crypto.token_digest(private_token), str(job["private_token_hash"])):
                    return False, "Invalid private token.", None
            prior = con.execute("SELECT withdrawn FROM job_accepts WHERE job_id = ? AND user_id = ?", (job_id, user_id)).fetchone()
            if prior is not None:
                return False, "You already accepted this job." if not prior["withdrawn"] else "You withdrew from this job and cannot accept it again.", None
            reason = self._consume_quota(con, user, "accept_job")
            if reason:
                return False, reason, None
            con.execute("INSERT INTO job_accepts (job_id, user_id, created_at) VALUES (?, ?, ?)", (job_id, user_id, int(time.time())))
            chat_id = self.ensure_chat(con, int(job["author_id"]), user_id)
            self.system_message(con, chat_id, f"{user['nickname']} accepted your job #{job_id}: {self.dec(job['title_enc'])}")
            return True, "Job accepted.", None

    def withdraw_accept(self, job_id: int, user_id: int) -> Result:
        with self.tx() as con:
            job = con.execute("SELECT status, selected_worker_id FROM jobs WHERE id = ? AND removed = 0", (job_id,)).fetchone()
            if job is None:
                return False, "Job not found.", None
            if job["status"] != "open":
                return False, "Cannot withdraw from a job that is not open.", None
            if job["selected_worker_id"] == user_id:
                return False, "Selected worker cannot withdraw unless the author changes selection first.", None
            if con.execute("UPDATE job_accepts SET withdrawn = 1 WHERE job_id = ? AND user_id = ? AND withdrawn = 0", (job_id, user_id)).rowcount == 0:
                return False, "You had not accepted this job.", None
            return True, "Acceptance withdrawn. You cannot accept this job again.", None

    def select_worker(self, job_id: int, actor_id: int, worker_id: int) -> Result:
        with self.tx() as con:
            job = con.execute("SELECT * FROM jobs WHERE id = ? AND removed = 0", (job_id,)).fetchone()
            actor = self.user(con, actor_id)
            if job is None or actor is None:
                return False, "Job not found.", None
            if actor_id != int(job["author_id"]) and not actor["is_admin"]:
                return False, "Not allowed.", None
            if job["status"] != "open":
                return False, "A worker can only be selected while the job is open.", None
            if con.execute("SELECT 1 FROM job_accepts WHERE job_id = ? AND user_id = ? AND withdrawn = 0", (job_id, worker_id)).fetchone() is None:
                return False, "Worker is not in the pool.", None
            worker = self.user(con, worker_id)
            if worker is None or worker["is_banned"]:
                return False, "Worker is banned.", None
            if self.block_exists(con, int(job["author_id"]), worker_id):
                return False, "Not allowed.", None
            con.execute("UPDATE jobs SET selected_worker_id = ?, updated_at = ? WHERE id = ?", (worker_id, int(time.time()), job_id))
            self.system_message(con, self.ensure_chat(con, int(job["author_id"]), worker_id), f"You were selected as the worker for job #{job_id}.")
            return True, "Selected worker updated.", worker_id

    def set_job_status(self, job_id: int, actor_id: int, new_status: str) -> Result:
        """Author/admin transitions. Marking done only REQUESTS completion; the
        worker must confirm (or dispute) before reputation or ratings unlock."""
        now = int(time.time())
        with self.tx() as con:
            job = con.execute("SELECT * FROM jobs WHERE id = ? AND removed = 0", (job_id,)).fetchone()
            actor = self.user(con, actor_id)
            if job is None or actor is None:
                return False, "Job not found.", None
            if actor_id != int(job["author_id"]) and not actor["is_admin"]:
                return False, "Not allowed.", None
            cur = str(job["status"])
            allowed = {
                "done": {"open"},                                   # -> awaiting_confirmation
                "cancelled": {"open", "awaiting_confirmation"},
                "open": {"cancelled", "awaiting_confirmation"},
            }
            if new_status not in allowed:
                return False, "Invalid status. Use done, cancelled or open.", None
            if cur not in allowed[new_status]:
                return False, f"Cannot change a job from '{cur}' to '{new_status}'.", None
            if new_status == "done":
                worker_id = job["selected_worker_id"]
                if not worker_id:
                    return False, "Select a worker before marking as done.", None
                con.execute("UPDATE jobs SET status = 'awaiting_confirmation', done_requested_at = ?, updated_at = ? WHERE id = ?", (now, now, job_id))
                self.system_message(con, self.ensure_chat(con, int(job["author_id"]), int(worker_id)),
                                    f"Job #{job_id} was marked done by the author. Please confirm or dispute it (job details).")
                return True, "Completion requested. The worker must confirm before it counts.", None
            con.execute("UPDATE jobs SET status = ?, done_requested_at = NULL, updated_at = ? WHERE id = ?", (new_status, now, job_id))
            return True, f"Job status set to {new_status}.", None

    def worker_confirm(self, job_id: int, worker_id: int, confirm: bool) -> Result:
        now = int(time.time())
        with self.tx() as con:
            job = con.execute("SELECT * FROM jobs WHERE id = ? AND removed = 0", (job_id,)).fetchone()
            if job is None or job["selected_worker_id"] != worker_id:
                return False, "Job not found.", None
            if job["status"] != "awaiting_confirmation":
                return False, "This job is not awaiting your confirmation.", None
            chat_id = self.ensure_chat(con, int(job["author_id"]), worker_id)
            if confirm:
                con.execute("UPDATE jobs SET status = 'done', updated_at = ? WHERE id = ?", (now, job_id))
                gain = self._grant_completion(con, job)
                self.system_message(con, chat_id, f"Job #{job_id} completion was confirmed by the worker.")
                return True, f"Completion confirmed. You earned {gain:.3f} reputation.", None
            con.execute("UPDATE jobs SET status = 'disputed', updated_at = ? WHERE id = ?", (now, job_id))
            con.execute("INSERT INTO job_disputes (job_id, worker_id, created_at) VALUES (?, ?, ?)", (job_id, worker_id, now))
            worker = self.user(con, worker_id)
            self.add_flag(con, worker_id, str(worker["nickname"]) if worker else None, "job_dispute", f"worker disputed completion of job {job_id}")
            self.system_message(con, chat_id, f"Job #{job_id} completion was disputed by the worker. An administrator will review it.")
            return True, "Dispute opened. An administrator will review it.", None

    def list_disputes(self, page: int) -> tuple[list[dict[str, Any]], int, int]:
        with self.tx() as con:
            total = int(con.execute("SELECT COUNT(*) FROM job_disputes WHERE resolved = 0").fetchone()[0])
            page, offset = clamp_page(total, page, C.ADMIN_PAGE_SIZE)
            rows = con.execute("SELECT d.job_id, d.created_at, w.nickname AS worker, a.nickname AS author FROM job_disputes d "
                               "JOIN jobs j ON j.id = d.job_id JOIN users w ON w.id = d.worker_id JOIN users a ON a.id = j.author_id "
                               "WHERE d.resolved = 0 ORDER BY d.created_at LIMIT ? OFFSET ?", (C.ADMIN_PAGE_SIZE, offset)).fetchall()
        return [{"job_id": int(r["job_id"]), "worker": r["worker"], "author": r["author"], "created_at": int(r["created_at"])} for r in rows], total, page

    def resolve_dispute(self, job_id: int, outcome: str) -> Result:
        if outcome not in {"done", "open", "cancelled"}:
            return False, "Outcome must be done, open or cancelled.", None
        now = int(time.time())
        with self.tx() as con:
            job = con.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if job is None or job["status"] != "disputed":
                return False, "No open dispute for this job.", None
            con.execute("UPDATE job_disputes SET resolved = 1, outcome = ? WHERE job_id = ? AND resolved = 0", (outcome, job_id))
            con.execute("UPDATE jobs SET status = ?, done_requested_at = NULL, updated_at = ? WHERE id = ?", (outcome, now, job_id))
            msg = f"Dispute resolved: job set to {outcome}."
            if outcome == "done":
                msg += f" Worker earned {self._grant_completion(con, job):.3f} reputation."
            return True, msg, None

    def auto_confirm_stale(self) -> int:
        """A worker who never answers cannot hold the author hostage forever:
        after the confirmation window the job completes automatically."""
        cutoff = int(time.time()) - C.JOB_CONFIRM_TIMEOUT_SECONDS
        n = 0
        with self.tx() as con:
            for job in con.execute("SELECT * FROM jobs WHERE status = 'awaiting_confirmation' AND done_requested_at < ? LIMIT 200", (cutoff,)).fetchall():
                con.execute("UPDATE jobs SET status = 'done', updated_at = ? WHERE id = ?", (int(time.time()), int(job["id"])))
                self._grant_completion(con, job)
                n += 1
        return n

    def _grant_completion(self, con: sqlite3.Connection, job: sqlite3.Row) -> float:
        now = int(time.time())
        job_id, author_id, worker_id = int(job["id"]), int(job["author_id"]), int(job["selected_worker_id"])

        def record(gain: float) -> float:
            con.execute("INSERT OR IGNORE INTO job_completions (job_id, author_id, worker_id, rep_gain, created_at) VALUES (?, ?, ?, ?, ?)",
                        (job_id, author_id, worker_id, gain, now))
            if gain > 0:
                con.execute("UPDATE users SET reputation = reputation + ? WHERE id = ?", (gain, worker_id))
            return gain

        author, worker = self.user(con, author_id), self.user(con, worker_id)
        if author is None or worker is None or worker["is_banned"]:
            return record(0.0)
        # A job opened and "completed" moments later earns nothing.
        if int(job["done_requested_at"] or now) - int(job["created_at"]) < C.JOB_MIN_AGE_FOR_REP_SECONDS:
            return record(0.0)
        aw = author_grant_weight(float(author["reputation"]), bool(author["is_admin"]))
        if aw <= 0:
            return record(0.0)
        granted = float(con.execute("SELECT COALESCE(SUM(rep_gain), 0) FROM job_completions WHERE author_id = ? AND created_at >= ?",
                                    (author_id, now - 86400)).fetchone()[0])
        if granted >= C.AUTHOR_GRANT_DAILY_CAP:
            return record(0.0)
        w_ctx = self.trust_context(con, worker)
        n_today = int(con.execute("SELECT COUNT(*) FROM job_completions WHERE worker_id = ? AND rep_gain > 0 AND created_at >= ?",
                                  (worker_id, now - 86400)).fetchone()[0])
        if n_today >= daily_job_cap(float(worker["reputation"]), w_ctx["level"]):
            return record(0.0)
        pair_n = int(con.execute("SELECT COUNT(*) FROM job_completions WHERE author_id = ? AND worker_id = ? AND rep_gain > 0",
                                 (author_id, worker_id)).fetchone()[0])
        gain = C.BASE_JOB_REP * aw * (C.JOB_DAILY_DECAY ** n_today) * (C.JOB_PAIR_DECAY ** pair_n)
        return record(round(max(0.0, min(gain, C.AUTHOR_GRANT_DAILY_CAP - granted)), 4))

    def remove_job(self, job_id: int) -> Result:
        """Soft delete: completion and rating history of other users survives."""
        with self.tx() as con:
            if con.execute("UPDATE jobs SET removed = 1, status = CASE WHEN status IN ('open','awaiting_confirmation') THEN 'cancelled' ELSE status END, "
                           "updated_at = ? WHERE id = ? AND removed = 0", (int(time.time()), job_id)).rowcount == 0:
                return False, "Job not found.", None
            return True, "Job removed.", None

    # ------------------------------------------------------------ ban / wipe
    def ban_user(self, nickname: str, wipe: bool) -> Result:
        now = int(time.time())
        with self.tx() as con:
            target = self.user_by_nick(con, nickname)
            if target is None:
                return False, "User not found.", None
            if target["is_admin"]:
                return False, "Admin accounts cannot be banned.", None
            tid = int(target["id"])
            if target["is_banned"] and not wipe:
                return False, "User is already banned.", tid
            con.execute("UPDATE users SET is_banned = 1 WHERE id = ?", (tid,))
            con.execute("UPDATE job_accepts SET withdrawn = 1 WHERE user_id = ?", (tid,))
            con.execute("UPDATE jobs SET selected_worker_id = NULL, updated_at = ? WHERE selected_worker_id = ? AND status = 'open'", (now, tid))
            self._penalize_inviter_once(con, target)
            if not wipe:
                return True, "User banned permanently.", tid
            jobs = con.execute("UPDATE jobs SET removed = 1, status = CASE WHEN status IN ('open','awaiting_confirmation') THEN 'cancelled' ELSE status END, "
                               "updated_at = ? WHERE author_id = ? AND removed = 0", (now, tid)).rowcount
            threads = con.execute("DELETE FROM threads WHERE author_id = ?", (tid,)).rowcount
            comments = con.execute("DELETE FROM thread_posts WHERE author_id = ?", (tid,)).rowcount
            return True, f"User wiped and banned. Removed jobs={jobs} threads={threads} comments={comments}.", tid

    # ------------------------------------------------------------ ratings
    def rate_user(self, rater_id: int, target_nick: str, choice: str, job_id: int) -> Result:
        value = C.RATING_CHOICES[choice]
        positive = value > 0
        now = int(time.time())
        with self.tx() as con:
            rater = self.user(con, rater_id)
            target = self.user_by_nick(con, target_nick)
            if rater is None or rater["is_banned"]:
                return False, "Not allowed.", None
            if target is None or target["is_banned"]:
                return False, "Operation not allowed.", None
            tid = int(target["id"])
            if tid == rater_id:
                return False, "You cannot rate yourself.", None
            job = con.execute("SELECT author_id, selected_worker_id, status FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if job is None:
                return False, "Job not found.", None
            if job["status"] != "done":
                return False, "You can only rate after the job completion has been confirmed.", None
            pair = {int(job["author_id"]), int(job["selected_worker_id"] or -1)}
            if rater_id not in pair or tid not in pair:
                return False, "You can only rate the other party of a job you completed together.", None
            if con.execute("SELECT 1 FROM reputation_ratings WHERE rater_id = ? AND target_id = ? AND job_id = ?", (rater_id, tid, job_id)).fetchone():
                return False, "You already rated this user for this job.", None

            weight = rating_weight(float(rater["reputation"]), bool(rater["is_admin"]), positive)
            # Repeated ratings between the same two people decay geometrically.
            pair_n = int(con.execute("SELECT COUNT(*) FROM reputation_ratings WHERE state = 'applied' AND "
                                     "((rater_id = ? AND target_id = ?) OR (rater_id = ? AND target_id = ?))",
                                     (rater_id, tid, tid, rater_id)).fetchone()[0])
            weight *= C.RATING_PAIR_DECAY ** pair_n
            if positive and con.execute("SELECT 1 FROM reputation_ratings WHERE rater_id = ? AND target_id = ? AND job_id = ? AND rating_value > 0",
                                        (tid, rater_id, job_id)).fetchone():
                weight *= C.RATING_RECIPROCAL_FACTOR
            if positive and not rater["is_admin"]:
                given = float(con.execute("SELECT COALESCE(SUM(applied_delta), 0) FROM reputation_ratings WHERE rater_id = ? AND applied_delta > 0 AND created_at >= ?",
                                          (rater_id, now - 86400)).fetchone()[0])
                weight = max(0.0, min(weight, C.RATER_DAILY_POSITIVE_BUDGET - given))
            delta = round(value * weight, 4)

            state = "applied"
            if not positive:
                recent_n = int(con.execute("SELECT COUNT(*) FROM reputation_ratings WHERE target_id = ? AND rating_value < 0 AND state != 'discarded' AND created_at >= ?",
                                           (tid, now - C.NEGATIVE_RATING_BURST_WINDOW)).fetchone()[0])
                lost = -float(con.execute("SELECT COALESCE(SUM(applied_delta), 0) FROM reputation_ratings WHERE target_id = ? AND applied_delta < 0 AND created_at >= ?",
                                          (tid, now - 86400)).fetchone()[0])
                if recent_n >= C.NEGATIVE_RATING_BURST_LIMIT:
                    state = "frozen"
                    self.add_flag(con, tid, str(target["nickname"]), "rating_brigade", f"negative-rating burst; rating on job {job_id} frozen")
                elif lost + abs(delta) > C.RATING_TARGET_DAILY_NEGATIVE_CAP:
                    state = "frozen"
                    self.add_flag(con, tid, str(target["nickname"]), "rating_target_cap", f"24h negative cap reached; rating on job {job_id} frozen")
            con.execute("INSERT INTO reputation_ratings (rater_id, target_id, job_id, rating_value, applied_delta, state, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (rater_id, tid, job_id, value, delta if state == "applied" else 0.0, state, now))
            if state == "applied" and delta:
                con.execute("UPDATE users SET reputation = reputation + ? WHERE id = ?", (delta, tid))
            if state == "frozen":
                return True, "Rating recorded and held for moderator review.", {"frozen": True}
            return True, f"Rating recorded ({delta:+.3f}).", {"frozen": False}

    def admin_adjust_reputation(self, nickname: str, delta: float) -> Result:
        with self.tx() as con:
            target = self.user_by_nick(con, nickname)
            if target is None:
                return False, "User not found.", None
            con.execute("UPDATE users SET reputation = reputation + ? WHERE id = ?", (round(delta, 4), int(target["id"])))
            return True, f"Adjusted reputation of {nickname} by {delta:+.3f}.", None

    def list_frozen_ratings(self, page: int) -> tuple[list[dict[str, Any]], int, int]:
        with self.tx() as con:
            total = int(con.execute("SELECT COUNT(*) FROM reputation_ratings WHERE state = 'frozen'").fetchone()[0])
            page, offset = clamp_page(total, page, C.ADMIN_PAGE_SIZE)
            rows = con.execute("SELECT r.*, ur.nickname AS rn, ut.nickname AS tn FROM reputation_ratings r JOIN users ur ON ur.id = r.rater_id "
                               "JOIN users ut ON ut.id = r.target_id WHERE r.state = 'frozen' ORDER BY r.created_at DESC LIMIT ? OFFSET ?",
                               (C.ADMIN_PAGE_SIZE, offset)).fetchall()
        return [{"rater": r["rn"], "target": r["tn"], "rater_id": int(r["rater_id"]), "target_id": int(r["target_id"]),
                 "job_id": int(r["job_id"]), "rating_value": int(r["rating_value"]), "created_at": int(r["created_at"])} for r in rows], total, page

    def resolve_frozen_rating(self, rater_id: int, target_id: int, job_id: int, apply: bool) -> Result:
        """Discarded ratings are KEPT (state='discarded') so the rater cannot
        simply submit the same rating again."""
        with self.tx() as con:
            row = con.execute("SELECT * FROM reputation_ratings WHERE rater_id = ? AND target_id = ? AND job_id = ? AND state = 'frozen'",
                              (rater_id, target_id, job_id)).fetchone()
            if row is None:
                return False, "Frozen rating not found.", None
            if not apply:
                con.execute("UPDATE reputation_ratings SET state = 'discarded', applied_delta = 0 WHERE rater_id = ? AND target_id = ? AND job_id = ?",
                            (rater_id, target_id, job_id))
                return True, "Frozen rating discarded.", None
            rater = self.user(con, rater_id)
            weight = rating_weight(float(rater["reputation"]) if rater else 0.0, bool(rater and rater["is_admin"]), int(row["rating_value"]) > 0)
            delta = round(int(row["rating_value"]) * weight, 4)
            con.execute("UPDATE reputation_ratings SET state = 'applied', applied_delta = ? WHERE rater_id = ? AND target_id = ? AND job_id = ?",
                        (delta, rater_id, target_id, job_id))
            con.execute("UPDATE users SET reputation = reputation + ? WHERE id = ?", (delta, target_id))
            return True, f"Frozen rating applied ({delta:+.3f}).", None

    # ------------------------------------------------------------ E2E keys
    @staticmethod
    def _parse_pubkey(public_key: Any) -> Optional[tuple[str, str]]:
        if not isinstance(public_key, str) or len(public_key) != C.E2E_PUBKEY_B64_LEN:
            return None
        try:
            raw = base64.b64decode(public_key, validate=True)
        except (binascii.Error, ValueError):
            return None
        if len(raw) != 32 or raw == b"\x00" * 32:
            return None
        return public_key, key_fingerprint(raw)

    def _store_key(self, con: sqlite3.Connection, user_id: int, pub_b64: str, fp: str, now: int) -> None:
        existing = con.execute("SELECT id, user_id FROM user_keys WHERE fingerprint = ?", (fp,)).fetchone()
        if existing is not None:
            if int(existing["user_id"]) != user_id:
                raise ValueError("key already registered to another user")
            key_id = int(existing["id"])
        else:
            key_id = int(con.execute("INSERT INTO user_keys (user_id, fingerprint, public_key, created_at) VALUES (?, ?, ?, ?)",
                                     (user_id, fp, pub_b64, now)).lastrowid)
        con.execute("UPDATE users SET current_key_id = ? WHERE id = ?", (key_id, user_id))

    def set_public_key(self, user_id: int, public_key: Any) -> Result:
        info = self._parse_pubkey(public_key)
        if info is None:
            return False, "Invalid public key.", None
        now = int(time.time())
        with self.tx() as con:
            recent = int(con.execute("SELECT COUNT(*) FROM user_keys WHERE user_id = ? AND created_at >= ?", (user_id, now - 86400)).fetchone()[0])
            if recent >= C.E2E_KEY_ROTATIONS_PER_DAY:
                return False, "Too many key changes today.", None
            try:
                self._store_key(con, user_id, info[0], info[1], now)
            except ValueError:
                return False, "That key is already registered to another account.", None
            # Tell every chat partner the key changed, so they can re-verify it.
            for c in con.execute("SELECT id FROM chats WHERE user_low_id = ? OR user_high_id = ?", (user_id, user_id)).fetchall():
                u = self.user(con, user_id)
                self.system_message(con, int(c["id"]), f"{u['nickname']} changed their encryption key (new fingerprint {info[1][:16]}). Verify it out of band.")
            return True, "Public key registered.", {"fingerprint": info[1]}

    def get_public_key(self, viewer_id: int, nickname: Optional[str], fingerprint: Optional[str]) -> Result:
        with self.tx() as con:
            if fingerprint:
                row = con.execute("SELECT k.*, u.nickname, u.current_key_id FROM user_keys k JOIN users u ON u.id = k.user_id WHERE k.fingerprint = ?",
                                  (fingerprint,)).fetchone()
            else:
                row = con.execute("SELECT k.*, u.nickname, u.current_key_id FROM users u JOIN user_keys k ON k.id = u.current_key_id "
                                  "WHERE u.nickname = ? COLLATE NOCASE AND u.status = 'active'", (nickname,)).fetchone()
            if row is None:
                return False, "No encryption key published for that user yet.", None
            return True, "OK", {"nickname": str(row["nickname"]), "public_key": str(row["public_key"]),
                                "fingerprint": str(row["fingerprint"]), "current": int(row["id"]) == row["current_key_id"]}

    def current_key_fp(self, con: sqlite3.Connection, user_id: int) -> Optional[str]:
        row = con.execute("SELECT k.fingerprint FROM users u JOIN user_keys k ON k.id = u.current_key_id WHERE u.id = ?", (user_id,)).fetchone()
        return str(row["fingerprint"]) if row is not None else None

    # ------------------------------------------------------------ chat
    def ensure_chat(self, con: sqlite3.Connection, a: int, b: int) -> int:
        low, high = sorted((int(a), int(b)))
        row = con.execute("SELECT id FROM chats WHERE user_low_id = ? AND user_high_id = ?", (low, high)).fetchone()
        now = int(time.time())
        if row is not None:
            return int(row["id"])
        return int(con.execute("INSERT INTO chats (user_low_id, user_high_id, created_at, updated_at) VALUES (?, ?, ?, ?)", (low, high, now, now)).lastrowid)

    def system_message(self, con: sqlite3.Connection, chat_id: int, text: str) -> None:
        now = int(time.time())
        con.execute("INSERT INTO messages (chat_id, sender_id, message_type, body, created_at) VALUES (?, NULL, 'system', ?, ?)",
                    (chat_id, self.crypto.enc(text), now))
        con.execute("UPDATE chats SET updated_at = ? WHERE id = ?", (now, chat_id))

    def open_chat(self, actor_id: int, nickname: str) -> Result:
        with self.tx() as con:
            actor = self.user(con, actor_id)
            target = self.user_by_nick(con, nickname)
            if actor is None or actor["is_banned"] or target is None or target["is_banned"] or target["status"] != "active":
                return False, "Operation not allowed.", None
            tid = int(target["id"])
            if tid == actor_id:
                return False, "You cannot open a chat with yourself.", None
            if self.block_exists(con, actor_id, tid):
                return False, "Operation not allowed.", None
            low, high = sorted((actor_id, tid))
            existing = con.execute("SELECT id FROM chats WHERE user_low_id = ? AND user_high_id = ?", (low, high)).fetchone()
            if existing is None:
                reason = self._consume_quota(con, actor, "open_chat")
                if reason:
                    return False, reason, None
                chat_id = self.ensure_chat(con, actor_id, tid)
                self.system_message(con, chat_id, f"{actor['nickname']} started a conversation with you.")
            else:
                chat_id = int(existing["id"])
            return True, "Chat ready.", self._chat_summary(con, chat_id, actor_id)

    def _chat_partner(self, con: sqlite3.Connection, chat_id: int, user_id: int) -> Optional[int]:
        chat = con.execute("SELECT * FROM chats WHERE id = ? AND (user_low_id = ? OR user_high_id = ?)", (chat_id, user_id, user_id)).fetchone()
        if chat is None:
            return None
        return int(chat["user_high_id"]) if int(chat["user_low_id"]) == user_id else int(chat["user_low_id"])

    def _msg_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        system = row["message_type"] == "system"
        return {"id": int(row["id"]), "sender_id": row["sender_id"],
                "sender_nickname": None if system else (str(row["sender_nickname"]) if row["sender_nickname"] is not None else "[deleted user]"),
                "message_type": str(row["message_type"]),
                "body": self.dec(row["body"]) if system else str(row["body"]),
                "sender_key_fp": row["sender_key_fp"], "recipient_key_fp": row["recipient_key_fp"],
                "created_at": int(row["created_at"])}

    def _chat_summary(self, con: sqlite3.Connection, chat_id: int, viewer_id: int) -> Optional[dict[str, Any]]:
        other_id = self._chat_partner(con, chat_id, viewer_id)
        if other_id is None:
            return None
        chat = con.execute("SELECT * FROM chats WHERE id = ?", (chat_id,)).fetchone()
        other = self.user(con, other_id)
        last = con.execute("SELECT m.*, u.nickname AS sender_nickname FROM messages m LEFT JOIN users u ON u.id = m.sender_id "
                           "WHERE m.chat_id = ? ORDER BY m.id DESC LIMIT 1", (chat_id,)).fetchone()
        unread = int(con.execute("SELECT COUNT(*) FROM messages m LEFT JOIN message_reads r ON r.message_id = m.id AND r.user_id = ? "
                                 "WHERE m.chat_id = ? AND (m.sender_id IS NULL OR m.sender_id != ?) AND r.message_id IS NULL",
                                 (viewer_id, chat_id, viewer_id)).fetchone()[0])
        return {"chat_id": chat_id, "other_user_id": other_id, "other_nickname": str(other["nickname"]) if other else "[deleted user]",
                "other_key_fp": self.current_key_fp(con, other_id), "blocked": self.block_exists(con, viewer_id, other_id),
                "created_at": int(chat["created_at"]), "updated_at": int(chat["updated_at"]),
                "last_message": self._msg_dict(last) if last is not None else None, "unread_count": unread}

    def list_chats(self, user_id: int, page: int) -> tuple[list[dict[str, Any]], int, int]:
        with self.tx() as con:
            total = int(con.execute("SELECT COUNT(*) FROM chats WHERE user_low_id = ? OR user_high_id = ?", (user_id, user_id)).fetchone()[0])
            page, offset = clamp_page(total, page, C.PAGE_SIZE)
            rows = con.execute("SELECT id FROM chats WHERE user_low_id = ? OR user_high_id = ? ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                               (user_id, user_id, C.PAGE_SIZE, offset)).fetchall()
            return [s for s in (self._chat_summary(con, int(r["id"]), user_id) for r in rows) if s is not None], total, page

    def list_messages(self, user_id: int, chat_id: int, before_id: Optional[int]) -> Result:
        """Newest page first (cursor = before_id), so a huge chat never produces
        a huge response."""
        with self.tx() as con:
            other_id = self._chat_partner(con, chat_id, user_id)
            if other_id is None or self.block_exists(con, user_id, other_id):
                return False, "Chat not found.", None
            q = "SELECT m.*, u.nickname AS sender_nickname FROM messages m LEFT JOIN users u ON u.id = m.sender_id WHERE m.chat_id = ?"
            params: list[Any] = [chat_id]
            if before_id:
                q += " AND m.id < ?"
                params.append(before_id)
            rows = con.execute(q + " ORDER BY m.id DESC LIMIT ?", params + [C.MESSAGES_PAGE_SIZE + 1]).fetchall()
            has_more = len(rows) > C.MESSAGES_PAGE_SIZE
            rows = list(reversed(rows[:C.MESSAGES_PAGE_SIZE]))
            now = int(time.time())
            for r in rows:
                if r["sender_id"] != user_id:
                    con.execute("INSERT OR IGNORE INTO message_reads (message_id, user_id, read_at) VALUES (?, ?, ?)", (int(r["id"]), user_id, now))
            other = self.user(con, other_id)
            return True, "OK", {"chat_id": chat_id, "other_nickname": str(other["nickname"]) if other else "[deleted user]",
                                "my_key_fp": self.current_key_fp(con, user_id), "other_key_fp": self.current_key_fp(con, other_id),
                                "messages": [self._msg_dict(r) for r in rows], "has_more": has_more,
                                "next_before_id": int(rows[0]["id"]) if rows and has_more else None}

    def send_message(self, sender_id: int, chat_id: int, ciphertext: str, sender_fp: str, recipient_fp: str) -> Result:
        """The server only ever sees ciphertext. It checks that the client
        encrypted to the CURRENT keys of both parties."""
        with self.tx() as con:
            sender = self.user(con, sender_id)
            other_id = self._chat_partner(con, chat_id, sender_id)
            if sender is None or other_id is None:
                return False, "Chat not found.", None
            if self.block_exists(con, sender_id, other_id):
                return False, "Not allowed.", None
            other = self.user(con, other_id)
            if other is None or other["is_banned"]:
                return False, "Not allowed.", None
            my_fp, their_fp = self.current_key_fp(con, sender_id), self.current_key_fp(con, other_id)
            if my_fp is None:
                return False, "Publish your encryption key first.", {"code": "no_key"}
            if their_fp is None:
                return False, "The other user has not published an encryption key yet.", {"code": "no_key"}
            if sender_fp != my_fp or recipient_fp != their_fp:
                return False, "Encryption keys changed. Refresh and verify the new key.", {"code": "key_changed", "my_key_fp": my_fp, "other_key_fp": their_fp}
            reason = self._consume_quota(con, sender, "send_message")
            if reason:
                return False, reason, None
            now = int(time.time())
            cur = con.execute("INSERT INTO messages (chat_id, sender_id, message_type, body, sender_key_fp, recipient_key_fp, created_at) "
                              "VALUES (?, ?, 'e2e', ?, ?, ?, ?)", (chat_id, sender_id, ciphertext, my_fp, their_fp, now))
            con.execute("UPDATE chats SET updated_at = ? WHERE id = ?", (now, chat_id))
            return True, "Message sent.", {"message_id": int(cur.lastrowid)}

    # ------------------------------------------------------------ forum
    def _thread_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        banned = bool(row["author_is_banned"])
        nick = str(row["author_nickname"])
        return {"id": int(row["id"]), "title": self.dec(row["title_enc"]), "author_id": int(row["author_id"]), "author_nickname": nick,
                "author_is_banned": banned, "author_display": f"{C.BAN_LABEL} {nick}" if banned else nick,
                "reply_count": int(row["reply_count"]) if "reply_count" in row.keys() else 0,
                "created_at": int(row["created_at"]), "updated_at": int(row["updated_at"])}

    @staticmethod
    def _block_clause(col: str) -> str:
        return (f"NOT EXISTS (SELECT 1 FROM user_blocks b WHERE (b.blocker_id = ? AND b.blocked_id = {col}) "
                f"OR (b.blocker_id = {col} AND b.blocked_id = ?))")

    def list_threads(self, viewer_id: int, page: int) -> tuple[list[dict[str, Any]], int, int]:
        fw = "FROM threads t JOIN users u ON u.id = t.author_id WHERE " + self._block_clause("t.author_id")
        with self.tx() as con:
            total = int(con.execute("SELECT COUNT(*) " + fw, (viewer_id, viewer_id)).fetchone()[0])
            page, offset = clamp_page(total, page, C.PAGE_SIZE)
            rows = con.execute("SELECT t.*, u.nickname AS author_nickname, u.is_banned AS author_is_banned, "
                               "(SELECT COUNT(*) FROM thread_posts p WHERE p.thread_id = t.id) AS reply_count " + fw +
                               " ORDER BY t.updated_at DESC, t.id DESC LIMIT ? OFFSET ?", (viewer_id, viewer_id, C.PAGE_SIZE, offset)).fetchall()
            return [self._thread_dict(r) for r in rows], total, page

    def search_threads(self, viewer_id: int, query: str, page: int) -> tuple[list[dict[str, Any]], int, int]:
        tokens = sorted({t for t in tokenize(query) if len(t) >= C.MIN_SEARCH_QUERY_LEN})[:8]
        if not tokens:
            return [], 0, 1
        hmacs = [self.crypto.term_hmac(t) for t in tokens]
        with self.tx() as con:
            cands = [int(r[0]) for r in con.execute(
                f"SELECT thread_id FROM thread_search_terms WHERE term_hmac IN ({','.join('?' * len(hmacs))}) GROUP BY thread_id "
                "HAVING COUNT(DISTINCT term_hmac) = ? ORDER BY thread_id DESC LIMIT ?", hmacs + [len(hmacs), C.SEARCH_MAX_CANDIDATES]).fetchall()]
            if not cands:
                return [], 0, 1
            rows = con.execute("SELECT t.*, u.nickname AS author_nickname, u.is_banned AS author_is_banned, "
                               "(SELECT COUNT(*) FROM thread_posts p WHERE p.thread_id = t.id) AS reply_count FROM threads t JOIN users u ON u.id = t.author_id "
                               f"WHERE t.id IN ({','.join('?' * len(cands))}) AND " + self._block_clause("t.author_id") +
                               " ORDER BY t.updated_at DESC, t.id DESC LIMIT ?", cands + [viewer_id, viewer_id, C.MAX_SEARCH_RESULTS]).fetchall()
        total = len(rows)
        page, offset = clamp_page(total, page, C.PAGE_SIZE)
        return [self._thread_dict(r) for r in rows[offset:offset + C.PAGE_SIZE]], total, page

    def thread_for_viewer(self, thread_id: int, viewer_id: int, page: int) -> Result:
        with self.tx() as con:
            row = con.execute("SELECT t.*, u.nickname AS author_nickname, u.is_banned AS author_is_banned, "
                              "(SELECT COUNT(*) FROM thread_posts p WHERE p.thread_id = t.id) AS reply_count "
                              "FROM threads t JOIN users u ON u.id = t.author_id WHERE t.id = ?", (thread_id,)).fetchone()
            if row is None:
                return False, "Thread not found.", None
            viewer = self.user(con, viewer_id)
            is_admin = bool(viewer is not None and viewer["is_admin"])
            is_author = int(row["author_id"]) == viewer_id
            if not is_author and not is_admin and self.block_exists(con, viewer_id, int(row["author_id"])):
                return False, "Thread not found.", None
            data = self._thread_dict(row)
            data.update({"body": self.dec(row["body_enc"]), "is_author": is_author, "is_admin": is_admin})
            vis = "" if is_admin else " AND (p.author_id IS NULL OR p.author_id = ? OR " + self._block_clause("p.author_id") + ")"
            vparams: list[Any] = [] if is_admin else [viewer_id, viewer_id, viewer_id]
            total = int(con.execute("SELECT COUNT(*) FROM thread_posts p WHERE p.thread_id = ?" + vis, [thread_id] + vparams).fetchone()[0])
            page, offset = clamp_page(total, page, C.POSTS_PAGE_SIZE)
            posts = con.execute("SELECT p.*, u.nickname AS author_nickname, u.is_banned AS author_is_banned FROM thread_posts p "
                                "LEFT JOIN users u ON u.id = p.author_id WHERE p.thread_id = ?" + vis + " ORDER BY p.id ASC LIMIT ? OFFSET ?",
                                [thread_id] + vparams + [C.POSTS_PAGE_SIZE, offset]).fetchall()
            data["posts"] = []
            for p in posts:
                nick = str(p["author_nickname"]) if p["author_nickname"] is not None else "[deleted user]"
                data["posts"].append({"id": int(p["id"]), "author_id": p["author_id"], "author_nickname": nick,
                                      "author_display": f"{C.BAN_LABEL} {nick}" if p["author_is_banned"] else nick,
                                      "body": self.dec(p["body_enc"]), "created_at": int(p["created_at"])})
            data["posts_total"], data["posts_page"] = total, page
            return True, "OK", data

    def _fingerprint(self, con: sqlite3.Connection, user_id: int, kind: str, text: str, now: int) -> None:
        sh = simhash64(text)
        if sh == 0:
            return
        for r in con.execute("SELECT user_id, simhash FROM content_fingerprints WHERE created_at >= ? ORDER BY id DESC LIMIT ?",
                             (now - 7 * 86400, C.CONTENT_SIMHASH_WINDOW)).fetchall():
            if r["user_id"] is not None and int(r["user_id"]) != user_id and hamming(sh, int(r["simhash"])) <= C.CONTENT_SIMHASH_MAX_HAMMING:
                self.add_flag(con, user_id, None, "cross_account_duplicate", f"{kind} near-duplicate of content from user {int(r['user_id'])}")
                break
        con.execute("INSERT INTO content_fingerprints (user_id, kind, simhash, created_at) VALUES (?, ?, ?, ?)", (user_id, kind, sh, now))

    def create_thread(self, author_id: int, title: str, body: str) -> Result:
        now = int(time.time())
        with self.tx() as con:
            author = self.user(con, author_id)
            if author is None or author["is_banned"]:
                return False, "Not allowed.", None
            if float(author["reputation"]) <= C.NEGATIVE_REP_POST_THRESHOLD:
                return False, f"Users with reputation of {C.NEGATIVE_REP_POST_THRESHOLD:g} or below cannot post or comment.", None
            reason = self._consume_quota(con, author, "create_thread")
            if reason:
                return False, reason, None
            tid = int(con.execute("INSERT INTO threads (author_id, title_enc, body_enc, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                                  (author_id, self.crypto.enc(title), self.crypto.enc(body), now, now)).lastrowid)
            terms = {t for text in (title, body) for t in tokenize(text) if len(t) >= C.MIN_SEARCH_QUERY_LEN}
            con.executemany("INSERT OR IGNORE INTO thread_search_terms (thread_id, term_hmac) VALUES (?, ?)",
                            [(tid, self.crypto.term_hmac(t)) for t in terms])
            self._fingerprint(con, author_id, "thread", f"{title}\n{body}", now)
            return True, "Thread created.", tid

    def add_post(self, author_id: int, thread_id: int, body: str, viewed: bool) -> Result:
        now = int(time.time())
        with self.tx() as con:
            author = self.user(con, author_id)
            if author is None or author["is_banned"]:
                return False, "Not allowed.", None
            if float(author["reputation"]) <= C.NEGATIVE_REP_POST_THRESHOLD:
                return False, f"Users with reputation of {C.NEGATIVE_REP_POST_THRESHOLD:g} or below cannot post or comment.", None
            thread = con.execute("SELECT id, author_id, created_at FROM threads WHERE id = ?", (thread_id,)).fetchone()
            if thread is None:
                return False, "Thread not found.", None
            if self.block_exists(con, author_id, int(thread["author_id"])):
                return False, "Not allowed.", None
            reason = self._consume_quota(con, author, "post_comment")
            if reason:
                return False, reason, None
            pid = int(con.execute("INSERT INTO thread_posts (thread_id, author_id, body_enc, created_at) VALUES (?, ?, ?, ?)",
                                  (thread_id, author_id, self.crypto.enc(body), now)).lastrowid)
            con.execute("UPDATE threads SET updated_at = ? WHERE id = ?", (now, thread_id))
            if not author["is_admin"]:
                if now - int(thread["created_at"]) <= C.FAST_REPLY_SECONDS and int(thread["author_id"]) != author_id:
                    self.add_flag(con, author_id, str(author["nickname"]), "fast_reply", f"comment {now - int(thread['created_at'])}s after thread {thread_id} was created")
                if not viewed:
                    self.add_flag(con, author_id, str(author["nickname"]), "unseen_thread_comment", f"comment on thread {thread_id} not fetched this session")
            self._fingerprint(con, author_id, "comment", body, now)
            return True, "Comment posted.", pid

    def delete_thread(self, thread_id: int) -> Result:
        with self.tx() as con:
            if con.execute("DELETE FROM threads WHERE id = ?", (thread_id,)).rowcount == 0:
                return False, "Thread not found.", None
            return True, "Thread deleted.", None

    def delete_post(self, post_id: int) -> Result:
        with self.tx() as con:
            if con.execute("DELETE FROM thread_posts WHERE id = ?", (post_id,)).rowcount == 0:
                return False, "Comment not found.", None
            return True, "Comment deleted.", None

    # ------------------------------------------------------------ maintenance
    def maintenance(self) -> None:
        now = int(time.time())
        confirmed = self.auto_confirm_stale()
        with self.tx() as con:
            con.execute("DELETE FROM users WHERE status = 'pending' AND created_at < ?", (now - C.PENDING_EXPIRE_SECONDS,))
            con.execute("DELETE FROM content_fingerprints WHERE created_at < ?", (now - 7 * 86400,))
            con.execute("DELETE FROM moderation_flags WHERE resolved = 1 AND last_seen_at < ?", (now - C.FLAG_RETENTION_SECONDS,))
            con.execute("DELETE FROM rate_counters WHERE hour < ?", (_hour() - 48,))
        if confirmed:
            log(f"maintenance auto_confirmed_jobs={confirmed}")
