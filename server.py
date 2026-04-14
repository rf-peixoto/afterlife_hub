#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from cryptography.fernet import Fernet, InvalidToken

# =========================
# Configuration
# =========================
HOST = os.environ.get("AFTERLIFE_HOST", "0.0.0.0")
PORT = int(os.environ.get("AFTERLIFE_PORT", "2077"))
DB_PATH = Path(os.environ.get("AFTERLIFE_DB_PATH", "./AFTERLIFE.db"))
MASTER_KEY_PATH = Path(os.environ.get("AFTERLIFE_MASTER_KEY_PATH", "./master.key"))
LOG_PATH = Path(os.environ.get("AFTERLIFE_LOG_PATH", "./server.log"))

MAX_TITLE_LEN = 32
MAX_DESC_LEN = 256
MAX_MESSAGE_LEN = 128
MIN_NICK_LEN = 3
MAX_NICK_LEN = 12
MIN_PASSWORD_LEN = 8
MAX_REWARD = 99_999_999
MAX_MIN_REPUTATION = 999_999
BAN_LABEL = "[banned]"
MAX_REQUEST_LINE_BYTES = int(os.environ.get("AFTERLIFE_MAX_REQUEST_LINE_BYTES", "8192"))
MAX_JSON_DEPTH = int(os.environ.get("AFTERLIFE_MAX_JSON_DEPTH", "16"))
MAX_PARSE_ERRORS_PER_WINDOW = int(os.environ.get("AFTERLIFE_MAX_PARSE_ERRORS_PER_WINDOW", "10"))
MAX_CONNECTIONS = int(os.environ.get("AFTERLIFE_MAX_CONNECTIONS", "100"))
MAX_WORKERS = int(os.environ.get("AFTERLIFE_MAX_WORKERS", "32"))

FORBIDDEN_CHARS = set("'\"\\/%+")
ALLOWED_TEXT_RE = re.compile(r"^[A-Za-z0-9 _.,:;!?()\-\[\]@]{1,256}$")
MESSAGE_RE = re.compile(r"^[A-Za-z0-9 _.,:;!?()\-\[\]@]{1,128}$")
NICK_RE = re.compile(r"^[A-Za-z0-9_]{3,12}$")
RATING_CHOICES = {"positive": 1, "negative": -1}

GLOBAL_WINDOW_SECONDS = 10
GLOBAL_MAX_REQUESTS_PER_WINDOW = 40
AUTH_WINDOW_SECONDS = 300
AUTH_FAIL_LIMIT = 5
AUTH_LOCK_SECONDS = 300
READ_TIMEOUT_SECONDS = 180
SESSION_IDLE_SECONDS = 3600
PAIR_CHANGE_COOLDOWN_SECONDS = 86400

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
        self.fernet = Fernet(derive_fernet_key(master_secret))

    def enc(self, value: str) -> str:
        return self.fernet.encrypt(value.encode("utf-8")).decode("utf-8")

    def dec(self, value: Optional[str]) -> str:
        if not value:
            return ""
        try:
            return self.fernet.decrypt(value.encode("utf-8")).decode("utf-8")
        except InvalidToken:
            return ""




# =========================
# Validation
# =========================

def has_forbidden_chars(value: str) -> bool:
    return any(ch in FORBIDDEN_CHARS for ch in value)


def validate_nickname(nickname: str) -> Optional[str]:
    if not NICK_RE.fullmatch(nickname):
        return "Nickname must be 3-24 chars and contain only letters, digits, and underscore."
    if has_forbidden_chars(nickname):
        return "Nickname contains forbidden characters."
    return None


def validate_password(password: str) -> Optional[str]:
    if len(password) < MIN_PASSWORD_LEN:
        return f"Password must be at least {MIN_PASSWORD_LEN} characters."
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
                    reputation INTEGER NOT NULL DEFAULT 0,
                    is_admin INTEGER NOT NULL DEFAULT 0,
                    is_banned INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL
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

                CREATE TABLE IF NOT EXISTS reputation_ratings (
                    rater_id INTEGER NOT NULL,
                    target_id INTEGER NOT NULL,
                    rating_value INTEGER NOT NULL,
                    last_changed_at INTEGER NOT NULL,
                    PRIMARY KEY (rater_id, target_id),
                    FOREIGN KEY(rater_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(target_id) REFERENCES users(id) ON DELETE CASCADE
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
            nick_err = validate_nickname(BOOTSTRAP_ADMIN_USERNAME)
            if nick_err:
                raise RuntimeError(f"Invalid admin username: {nick_err}")
            existing = con.execute(
                "SELECT id, is_admin, is_banned FROM users WHERE nickname = ?",
                (BOOTSTRAP_ADMIN_USERNAME,),
            ).fetchone()
            now = int(time.time())
            if existing is not None:
                updates = ["password_hash = ?"]
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
                "INSERT INTO users (nickname, password_hash, reputation, is_admin, is_banned, created_at) VALUES (?, ?, 0, 1, 0, ?)",
                (BOOTSTRAP_ADMIN_USERNAME, pbkdf2_hash(BOOTSTRAP_ADMIN_PASSWORD), now),
            )
            log(f"Bootstrap admin account {BOOTSTRAP_ADMIN_USERNAME} created.")

    def create_user(self, nickname: str, password: str) -> tuple[bool, str]:
        with self.lock, self.conn() as con:
            try:
                con.execute(
                    "INSERT INTO users (nickname, password_hash, reputation, is_admin, is_banned, created_at) VALUES (?, ?, 0, 0, 0, ?)",
                    (nickname, pbkdf2_hash(password), int(time.time())),
                )
                return True, "User created."
            except sqlite3.IntegrityError:
                return False, "Nickname already exists."

    def authenticate(self, nickname: str, password: str) -> Optional[sqlite3.Row]:
        with self.lock, self.conn() as con:
            row = con.execute(
                "SELECT id, nickname, password_hash, reputation, is_admin, is_banned, created_at FROM users WHERE nickname = ?",
                (nickname,),
            ).fetchone()
            if row and bool(row["is_banned"]):
                return None
            if row and pbkdf2_verify(password, row["password_hash"]):
                return row
            return None

    def get_user(self, user_id: int) -> Optional[sqlite3.Row]:
        with self.lock, self.conn() as con:
            return con.execute(
                "SELECT id, nickname, reputation, is_admin, is_banned, created_at FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()

    def get_user_by_nickname(self, nickname: str) -> Optional[sqlite3.Row]:
        with self.lock, self.conn() as con:
            return con.execute(
                "SELECT id, nickname, reputation, is_admin, is_banned, created_at FROM users WHERE nickname = ?",
                (nickname,),
            ).fetchone()

    def block_exists(self, con: sqlite3.Connection, user_a: int, user_b: int) -> bool:
        return con.execute(
            "SELECT 1 FROM user_blocks WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?) LIMIT 1",
            (user_a, user_b, user_b, user_a),
        ).fetchone() is not None

    def are_blocked(self, user_a: int, user_b: int) -> bool:
        with self.lock, self.conn() as con:
            return self.block_exists(con, user_a, user_b)

    def create_job(self, author_id: int, title: str, description: str, reward: int, min_reputation: int, is_private: bool) -> dict[str, Any]:
        now = int(time.time())
        private_token = secrets.token_urlsafe(16) if is_private else ""
        password_hash = pbkdf2_hash(private_token) if is_private else None
        with self.lock, self.conn() as con:
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
                    min_reputation,
                    1 if is_private else 0,
                    password_hash,
                    now,
                    now,
                ),
            )
            return {"job_id": cur.lastrowid, "private_token": private_token}

    def list_jobs(self, viewer_id: Optional[int], status: Optional[str] = None) -> list[dict[str, Any]]:
        with self.lock, self.conn() as con:
            query = (
                "SELECT j.*, u.nickname AS author_nickname, u.is_banned AS author_is_banned, "
                "(SELECT COUNT(*) FROM job_accepts a WHERE a.job_id = j.id) AS accept_count "
                "FROM jobs j JOIN users u ON u.id = j.author_id "
            )
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
            if clauses:
                query += "WHERE " + " AND ".join(clauses) + " "
            query += "ORDER BY j.created_at DESC"
            rows = con.execute(query, params).fetchall()
            viewer = self.get_user(viewer_id) if viewer_id else None
            return [self._job_row_to_public_dict(row, viewer) for row in rows]

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
                        "reputation": int(w["reputation"]),
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

    def accept_job(self, job_id: int, user_id: int) -> tuple[bool, str]:
        with self.lock, self.conn() as con:
            row = con.execute(
                "SELECT author_id, status, min_reputation FROM jobs WHERE id = ?",
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
            if int(user["reputation"]) < int(row["min_reputation"]):
                return False, "Not enough reputation."
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
                con.execute("UPDATE users SET reputation = reputation + 1 WHERE id = ?", (job["selected_worker_id"],))
            return True, f"Job status set to {new_status}."

    def _job_row_to_public_dict(self, row: sqlite3.Row, viewer: Optional[sqlite3.Row]) -> dict[str, Any]:
        author_is_banned = bool(row["author_is_banned"]) if "author_is_banned" in row.keys() else False
        author_nickname = str(row["author_nickname"])
        author_display = f"{BAN_LABEL} {author_nickname}" if author_is_banned else author_nickname
        viewer_rep = int(viewer["reputation"]) if viewer is not None else None
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
        base = {
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
            "viewer_reputation": int(viewer["reputation"]) if viewer is not None else None,
            "not_enough_reputation": False,
        }
        return base

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
            return True, "User banned permanently.", int(target["id"])

    def delete_job(self, actor_id: int, job_id: int) -> tuple[bool, str]:
        with self.lock, self.conn() as con:
            actor = con.execute("SELECT id, is_admin FROM users WHERE id = ?", (actor_id,)).fetchone()
            if actor is None or not bool(actor["is_admin"]):
                return False, "Not allowed."
            cur = con.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
            if cur.rowcount == 0:
                return False, "Job not found."
            return True, "Job deleted."

    def set_user_rating(self, rater_id: int, target_nickname: str, choice: str) -> tuple[bool, str, Optional[int]]:
        rating_value = RATING_CHOICES[choice]
        now = int(time.time())
        with self.lock, self.conn() as con:
            rater = con.execute("SELECT id, is_banned, nickname FROM users WHERE id = ?", (rater_id,)).fetchone()
            target = con.execute("SELECT id, nickname, is_admin, is_banned FROM users WHERE nickname = ?", (target_nickname,)).fetchone()
            if rater is None or bool(rater["is_banned"]):
                return False, "Not allowed.", None
            if target is None:
                return False, "Operation not allowed.", None
            if int(target["id"]) == rater_id:
                return False, "You cannot rate yourself.", None
            if bool(target["is_banned"]):
                return False, "Operation not allowed.", None
            if self.block_exists(con, rater_id, int(target["id"])):
                return False, "Operation not allowed.", None
            existing = con.execute(
                "SELECT rating_value, last_changed_at FROM reputation_ratings WHERE rater_id = ? AND target_id = ?",
                (rater_id, int(target["id"])),
            ).fetchone()
            if existing is None:
                con.execute(
                    "INSERT INTO reputation_ratings (rater_id, target_id, rating_value, last_changed_at) VALUES (?, ?, ?, ?)",
                    (rater_id, int(target["id"]), rating_value, now),
                )
                con.execute("UPDATE users SET reputation = reputation + ? WHERE id = ?", (rating_value, int(target["id"])))
                return True, f"Rating set to {choice}.", int(target["id"])
            if int(existing["rating_value"]) == rating_value:
                return False, "You already set this rating for this user.", int(target["id"])
            if now - int(existing["last_changed_at"]) < PAIR_CHANGE_COOLDOWN_SECONDS:
                return False, "You can only change this rating once every 24 hours.", int(target["id"])
            delta = rating_value - int(existing["rating_value"])
            con.execute(
                "UPDATE reputation_ratings SET rating_value = ?, last_changed_at = ? WHERE rater_id = ? AND target_id = ?",
                (rating_value, now, rater_id, int(target["id"])),
            )
            con.execute("UPDATE users SET reputation = reputation + ? WHERE id = ?", (delta, int(target["id"])))
            return True, f"Rating changed to {choice}.", int(target["id"])

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
                    "reputation": int(row["reputation"]),
                    "is_banned": bool(row["is_banned"]),
                    "created_at": int(row["created_at"]),
                }
                for row in rows
            ]

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

    def open_chat_by_nickname(self, actor_id: int, target_nickname: str) -> tuple[bool, str, Optional[dict[str, Any]]]:
        with self.lock, self.conn() as con:
            actor = con.execute("SELECT id, nickname, is_banned FROM users WHERE id = ?", (actor_id,)).fetchone()
            target = con.execute("SELECT id, nickname, is_admin, is_banned FROM users WHERE nickname = ?", (target_nickname,)).fetchone()
            if actor is None or bool(actor["is_banned"]):
                return False, "Operation not allowed.", None
            if target is None:
                return False, "Operation not allowed.", None
            if int(target["id"]) == actor_id:
                return False, "You cannot open a chat with yourself.", None
            if bool(target["is_banned"]):
                return False, "Operation not allowed.", None
            if self.block_exists(con, actor_id, int(target["id"])):
                return False, "Operation not allowed.", None
            chat_id = self.ensure_chat_between_users(con, actor_id, int(target["id"]))
            row = con.execute(
                "SELECT COUNT(*) AS count FROM messages WHERE chat_id = ?",
                (chat_id,),
            ).fetchone()
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
                "SELECT id, sender_id, message_type, body_enc, created_at FROM messages WHERE chat_id = ? ORDER BY created_at ASC, id ASC",
                (chat_id,),
            ).fetchall()
            unread_ids: list[int] = []
            items: list[dict[str, Any]] = []
            for row in rows:
                is_read = con.execute(
                    "SELECT 1 FROM message_reads WHERE message_id = ? AND user_id = ?",
                    (int(row["id"]), user_id),
                ).fetchone() is not None
                if (row["sender_id"] is None or int(row["sender_id"]) != user_id) and not is_read:
                    unread_ids.append(int(row["id"]))
                sender_name = "system"
                if row["sender_id"] is not None:
                    sender = con.execute("SELECT nickname FROM users WHERE id = ?", (int(row["sender_id"]),)).fetchone()
                    sender_name = str(sender["nickname"]) if sender is not None else "unknown"
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


class LoginThrottle:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.failures: dict[str, list[float]] = {}
        self.locked_until: dict[str, float] = {}

    def _make_key(self, ip: str, nickname: str) -> str:
        safe_nick = nickname[:MAX_NICK_LEN]
        return f"{ip}|{safe_nick}"

    def _cleanup(self, now: float) -> None:
        stale_failures = []
        for key, values in self.failures.items():
            new_values = [ts for ts in values if now - ts <= AUTH_WINDOW_SECONDS]
            if new_values:
                self.failures[key] = new_values
            else:
                stale_failures.append(key)
        for key in stale_failures:
            self.failures.pop(key, None)
        stale_locks = [key for key, until in self.locked_until.items() if until <= now]
        for key in stale_locks:
            self.locked_until.pop(key, None)

    def check(self, ip: str, nickname: str) -> tuple[bool, int]:
        key = self._make_key(ip, nickname)
        now = time.time()
        with self.lock:
            self._cleanup(now)
            locked_until = self.locked_until.get(key)
            if locked_until and locked_until > now:
                return False, max(1, int(locked_until - now))
            return True, 0

    def success(self, ip: str, nickname: str) -> None:
        key = self._make_key(ip, nickname)
        with self.lock:
            self.failures.pop(key, None)
            self.locked_until.pop(key, None)

    def fail(self, ip: str, nickname: str) -> None:
        key = self._make_key(ip, nickname)
        now = time.time()
        with self.lock:
            self._cleanup(now)
            bucket = self.failures.get(key, [])
            bucket.append(now)
            self.failures[key] = bucket
            if len(bucket) >= AUTH_FAIL_LIMIT:
                self.locked_until[key] = now + AUTH_LOCK_SECONDS


sessions = SessionStore()
global_limiter = SlidingWindowLimiter(GLOBAL_WINDOW_SECONDS, GLOBAL_MAX_REQUESTS_PER_WINDOW)
login_throttle = LoginThrottle()
parse_error_limiter = SlidingWindowLimiter(GLOBAL_WINDOW_SECONDS, MAX_PARSE_ERRORS_PER_WINDOW)


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
    "ping",
    "register",
    "login",
    "logout",
    "profile",
    "list_jobs",
    "my_jobs",
    "my_accepts",
    "create_job",
    "job_details",
    "accept_job",
    "withdraw_job",
    "select_worker",
    "set_status",
    "delete_job",
    "ban_user",
    "rate_user",
    "block_user",
    "unblock_user",
    "list_blocks",
    "open_chat",
    "list_chats",
    "list_messages",
    "read_message",
    "send_message",
}


def require_session(request: dict[str, Any]) -> tuple[Optional[Session], Optional[dict[str, Any]]]:
    session = sessions.get(request.get("session_token"))
    if not session:
        return None, err("Authentication required.", "auth_required")
    user = get_db().get_user(session.user_id)
    if user is None:
        sessions.delete(session.token)
        return None, err("User not found.", "auth_required")
    if bool(user["is_banned"]):
        sessions.delete(session.token)
        return None, err("Invalid credentials.", "login_failed")
    session.is_admin = bool(user["is_admin"])
    return session, None


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
        audit_log(event="request", action=action, ip=ip, status="success")
        return ok({"server": "AFTERLIFE", "version": 1}, "Welcome to AFTERLIFE")

    if action == "register":
        nickname = str(request.get("nickname", "")).strip()
        password = str(request.get("password", ""))
        problem = validate_nickname(nickname) or validate_password(password)
        if problem:
            audit_log(event="user_register", action=action, ip=ip, actor_nickname=nickname or None, status="fail", details=problem)
            return err(problem, "validation_error")
        success, message = get_db().create_user(nickname, password)
        audit_log(event="user_register", action=action, ip=ip, actor_nickname=nickname or None, status="success" if success else "fail", details=message)
        return ok(message=message) if success else err(message, "register_failed")

    if action == "login":
        nickname = str(request.get("nickname", "")).strip()
        password = str(request.get("password", ""))
        allowed_login, retry = login_throttle.check(ip, nickname)
        if not allowed_login:
            audit_log(event="login_throttled", action=action, ip=ip, actor_nickname=nickname or None, status="blocked", details=f"retry_after={retry}s")
            return err("Login temporarily blocked for this nickname from your address.", "login_throttled", retry)
        user = get_db().authenticate(nickname, password)
        if not user:
            login_throttle.fail(ip, nickname)
            time.sleep(1.0)
            audit_log(event="login_failed", action=action, ip=ip, actor_nickname=nickname or None, status="fail", details="invalid credentials")
            return err("Invalid credentials.", "login_failed")
        login_throttle.success(ip, nickname)
        session = sessions.create(user)
        audit_log(event="login_success", action=action, ip=ip, actor_nickname=session.nickname, status="success")
        return ok({"session_token": session.token, "nickname": session.nickname, "reputation": int(user["reputation"]), "is_admin": bool(user["is_admin"]), "is_banned": bool(user["is_banned"])}, "Login successful.")

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
        return ok({"nickname": str(user["nickname"]), "reputation": int(user["reputation"]), "created_at": int(user["created_at"]), "is_admin": bool(user["is_admin"]), "is_banned": bool(user["is_banned"])})

    if action == "list_jobs":
        status = request.get("status")
        if status is not None and status not in {"open", "done", "cancelled"}:
            return err("Invalid status filter.", "validation_error")
        session = sessions.get(request.get("session_token"))
        viewer_id = session.user_id if session else None
        return ok({"jobs": get_db().list_jobs(viewer_id=viewer_id, status=status)})

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
        title = str(request.get("title", "")).strip()
        description = str(request.get("description", "")).strip()
        reward_raw = str(request.get("reward", "")).strip()
        min_rep_raw = str(request.get("min_reputation", "0")).strip()
        is_private, bool_problem = parse_bool_field(request.get("is_private", False), "is_private")
        problem = validate_title(title) or validate_description(description) or validate_reward(reward_raw) or validate_min_reputation(min_rep_raw) or bool_problem
        if problem:
            return err(problem, "validation_error")
        result = get_db().create_job(session.user_id, title, description, int(reward_raw), int(min_rep_raw), bool(is_private))
        return ok(result, "Job created.")

    if action == "job_details":
        try:
            job_id_int = int(request.get("job_id"))
        except Exception:
            return err("Invalid job id.", "validation_error")
        unlock_token = request.get("unlock_token")
        session = sessions.get(request.get("session_token"))
        viewer_id = session.user_id if session else None
        success, message, data = get_db().get_job_for_viewer(job_id_int, viewer_id, str(unlock_token) if unlock_token else None)
        return ok(data, message) if success and data is not None else err(message, "not_found")

    if action == "accept_job":
        session, failure = require_session(request)
        if failure:
            return failure
        try:
            job_id = int(request.get("job_id"))
        except Exception:
            return err("Invalid job id.", "validation_error")
        success, message = get_db().accept_job(job_id, session.user_id)
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
        success, message, _ = get_db().set_user_rating(session.user_id, nickname, rating)
        audit_log(event="user_rate", action=action, ip=ip, actor_nickname=session.nickname, target_user=nickname, status="success" if success else "fail", details=message)
        return ok(message=message) if success else err(message, "rating_failed")

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
        audit_log(event="blocks_list", action=action, ip=ip, actor_nickname=session.nickname, status="success")
        return ok({"blocks": get_db().list_blocks(session.user_id)})

    if action == "open_chat":
        session, failure = require_session(request)
        if failure:
            return failure
        nickname = str(request.get("nickname", "")).strip()
        problem = validate_nickname(nickname)
        if problem:
            return err(problem, "validation_error")
        success, message, data = get_db().open_chat_by_nickname(session.user_id, nickname)
        audit_log(event="chat_open", action=action, ip=ip, actor_nickname=session.nickname, target_user=nickname, chat_id=(data or {}).get("chat_id") if data else None, status="success" if success else "fail", details=message)
        return ok(data, message) if success and data is not None else err(message, "chat_failed")

    if action == "list_chats":
        session, failure = require_session(request)
        if failure:
            return failure
        audit_log(event="chats_list", action=action, ip=ip, actor_nickname=session.nickname, status="success")
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
        audit_log(event="messages_list", action=action, ip=ip, actor_nickname=session.nickname, chat_id=chat_id, status="success" if success else "fail", details=message)
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
        audit_log(event="message_read", action=action, ip=ip, actor_nickname=session.nickname, status="success" if success else "fail", details=message)
        return ok(data, message) if success and data is not None else err(message, "message_failed")

    if action == "send_message":
        session, failure = require_session(request)
        if failure:
            return failure
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

    return err("Unknown action.", "unknown_action")


class ClientHandler:
    def __init__(self, conn: socket.socket, addr: tuple[str, int], server: "Server") -> None:
        self.conn = conn
        self.addr = addr
        self.server = server

    def run(self) -> None:
        ip = self.addr[0]
        try:
            allow, retry = global_limiter.allow(ip)
            if not allow:
                payload = err("Too many requests.", "rate_limited", retry)
                self._send(payload)
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
                allow_parse, retry_parse = parse_error_limiter.allow(ip)
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
        log(f"server_listening host={self.host} port={self.port}")
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
