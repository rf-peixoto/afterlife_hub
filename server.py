#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from cryptography import x509
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.x509.oid import NameOID

# =========================
# Configuration
# =========================
HOST = os.environ.get("AFTERLIFE_HOST", "0.0.0.0")
PORT = int(os.environ.get("AFTERLIFE_PORT", "2077"))
DB_PATH = Path(os.environ.get("AFTERLIFE_DB_PATH", "./AFTERLIFE_space.db"))
MASTER_KEY_PATH = Path(os.environ.get("AFTERLIFE_MASTER_KEY_PATH", "./master.key"))
LOG_PATH = Path(os.environ.get("AFTERLIFE_LOG_PATH", "./server.log"))

MAX_TITLE_LEN = 32
MAX_DESC_LEN = 256
MIN_NICK_LEN = 3
MAX_NICK_LEN = 24
MIN_PASSWORD_LEN = 8
MAX_REWARD = 99_999_999
MAX_CONTACT_INFO_LEN = 128
BAN_LABEL = "[banned]"
MAX_REQUEST_LINE_BYTES = int(os.environ.get("AFTERLIFE_MAX_REQUEST_LINE_BYTES", "8192"))
MAX_JSON_DEPTH = int(os.environ.get("AFTERLIFE_MAX_JSON_DEPTH", "16"))
MAX_PARSE_ERRORS_PER_WINDOW = int(os.environ.get("AFTERLIFE_MAX_PARSE_ERRORS_PER_WINDOW", "10"))
MAX_CONNECTIONS = int(os.environ.get("AFTERLIFE_MAX_CONNECTIONS", "100"))
MAX_WORKERS = int(os.environ.get("AFTERLIFE_MAX_WORKERS", "32"))

# Forbidden across validated text input fields requested by user.
FORBIDDEN_CHARS = set("'\"\\/%")

# Generic text allowlist for title and description.
ALLOWED_TEXT_RE = re.compile(r"^[A-Za-z0-9 _.,:;!?()\-\[\]@]{1,256}$")
NICK_RE = re.compile(r"^[A-Za-z0-9_]{3,24}$")
CONTACT_INFO_RE = re.compile(r"^[A-Za-z0-9 @._-]{1,128}$")

# Rate limiting / throttling
GLOBAL_WINDOW_SECONDS = 10
GLOBAL_MAX_REQUESTS_PER_WINDOW = 40
AUTH_WINDOW_SECONDS = 300
AUTH_FAIL_LIMIT = 5
AUTH_LOCK_SECONDS = 300

READ_TIMEOUT_SECONDS = 180
SESSION_IDLE_SECONDS = 3600

BOOTSTRAP_ADMIN_USERNAME = os.environ.get("AFTERLIFE_BOOTSTRAP_ADMIN_USERNAME", "admin")
BOOTSTRAP_ADMIN_PASSWORD = os.environ.get("AFTERLIFE_BOOTSTRAP_ADMIN_PASSWORD")

# TLS hardening
TLS_MIN_VERSION = ssl.TLSVersion.TLSv1_2


# =========================
# Utilities
# =========================
print_lock = threading.Lock()


def log(message: str) -> None:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}\n"
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(line)
    with print_lock:
        print(line, end="")


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


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def format_x509_name(name: x509.Name) -> str:
    parts = []
    for attr in name:
        try:
            key = attr.oid._name or attr.oid.dotted_string
        except Exception:
            key = attr.oid.dotted_string
        parts.append(f"{key}={attr.value}")
    return ", ".join(parts)


def get_common_name(name: x509.Name) -> str:
    try:
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if attrs:
            return str(attrs[0].value)
    except Exception:
        pass
    return ""


@dataclass
class CertificateInfo:
    subject: str
    issuer: str
    common_name: str
    san_dns: list[str]
    san_ip: list[str]
    not_valid_before: str
    not_valid_after: str
    expired: bool
    not_yet_valid: bool


def read_certificate_info(cert_path: Path) -> CertificateInfo:
    raw = cert_path.read_bytes()
    cert = x509.load_pem_x509_certificate(raw)

    san_dns: list[str] = []
    san_ip: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san_dns = [str(v) for v in san.get_values_for_type(x509.DNSName)]
        san_ip = [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass

    now = time.time()
    not_before_ts = cert.not_valid_before_utc.timestamp()
    not_after_ts = cert.not_valid_after_utc.timestamp()

    return CertificateInfo(
        subject=format_x509_name(cert.subject),
        issuer=format_x509_name(cert.issuer),
        common_name=get_common_name(cert.subject),
        san_dns=san_dns,
        san_ip=san_ip,
        not_valid_before=cert.not_valid_before_utc.isoformat(),
        not_valid_after=cert.not_valid_after_utc.isoformat(),
        expired=now > not_after_ts,
        not_yet_valid=now < not_before_ts,
    )


def read_private_key_pem_bytes(certfile: Path, keyfile: Optional[Path]) -> bytes:
    if keyfile is not None:
        return keyfile.read_bytes()

    # Support combined PEM in --cert
    raw = certfile.read_text(encoding="utf-8", errors="ignore")
    begin = "-----BEGIN PRIVATE KEY-----"
    end = "-----END PRIVATE KEY-----"
    rsa_begin = "-----BEGIN RSA PRIVATE KEY-----"
    rsa_end = "-----END RSA PRIVATE KEY-----"
    ec_begin = "-----BEGIN EC PRIVATE KEY-----"
    ec_end = "-----END EC PRIVATE KEY-----"

    for b, e in (
        (begin, end),
        (rsa_begin, rsa_end),
        (ec_begin, ec_end),
    ):
        start = raw.find(b)
        finish = raw.find(e)
        if start != -1 and finish != -1 and finish > start:
            finish += len(e)
            return raw[start:finish].encode("utf-8")

    raise RuntimeError(
        "No private key found in --cert PEM. Supply --key or use a combined PEM containing both certificate and key."
    )


def extract_public_key_bytes_from_cert(cert_path: Path) -> bytes:
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    return cert.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def extract_public_key_bytes_from_private_key_pem(key_pem: bytes) -> bytes:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key, PublicFormat

    private_key = load_pem_private_key(key_pem, password=None)
    return private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def ensure_cert_key_match(cert_path: Path, key_path: Optional[Path]) -> None:
    key_pem = read_private_key_pem_bytes(cert_path, key_path)
    cert_pub = extract_public_key_bytes_from_cert(cert_path)
    key_pub = extract_public_key_bytes_from_private_key_pem(key_pem)
    if cert_pub != key_pub:
        raise RuntimeError("TLS certificate and private key do not match.")


def validate_tls_files(cert_path: Path, key_path: Optional[Path]) -> None:
    if not cert_path.is_file():
        raise RuntimeError(f"TLS certificate file not found: {cert_path}")
    if key_path is not None and not key_path.is_file():
        raise RuntimeError(f"TLS private key file not found: {key_path}")
    ensure_cert_key_match(cert_path, key_path)


def startup_log_certificate_info(info: CertificateInfo, advertised_name: Optional[str]) -> None:
    log(f"TLS certificate subject: {info.subject}")
    log(f"TLS certificate issuer: {info.issuer}")
    if info.common_name:
        log(f"TLS certificate common name: {info.common_name}")
    log(f"TLS certificate validity: {info.not_valid_before} -> {info.not_valid_after}")

    if info.san_dns or info.san_ip:
        san_chunks = []
        if info.san_dns:
            san_chunks.append("DNS=" + ", ".join(info.san_dns))
        if info.san_ip:
            san_chunks.append("IP=" + ", ".join(info.san_ip))
        log("TLS certificate SANs: " + " | ".join(san_chunks))
    else:
        log("WARNING: TLS certificate has no SAN extension. Modern clients should reject such certificates.")

    if info.not_yet_valid:
        log("WARNING: TLS certificate is not yet valid according to current system time.")
    if info.expired:
        log("WARNING: TLS certificate is expired.")

    if advertised_name:
        if is_ip_address(advertised_name):
            if advertised_name not in info.san_ip:
                log(
                    "WARNING: advertised TLS name is an IP that is not present in the certificate SAN IP list. "
                    "Production clients validating that IP should fail."
                )
        else:
            if advertised_name not in info.san_dns:
                log(
                    "WARNING: advertised TLS name is not present in the certificate SAN DNS list. "
                    "Production clients validating that hostname should fail."
                )


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


crypto = CryptoBox(MASTER_KEY_PATH)


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


def validate_reward(raw: str) -> Optional[str]:
    if not raw.isdigit():
        return "Reward must contain digits only."
    value = int(raw)
    if value < 1 or value > MAX_REWARD:
        return f"Reward must be between 1 and {MAX_REWARD}."
    return None


def validate_contact_info(contact_info: str) -> Optional[str]:
    if not contact_info or len(contact_info) > MAX_CONTACT_INFO_LEN:
        return f"Contact info must be 1-{MAX_CONTACT_INFO_LEN} characters."
    if has_forbidden_chars(contact_info):
        return "Contact info contains forbidden characters."
    if not CONTACT_INFO_RE.fullmatch(contact_info):
        return "Contact info may only contain letters, digits, spaces, and @ . - _."
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

    def conn(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, check_same_thread=False)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA foreign_keys=ON")
        return con

    def _init_db(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.conn() as con:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    nickname TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    contact_info_enc TEXT NOT NULL DEFAULT '',
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
                """
            )
            self._migrate_schema(con)

    def _migrate_schema(self, con: sqlite3.Connection) -> None:
        user_columns = {row["name"] for row in con.execute("PRAGMA table_info(users)").fetchall()}
        if "contact_info_enc" not in user_columns:
            con.execute("ALTER TABLE users ADD COLUMN contact_info_enc TEXT NOT NULL DEFAULT ''")
        if "is_banned" not in user_columns:
            con.execute("ALTER TABLE users ADD COLUMN is_banned INTEGER NOT NULL DEFAULT 0")

    def _ensure_bootstrap_admin(self) -> None:
        with self.lock, self.conn() as con:
            row = con.execute(
                "SELECT id FROM users WHERE nickname = ?", (BOOTSTRAP_ADMIN_USERNAME,)
            ).fetchone()
            if row is not None:
                return
            if not BOOTSTRAP_ADMIN_PASSWORD or BOOTSTRAP_ADMIN_PASSWORD == "changeme":
                raise RuntimeError(
                    "Refusing to auto-provision bootstrap admin with an unsafe default password. "
                    "Set AFTERLIFE_BOOTSTRAP_ADMIN_PASSWORD to a strong secret before starting the server."
                )
            con.execute(
                "INSERT INTO users (nickname, password_hash, reputation, is_admin, is_banned, created_at) VALUES (?, ?, 0, 1, 0, ?)",
                (BOOTSTRAP_ADMIN_USERNAME, pbkdf2_hash(BOOTSTRAP_ADMIN_PASSWORD), int(time.time())),
            )
            log("Bootstrap admin account created from operator-supplied secret.")

    def create_user(self, nickname: str, password: str, contact_info: str) -> tuple[bool, str]:
        with self.lock, self.conn() as con:
            try:
                con.execute(
                    "INSERT INTO users (nickname, password_hash, contact_info_enc, reputation, is_admin, is_banned, created_at) VALUES (?, ?, ?, 0, 0, 0, ?)",
                    (nickname, pbkdf2_hash(password), crypto.enc(contact_info), int(time.time())),
                )
                return True, "User created."
            except sqlite3.IntegrityError:
                return False, "Nickname already exists."

    def authenticate(self, nickname: str, password: str) -> Optional[sqlite3.Row]:
        with self.lock, self.conn() as con:
            row = con.execute(
                "SELECT id, nickname, password_hash, contact_info_enc, reputation, is_admin, is_banned, created_at FROM users WHERE nickname = ?",
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
                "SELECT id, nickname, contact_info_enc, reputation, is_admin, is_banned, created_at FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()

    def get_user_by_nickname(self, nickname: str) -> Optional[sqlite3.Row]:
        with self.lock, self.conn() as con:
            return con.execute(
                "SELECT id, nickname, contact_info_enc, reputation, is_admin, is_banned, created_at FROM users WHERE nickname = ?",
                (nickname,),
            ).fetchone()

    def ban_user(self, actor_id: int, nickname: str) -> tuple[bool, str, Optional[int]]:
        with self.lock, self.conn() as con:
            actor = con.execute("SELECT id, is_admin FROM users WHERE id = ?", (actor_id,)).fetchone()
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

    def create_job(self, author_id: int, title: str, description: str, reward: int, is_private: bool) -> dict[str, Any]:
        now = int(time.time())
        private_token = secrets.token_urlsafe(16) if is_private else ""
        password_hash = pbkdf2_hash(private_token) if is_private else None
        with self.lock, self.conn() as con:
            cur = con.execute(
                """
                INSERT INTO jobs (
                    author_id, title_enc, description_enc, reward, is_private,
                    description_password_hash, status, selected_worker_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'open', NULL, ?, ?)
                """,
                (
                    author_id,
                    crypto.enc(title),
                    crypto.enc(description),
                    reward,
                    1 if is_private else 0,
                    password_hash,
                    now,
                    now,
                ),
            )
            return {"job_id": cur.lastrowid, "private_token": private_token}

    def list_jobs(self, status: Optional[str] = None) -> list[dict[str, Any]]:
        with self.lock, self.conn() as con:
            query = (
                "SELECT j.*, u.nickname AS author_nickname, u.is_banned AS author_is_banned, "
                "(SELECT COUNT(*) FROM job_accepts a WHERE a.job_id = j.id) AS accept_count "
                "FROM jobs j JOIN users u ON u.id = j.author_id "
            )
            params: list[Any] = []
            if status:
                query += "WHERE j.status = ? "
                params.append(status)
            query += "ORDER BY j.created_at DESC"
            rows = con.execute(query, params).fetchall()
            return [self._job_row_to_public_dict(row) for row in rows]

    def my_authored_jobs(self, user_id: int) -> list[dict[str, Any]]:
        with self.lock, self.conn() as con:
            rows = con.execute(
                "SELECT j.*, (SELECT COUNT(*) FROM job_accepts a WHERE a.job_id = j.id) AS accept_count FROM jobs j WHERE author_id = ? ORDER BY created_at DESC",
                (user_id,),
            ).fetchall()
            return [self._job_row_to_author_dict(row, viewer_is_admin=False) for row in rows]

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
            items: list[dict[str, Any]] = []
            for row in rows:
                item = self._job_row_to_public_dict(row)
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

        data = self._job_row_to_public_dict(row)
        can_view_description = False
        if not row["is_private"]:
            can_view_description = True
        elif is_admin or is_author:
            can_view_description = True
        elif unlock_token and row["description_password_hash"] and pbkdf2_verify(unlock_token, row["description_password_hash"]):
            can_view_description = True

        data["description_visible"] = can_view_description
        data["description"] = crypto.dec(row["description_enc"]) if can_view_description else None

        with self.lock, self.conn() as con:
            accepted = con.execute(
                "SELECT 1 FROM job_accepts WHERE job_id = ? AND user_id = ?",
                (job_id, viewer_id or -1),
            ).fetchone() is not None
            data["viewer_has_accepted"] = accepted

            if is_author or is_admin:
                workers = con.execute(
                    "SELECT u.id, u.nickname, u.contact_info_enc, u.reputation, u.is_banned FROM job_accepts a JOIN users u ON u.id = a.user_id WHERE a.job_id = ? ORDER BY a.created_at ASC",
                    (job_id,),
                ).fetchall()
                data["worker_pool"] = [
                    {
                        "id": int(w["id"]),
                        "nickname": str(w["nickname"]),
                        "contact_info": crypto.dec(w["contact_info_enc"]),
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
            row = con.execute("SELECT author_id, status FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if row is None:
                return False, "Job not found."
            if row["status"] != "open":
                return False, "Job is not open."
            if row["author_id"] == user_id:
                return False, "Author cannot accept own job."
            try:
                con.execute(
                    "INSERT INTO job_accepts (job_id, user_id, created_at) VALUES (?, ?, ?)",
                    (job_id, user_id, int(time.time())),
                )
                return True, "Job accepted."
            except sqlite3.IntegrityError:
                return False, "You already accepted this job."

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
                con.execute(
                    "UPDATE users SET reputation = reputation + 1 WHERE id = ?",
                    (job["selected_worker_id"],),
                )
            return True, f"Job status set to {new_status}."

    def _job_row_to_public_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        author_is_banned = bool(row["author_is_banned"]) if "author_is_banned" in row.keys() else False
        author_nickname = str(row["author_nickname"])
        author_display = f"{BAN_LABEL} {author_nickname}" if author_is_banned else author_nickname
        return {
            "id": row["id"],
            "title": crypto.dec(row["title_enc"]),
            "reward": row["reward"],
            "is_private": bool(row["is_private"]),
            "status": row["status"],
            "author_id": row["author_id"],
            "author_nickname": author_nickname,
            "author_is_banned": author_is_banned,
            "author_display": author_display,
            "accept_count": row["accept_count"] if "accept_count" in row.keys() else 0,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _job_row_to_author_dict(self, row: sqlite3.Row, viewer_is_admin: bool) -> dict[str, Any]:
        return {
            "id": row["id"],
            "title": crypto.dec(row["title_enc"]),
            "reward": row["reward"],
            "is_private": bool(row["is_private"]),
            "status": row["status"],
            "accept_count": row["accept_count"] if "accept_count" in row.keys() else 0,
            "selected_worker_id": row["selected_worker_id"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }


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
    def __init__(self, window_seconds: int, max_hits: int) -> None:
        self.window_seconds = window_seconds
        self.max_hits = max_hits
        self.lock = threading.Lock()
        self.hits: dict[str, list[float]] = {}

    def allow(self, key: str) -> tuple[bool, int]:
        now = time.time()
        with self.lock:
            bucket = self.hits.setdefault(key, [])
            bucket[:] = [ts for ts in bucket if now - ts < self.window_seconds]
            if len(bucket) >= self.max_hits:
                retry = int(self.window_seconds - (now - bucket[0])) + 1
                return False, max(retry, 1)
            bucket.append(now)
            return True, 0


class LoginThrottle:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.failures: dict[str, list[float]] = {}
        self.locked_until: dict[str, float] = {}

    def check(self, ip: str, nickname: str) -> tuple[bool, int]:
        key = f"{ip}|{nickname.lower()}"
        now = time.time()
        with self.lock:
            locked = self.locked_until.get(key, 0)
            if locked > now:
                return False, int(locked - now) + 1
            return True, 0

    def success(self, ip: str, nickname: str) -> None:
        key = f"{ip}|{nickname.lower()}"
        with self.lock:
            self.failures.pop(key, None)
            self.locked_until.pop(key, None)

    def fail(self, ip: str, nickname: str) -> tuple[bool, int]:
        key = f"{ip}|{nickname.lower()}"
        now = time.time()
        with self.lock:
            bucket = self.failures.setdefault(key, [])
            bucket[:] = [ts for ts in bucket if now - ts < AUTH_WINDOW_SECONDS]
            bucket.append(now)
            if len(bucket) >= AUTH_FAIL_LIMIT:
                self.locked_until[key] = now + AUTH_LOCK_SECONDS
                return False, AUTH_LOCK_SECONDS
            return True, 0


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
}


def require_session(request: dict[str, Any]) -> tuple[Optional[Session], Optional[dict[str, Any]]]:
    session = sessions.get(request.get("session_token"))
    if not session:
        return None, err("Authentication required.", "auth_required")
    user = db.get_user(session.user_id)
    if user is None:
        sessions.delete(session.token)
        return None, err("User not found.", "auth_required")
    if bool(user["is_banned"]):
        sessions.delete(session.token)
        return None, err("This account is banned.", "account_banned")
    return session, None


def handle_request(request: dict[str, Any], ip: str) -> dict[str, Any]:
    shape_problem = ensure_request_shape(request)
    if shape_problem:
        return err(shape_problem, "bad_request")

    action = request.get("action")
    if not isinstance(action, str):
        return err("Missing action.", "bad_request")
    if action not in VALID_ACTIONS:
        return err("Unknown action.", "unknown_action")

    if action == "ping":
        return ok({"server": "AFTERLIFE-space", "version": 2}, "pong")

    if action == "register":
        nickname = str(request.get("nickname", "")).strip()
        password = str(request.get("password", ""))
        contact_info = str(request.get("contact_info", "")).strip()
        problem = validate_nickname(nickname) or validate_password(password) or validate_contact_info(contact_info)
        if problem:
            return err(problem, "validation_error")
        success, message = db.create_user(nickname, password, contact_info)
        return ok(message=message) if success else err(message, "register_failed")

    if action == "login":
        nickname = str(request.get("nickname", "")).strip()
        password = str(request.get("password", ""))
        allowed_login, retry = login_throttle.check(ip, nickname)
        if not allowed_login:
            return err("Login temporarily blocked for this nickname from your address.", "login_throttled", retry)
        known_user = db.get_user_by_nickname(nickname)
        if known_user is not None and bool(known_user["is_banned"]):
            login_throttle.fail(ip, nickname)
            time.sleep(1.0)
            return err("This account is banned.", "account_banned")
        user = db.authenticate(nickname, password)
        if not user:
            login_throttle.fail(ip, nickname)
            time.sleep(1.0)
            return err("Invalid credentials.", "login_failed")
        login_throttle.success(ip, nickname)
        session = sessions.create(user)
        return ok(
            {
                "session_token": session.token,
                "nickname": session.nickname,
                "reputation": user["reputation"],
            },
            "Login successful.",
        )

    if action == "logout":
        sessions.delete(request.get("session_token"))
        return ok(message="Logged out.")

    if action == "profile":
        session, failure = require_session(request)
        if failure:
            return failure
        user = db.get_user(session.user_id)
        if user is None:
            return err("User not found.", "not_found")
        return ok(
            {
                "nickname": user["nickname"],
                "contact_info": crypto.dec(user["contact_info_enc"]),
                "reputation": user["reputation"],
                "created_at": user["created_at"],
                "is_admin": bool(user["is_admin"]),
                "is_banned": bool(user["is_banned"]),
            }
        )

    if action == "list_jobs":
        status = request.get("status")
        if status is not None and status not in {"open", "done", "cancelled"}:
            return err("Invalid status filter.", "validation_error")
        return ok({"jobs": db.list_jobs(status=status)})

    if action == "my_jobs":
        session, failure = require_session(request)
        if failure:
            return failure
        return ok({"jobs": db.my_authored_jobs(session.user_id)})

    if action == "my_accepts":
        session, failure = require_session(request)
        if failure:
            return failure
        return ok({"jobs": db.my_accepted_jobs(session.user_id)})

    if action == "create_job":
        session, failure = require_session(request)
        if failure:
            return failure
        title = str(request.get("title", "")).strip()
        description = str(request.get("description", "")).strip()
        reward_raw = str(request.get("reward", "")).strip()
        is_private, bool_problem = parse_bool_field(request.get("is_private", False), "is_private")
        problem = validate_title(title) or validate_description(description) or validate_reward(reward_raw) or bool_problem
        if problem:
            return err(problem, "validation_error")
        result = db.create_job(session.user_id, title, description, int(reward_raw), bool(is_private))
        return ok(result, "Job created.")

    if action == "job_details":
        job_id = request.get("job_id")
        unlock_token = request.get("unlock_token")
        try:
            job_id_int = int(job_id)
        except Exception:
            return err("Invalid job id.", "validation_error")
        session = sessions.get(request.get("session_token"))
        viewer_id = session.user_id if session else None
        success, message, data = db.get_job_for_viewer(job_id_int, viewer_id, str(unlock_token) if unlock_token else None)
        return ok(data, message) if success and data is not None else err(message, "not_found")

    if action == "accept_job":
        session, failure = require_session(request)
        if failure:
            return failure
        try:
            job_id = int(request.get("job_id"))
        except Exception:
            return err("Invalid job id.", "validation_error")
        success, message = db.accept_job(job_id, session.user_id)
        return ok(message=message) if success else err(message, "accept_failed")

    if action == "withdraw_job":
        session, failure = require_session(request)
        if failure:
            return failure
        try:
            job_id = int(request.get("job_id"))
        except Exception:
            return err("Invalid job id.", "validation_error")
        success, message = db.withdraw_accept(job_id, session.user_id)
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
        success, message = db.set_selected_worker(job_id, session.user_id, worker_id)
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
        success, message = db.set_job_status(job_id, session.user_id, status)
        return ok(message=message) if success else err(message, "status_failed")

    if action == "delete_job":
        session, failure = require_session(request)
        if failure:
            return failure
        try:
            job_id = int(request.get("job_id"))
        except Exception:
            return err("Invalid job id.", "validation_error")
        success, message = db.delete_job(session.user_id, job_id)
        return ok(message=message) if success else err(message, "delete_failed")

    if action == "ban_user":
        session, failure = require_session(request)
        if failure:
            return failure
        nickname = str(request.get("nickname", "")).strip()
        problem = validate_nickname(nickname)
        if problem:
            return err(problem, "validation_error")
        success, message, banned_user_id = db.ban_user(session.user_id, nickname)
        if success and banned_user_id is not None:
            sessions.delete_user_sessions(banned_user_id)
            return ok(message=message)
        return err(message, "ban_failed")

    return err("Unknown action.", "unknown_action")


class ClientHandler:
    def __init__(self, sock: socket.socket, addr: tuple[str, int], active_connections: set[str], active_lock: threading.Lock) -> None:
        self.sock = sock
        self.addr = addr
        self.active_connections = active_connections
        self.active_lock = active_lock

    def run(self) -> None:
        ip, port = self.addr[0], self.addr[1]
        peer = f"{ip}:{port}"
        log(f"Client connected: {peer}")
        self.sock.settimeout(READ_TIMEOUT_SECONDS)
        file = self.sock.makefile("rwb")
        try:
            while True:
                allowed, retry = global_limiter.allow(ip)
                if not allowed:
                    response = err("Too many requests. Slow down.", "rate_limited", retry)
                    file.write((json.dumps(response) + "\n").encode("utf-8"))
                    file.flush()
                    break

                line = file.readline(MAX_REQUEST_LINE_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_REQUEST_LINE_BYTES and not line.endswith(b"\n"):
                    response = err(f"Request line exceeds {MAX_REQUEST_LINE_BYTES} bytes.", "request_too_large")
                    file.write((json.dumps(response) + "\n").encode("utf-8"))
                    file.flush()
                    break
                if len(line) > MAX_REQUEST_LINE_BYTES:
                    response = err(f"Request line exceeds {MAX_REQUEST_LINE_BYTES} bytes.", "request_too_large")
                    file.write((json.dumps(response) + "\n").encode("utf-8"))
                    file.flush()
                    break
                try:
                    request = json.loads(line.decode("utf-8"))
                except Exception:
                    allowed_parse, retry_parse = parse_error_limiter.allow(ip)
                    response = err("Invalid JSON.", "bad_json", None if allowed_parse else retry_parse)
                    file.write((json.dumps(response) + "\n").encode("utf-8"))
                    file.flush()
                    if not allowed_parse:
                        break
                    continue

                response = handle_request(request, ip)
                file.write((json.dumps(response) + "\n").encode("utf-8"))
                file.flush()
        except (ConnectionError, TimeoutError, OSError):
            pass
        finally:
            try:
                file.close()
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
            with self.active_lock:
                self.active_connections.discard(peer)
            log(f"Client disconnected: {peer}")


class Server:
    def __init__(self, host: str, port: int, ssl_context: ssl.SSLContext) -> None:
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.sock: Optional[socket.socket] = None
        self.stop_event = threading.Event()
        self.executor = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="afterlife-client")
        self.active_connections: set[str] = set()
        self.active_lock = threading.Lock()

    def serve(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(MAX_CONNECTIONS)
            self.sock = sock
            log(f"AFTERLIFE Space TLS server listening on {self.host}:{self.port}")
            while not self.stop_event.is_set():
                try:
                    client, addr = sock.accept()
                except OSError:
                    break
                peer = f"{addr[0]}:{addr[1]}" if addr else "unknown"
                with self.active_lock:
                    if len(self.active_connections) >= MAX_CONNECTIONS:
                        log(f"Connection rejected due to capacity limit: {peer}")
                        try:
                            client.close()
                        except OSError:
                            pass
                        continue
                    self.active_connections.add(peer)
                try:
                    tls_client = self.ssl_context.wrap_socket(client, server_side=True)
                except ssl.SSLError as exc:
                    log(f"TLS handshake failed for {peer}: {exc}")
                    with self.active_lock:
                        self.active_connections.discard(peer)
                    try:
                        client.close()
                    except OSError:
                        pass
                    continue
                handler = ClientHandler(tls_client, addr, self.active_connections, self.active_lock)
                self.executor.submit(handler.run)

    def stop(self) -> None:
        self.stop_event.set()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.executor.shutdown(wait=False, cancel_futures=True)


def build_server_ssl_context(certfile: str, keyfile: Optional[str]) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = TLS_MIN_VERSION
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    # Conservative hardening for TLS 1.2 suites.
    # TLS 1.3 suites are managed separately by OpenSSL and are not configured here.
    try:
        context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!eNULL:!MD5:!RC4:!3DES:!DES:!EXPORT:!PSK")
    except ssl.SSLError:
        pass

    return context


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "AFTERLIFE Space server. TLS is mandatory. Pass --cert with a PEM file containing the server certificate "
            "and private key, or combine --cert with --key if they are stored separately."
        )
    )
    parser.add_argument("--host", default=HOST, help=f"Bind address (default: {HOST})")
    parser.add_argument("--port", type=int, default=PORT, help=f"Bind port (default: {PORT})")
    parser.add_argument(
        "--cert",
        required=True,
        help=(
            "Path to the server PEM certificate. This may be a combined PEM containing both certificate and key. "
            "The server refuses plaintext transport and will not start without TLS material."
        ),
    )
    parser.add_argument(
        "--key",
        default=None,
        help="Optional private key PEM path when the key is not embedded in --cert.",
    )
    parser.add_argument(
        "--advertised-name",
        default=None,
        help=(
            "Optional hostname or IP that clients are expected to validate. "
            "Used only for startup certificate SAN warnings."
        ),
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    try:
        db = Database(DB_PATH)
    except Exception as exc:
        log(f"Unable to initialize database/bootstrap state: {exc}")
        raise SystemExit(1)

    cert_path = Path(args.cert)
    key_path = Path(args.key) if args.key else None

    try:
        validate_tls_files(cert_path, key_path)
        cert_info = read_certificate_info(cert_path)
        startup_log_certificate_info(cert_info, args.advertised_name)
    except Exception as exc:
        log(f"Unable to validate TLS certificate material: {exc}")
        raise SystemExit(1)

    try:
        ssl_context = build_server_ssl_context(args.cert, args.key)
    except Exception as exc:
        log(f"Unable to load TLS certificate material: {exc}")
        raise SystemExit(1)

    server = Server(args.host, args.port, ssl_context)
    try:
        server.serve()
    except KeyboardInterrupt:
        log("Server interrupted by operator.")
    finally:
        server.stop()