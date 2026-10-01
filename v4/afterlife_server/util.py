"""Logging, validation and small helpers."""
from __future__ import annotations

import hashlib
import json
import logging
import logging.handlers
import os
import re
import threading
import time
from typing import Any, Optional

from . import config as C

# ============================================================== logging
_logger = logging.getLogger("afterlife")
_logger_ready = False
_logger_lock = threading.Lock()


def setup_logging() -> None:
    """Size-rotated log file (0600) + stdout. Rotation bounds disk use."""
    global _logger_ready
    with _logger_lock:
        if _logger_ready:
            return
        C.LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        if not C.LOG_PATH.exists():
            fd = os.open(C.LOG_PATH, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
            os.close(fd)
        try:
            os.chmod(C.LOG_PATH, 0o600)
        except OSError:
            pass
        fmt = logging.Formatter("[%(asctime)s] %(message)s", "%Y-%m-%d %H:%M:%S")
        fh = logging.handlers.RotatingFileHandler(C.LOG_PATH, maxBytes=C.LOG_MAX_BYTES, backupCount=C.LOG_BACKUPS, encoding="utf-8")
        fh.setFormatter(fmt)
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        _logger.handlers[:] = [fh, sh]
        _logger.setLevel(logging.INFO)
        _logger.propagate = False
        _logger_ready = True


_SAN_RE = re.compile(r"\s+")


def sanitize_log_value(value: Any) -> str:
    text = str(value)[:300]
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    for ch in ("'", '"', "%", "|", "+", "="):
        text = text.replace(ch, "")
    return _SAN_RE.sub(" ", text).strip()


def log(message: str) -> None:
    if not _logger_ready:
        setup_logging()
    _logger.info(sanitize_log_value(message) if "\n" in message or "\r" in message else message)


class _Suppressor:
    """Collapses floods of identical noisy events (e.g. rejected requests) into
    one line per window, so an attacker cannot fill the disk through the log."""

    def __init__(self, window: float = 60.0) -> None:
        self.window = window
        self.lock = threading.Lock()
        self.state: dict[str, list[float]] = {}

    def should_log(self, key: str) -> tuple[bool, int]:
        now = time.time()
        with self.lock:
            st = self.state.get(key)
            if st is None or now - st[0] > self.window:
                suppressed = int(st[1]) if st else 0
                self.state[key] = [now, 0]
                if len(self.state) > 5000:
                    self.state = {k: v for k, v in self.state.items() if now - v[0] <= self.window}
                return True, suppressed
            st[1] += 1
            return False, 0


_suppressor = _Suppressor()

# Events whose actor/target pairing reveals the social graph; hidden in privacy mode.
_PRIVATE_EVENTS = {"chat_open", "message_send", "user_block", "user_unblock", "key_rotate"}


def audit_log(event: str, *, actor: Optional[str] = None, action: Optional[str] = None,
              target: Optional[str] = None, job_id: Optional[int] = None, chat_id: Optional[int] = None,
              thread_id: Optional[int] = None, post_id: Optional[int] = None, status: str = "INFO",
              details: Optional[str] = None, noisy: bool = False) -> None:
    if noisy:
        allowed, suppressed = _suppressor.should_log(f"{event}:{status}:{details}")
        if not allowed:
            return
        if suppressed:
            details = f"{details or ''} (+{suppressed} similar suppressed)"
    private = C.LOG_PRIVACY and event in _PRIVATE_EVENTS
    parts = [f"event={sanitize_log_value(event)}", f"status={sanitize_log_value(status)}"]
    if action:
        parts.append(f"action={sanitize_log_value(action)}")
    if actor and not private:
        parts.append(f"actor={sanitize_log_value(actor)}")
    if target and not private:
        parts.append(f"target={sanitize_log_value(target)}")
    if job_id is not None:
        parts.append(f"job_id={int(job_id)}")
    if chat_id is not None and not private:
        parts.append(f"chat_id={int(chat_id)}")
    if thread_id is not None:
        parts.append(f"thread_id={int(thread_id)}")
    if post_id is not None:
        parts.append(f"post_id={int(post_id)}")
    if details:
        parts.append(f"details={sanitize_log_value(details)}")
    log(" ".join(parts))


# ============================================================== JSON parsing
def _reject_constant(name: str) -> Any:
    raise ValueError(f"invalid JSON constant {name}")


def parse_request_json(raw: bytes) -> Any:
    """Strict JSON: no NaN/Infinity, bounded depth (checked iteratively)."""
    text = raw.decode("utf-8")
    depth = 0
    max_depth = 0
    in_str = False
    esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            max_depth = max(max_depth, depth)
            if max_depth > C.MAX_JSON_DEPTH:
                raise ValueError("JSON nesting too deep")
        elif ch in "]}":
            depth -= 1
    return json.loads(text, parse_constant=_reject_constant)


# ============================================================== field parsing
def parse_int(value: Any, *, lo: int = 1, hi: int = C.MAX_ID) -> Optional[int]:
    """Parse an identifier/integer strictly. Accepts ints or digit strings only."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        v = value
    elif isinstance(value, str) and re.fullmatch(r"-?\d{1,19}", value.strip()):
        v = int(value.strip())
    else:
        return None
    if v < lo or v > hi:
        return None
    return v


def parse_page(request: dict[str, Any]) -> int:
    v = parse_int(request.get("page", 1), lo=1, hi=C.MAX_PAGE)
    return v if v is not None else 1


def parse_bool(value: Any) -> Optional[bool]:
    return value if isinstance(value, bool) else None


def pagination_meta(total: int, page: int, per_page: int) -> dict[str, Any]:
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(max(1, page), total_pages)
    return {"page": page, "per_page": per_page, "total": total, "total_pages": total_pages,
            "has_prev": page > 1, "has_next": page < total_pages}


def clamp_page(total: int, page: int, per_page: int) -> tuple[int, int]:
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(max(1, page), total_pages)
    return page, (page - 1) * per_page


# ============================================================== validation
def has_forbidden_chars(value: str) -> bool:
    return any(ch in C.FORBIDDEN_CHARS for ch in value)


_CONFUSABLES = str.maketrans({"0": "o", "1": "i", "l": "i", "3": "e", "4": "a", "5": "s",
                              "7": "t", "8": "b", "9": "g", "2": "z", "6": "g"})


def nick_skeleton(nickname: str) -> str:
    """Case-folded, confusable-normalised form used for uniqueness and the
    reserved-name check, so 'Admin', 'adm1n' and 'a_d_m_i_n' collide."""
    s = nickname.lower().replace("_", "").translate(_CONFUSABLES)
    s = re.sub(r"rn", "m", s)
    s = re.sub(r"vv", "w", s)
    return s


def validate_nickname(nickname: str, *, for_registration: bool = False) -> Optional[str]:
    if not C.NICK_RE.fullmatch(nickname):
        return "Nickname must be 3-12 chars: letters, digits, underscore."
    if for_registration:
        sk = nick_skeleton(nickname)
        if len(sk) < 3:
            return "Nickname is too short once underscores are ignored."
        if sk in {nick_skeleton(r) for r in C.RESERVED_NICKS} or any(nick_skeleton(r) in sk for r in ("admin", "moderator", "afterlife", "system")):
            return "That nickname is reserved."
    return None


def validate_password(password: str) -> Optional[str]:
    if len(password) < C.MIN_PASSWORD_LEN:
        return f"Password must be at least {C.MIN_PASSWORD_LEN} characters."
    if len(password) > C.MAX_PASSWORD_LEN:
        return f"Password must be at most {C.MAX_PASSWORD_LEN} characters."
    if any(not ch.isprintable() for ch in password):
        return "Password contains control characters."
    return None


def _text(value: str, label: str, max_len: int, regex: re.Pattern[str]) -> Optional[str]:
    if not value or len(value) > max_len:
        return f"{label} must be 1-{max_len} characters."
    if has_forbidden_chars(value):
        return f"{label} contains forbidden characters."
    if not regex.fullmatch(value):
        return f"{label} contains unsupported characters (plain text only)."
    return None


def validate_title(v: str) -> Optional[str]:
    return _text(v, "Title", C.MAX_TITLE_LEN, C.ALLOWED_TEXT_RE)


def validate_description(v: str) -> Optional[str]:
    return _text(v, "Description", C.MAX_DESC_LEN, C.ALLOWED_TEXT_RE)


def validate_thread_title(v: str) -> Optional[str]:
    return _text(v, "Thread title", C.MAX_THREAD_TITLE_LEN, C.THREAD_TITLE_RE)


def validate_thread_body(v: str) -> Optional[str]:
    return _text(v, "Thread body", C.MAX_THREAD_BODY_LEN, C.THREAD_BODY_RE)


def validate_comment(v: str) -> Optional[str]:
    return _text(v, "Comment", C.MAX_COMMENT_LEN, C.COMMENT_RE)


def validate_search_query(v: str) -> Optional[str]:
    if len(v) < C.MIN_SEARCH_QUERY_LEN:
        return f"Search query must be at least {C.MIN_SEARCH_QUERY_LEN} characters."
    return _text(v, "Search query", C.MAX_SEARCH_QUERY_LEN, C.SEARCH_QUERY_RE)


def validate_reward(raw: str) -> Optional[str]:
    if not raw.isdigit() or len(raw) > 9:
        return "Reward must contain digits only."
    value = int(raw)
    if value < 1 or value > C.MAX_REWARD:
        return f"Reward must be between 1 and {C.MAX_REWARD}."
    return None


def validate_min_reputation(raw: str) -> Optional[str]:
    if not re.fullmatch(r"-?\d{1,7}", raw):
        return "Minimum reputation must be an integer."
    if abs(int(raw)) > C.MAX_MIN_REPUTATION:
        return f"Minimum reputation must be between {-C.MAX_MIN_REPUTATION} and {C.MAX_MIN_REPUTATION}."
    return None


def normalize_multiline(value: Any) -> str:
    return str(value if value is not None else "").replace("\r\n", "\n").replace("\r", "\n").strip()


# ============================================================== content fingerprinting
def tokenize(text: str) -> list[str]:
    return [t[:32] for t in C.TOKEN_RE.findall(text.lower())]


def simhash64(text: str) -> int:
    """64-bit SimHash returned as a SIGNED integer so it fits SQLite INTEGER."""
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
            out |= 1 << i
    return out - (1 << 64) if out >= (1 << 63) else out


def hamming(a: int, b: int) -> int:
    return bin((a ^ b) & ((1 << 64) - 1)).count("1")
