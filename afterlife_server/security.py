"""Sessions, proof-of-work challenges, rate limiters and login-failure tracking.

All network-facing keys are per Tor circuit ("circ:<id>"), never a shared
address: every onion client arrives from the same loopback/unix endpoint, so a
shared key would let one client exhaust everybody's budget.
"""
from __future__ import annotations

import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional

from . import config as C
from .crypto import pow_solution_ok


# ============================================================== sessions
@dataclass
class Session:
    token: str
    user_id: int
    nickname: str
    is_admin: bool
    last_seen: float
    request_times: deque = field(default_factory=lambda: deque(maxlen=C.ACTIVITY_HISTORY))
    viewed_threads: set = field(default_factory=set)
    timing_flagged: bool = False


class SessionStore:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.sessions: dict[str, Session] = {}
        self._last_purge = time.time()

    def _purge(self, now: float) -> None:
        if now - self._last_purge < 60:
            return
        self._last_purge = now
        for tok in [t for t, s in self.sessions.items() if now - s.last_seen > C.SESSION_IDLE_SECONDS]:
            self.sessions.pop(tok, None)

    def create(self, user_id: int, nickname: str, is_admin: bool) -> Session:
        session = Session(secrets.token_urlsafe(32), user_id, nickname, is_admin, time.time())
        with self.lock:
            for tok in [t for t, s in self.sessions.items() if s.user_id == user_id]:
                self.sessions.pop(tok, None)
            self.sessions[session.token] = session
        return session

    def get(self, token: Any) -> Optional[Session]:
        if not isinstance(token, str) or not token or len(token) > 128:
            return None
        now = time.time()
        with self.lock:
            self._purge(now)
            s = self.sessions.get(token)
            if s is None:
                return None
            if now - s.last_seen > C.SESSION_IDLE_SECONDS:
                self.sessions.pop(token, None)
                return None
            s.last_seen = now
            return s

    def peek(self, token: Any) -> Optional[Session]:
        """Like get() but does not refresh the idle timer."""
        if not isinstance(token, str):
            return None
        with self.lock:
            return self.sessions.get(token)

    def delete(self, token: Any) -> None:
        if isinstance(token, str):
            with self.lock:
                self.sessions.pop(token, None)

    def delete_user_sessions(self, user_id: int) -> None:
        with self.lock:
            for tok in [t for t, s in self.sessions.items() if s.user_id == user_id]:
                self.sessions.pop(tok, None)


# ============================================================== rate limiting
class SlidingWindowLimiter:
    def __init__(self, window_seconds: float, max_events: int, max_keys: int = 200_000) -> None:
        self.window = window_seconds
        self.max_events = max_events
        self.max_keys = max_keys
        self.lock = threading.Lock()
        self.events: dict[str, deque] = {}
        self._last_prune = time.time()

    def _prune(self, now: float) -> None:
        if now - self._last_prune < self.window and len(self.events) < self.max_keys:
            return
        self._last_prune = now
        self.events = {k: v for k, v in self.events.items() if v and now - v[-1] <= self.window}

    def allow(self, key: str, cost: int = 1) -> tuple[bool, int]:
        now = time.time()
        with self.lock:
            self._prune(now)
            bucket = self.events.get(key)
            if bucket is None:
                bucket = deque()
                self.events[key] = bucket
            while bucket and now - bucket[0] > self.window:
                bucket.popleft()
            if len(bucket) + cost > self.max_events:
                retry = max(1, int(self.window - (now - bucket[0]))) if bucket else int(self.window)
                return False, retry
            for _ in range(cost):
                bucket.append(now)
            return True, 0


# ============================================================== proof-of-work challenges
class ChallengeManager:
    """One-time challenges, each bound to a purpose AND a subject:
    login -> the (case-folded) nickname, session purposes -> the user id,
    register -> nothing (but rate-limited per circuit).
    A challenge is removed BEFORE its solution is verified, so every challenge
    buys an attacker exactly one server-side scrypt evaluation."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.store: dict[str, dict[str, Any]] = {}
        self.outstanding: dict[str, int] = {}
        self._last_cleanup = 0.0

    def _cleanup(self, now: float, force: bool = False) -> None:
        if not force and now - self._last_cleanup < 5:
            return
        self._last_cleanup = now
        for cid in [cid for cid, c in self.store.items() if c["expires_at"] <= now]:
            self._drop(cid)

    def _drop(self, cid: str) -> Optional[dict[str, Any]]:
        c = self.store.pop(cid, None)
        if c is not None:
            k = c["issuer"]
            n = self.outstanding.get(k, 0) - 1
            if n <= 0:
                self.outstanding.pop(k, None)
            else:
                self.outstanding[k] = n
        return c

    def issue(self, purpose: str, subject: str, difficulty: int, issuer: str) -> tuple[Optional[dict[str, Any]], str]:
        now = time.time()
        with self.lock:
            self._cleanup(now)
            if self.outstanding.get(issuer, 0) >= C.POW_MAX_OUTSTANDING_PER_KEY:
                return None, "too_many_outstanding"
            if len(self.store) >= C.POW_MAX_CHALLENGES:
                self._cleanup(now, force=True)
                if len(self.store) >= C.POW_MAX_CHALLENGES:
                    return None, "store_full"
            cid = secrets.token_hex(16)
            prefix = secrets.token_hex(C.POW_PREFIX_BYTES)
            self.store[cid] = {"prefix": prefix, "difficulty": int(difficulty), "purpose": purpose,
                               "subject": subject, "issuer": issuer, "expires_at": now + C.POW_CHALLENGE_TTL}
            self.outstanding[issuer] = self.outstanding.get(issuer, 0) + 1
        return {
            "challenge_id": cid, "prefix": prefix, "difficulty": int(difficulty),
            "algorithm": "scrypt-leading-zero-bits",
            "scrypt": {"n": C.POW_SCRYPT_N, "r": C.POW_SCRYPT_R, "p": C.POW_SCRYPT_P, "dklen": 32},
            "expires_in": C.POW_CHALLENGE_TTL,
        }, "ok"

    def consume(self, challenge_id: Any, nonce: Any, purpose: str, subject: str) -> tuple[bool, str]:
        if not isinstance(challenge_id, str) or len(challenge_id) != 32:
            return False, "Challenge not found or expired. Request a new one."
        now = time.time()
        with self.lock:
            challenge = self._drop(challenge_id)       # single attempt, consumed up front
        if challenge is None or challenge["expires_at"] <= now:
            return False, "Challenge not found or expired. Request a new one."
        if challenge["purpose"] != purpose:
            return False, "Challenge was issued for a different action."
        if challenge["subject"] != subject:
            return False, "Challenge was issued for a different account."
        if not pow_solution_ok(challenge["prefix"], str(nonce), challenge["difficulty"]):
            return False, "Invalid proof-of-work solution. Request a new challenge."
        return True, "OK"


# ============================================================== login failures
class LoginFailTracker:
    """Escalates login PoW after failures without ever enabling a lockout:
    * per (nickname, circuit): up to +8 bits — punishes the guesser's circuit;
    * per nickname, from anywhere: +1 bit per 5 failures, capped at +3 bits —
      so a third party can make someone's login at most 8x slower.
    Failures are recorded only after a VALID proof-of-work was presented."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.per_circuit: dict[tuple[str, str], list[float]] = {}
        self.per_nick: dict[str, list[float]] = {}

    @staticmethod
    def _fresh(items: list[float], now: float) -> list[float]:
        return [t for t in items if now - t <= C.LOGIN_FAIL_WINDOW]

    def _prune(self, now: float) -> None:
        if len(self.per_circuit) > 100_000:
            self.per_circuit = {k: v for k, v in self.per_circuit.items() if self._fresh(v, now)}
        if len(self.per_nick) > 100_000:
            self.per_nick = {k: v for k, v in self.per_nick.items() if self._fresh(v, now)}

    def extra_difficulty(self, nick_key: str, circuit: str) -> int:
        now = time.time()
        with self.lock:
            c = self._fresh(self.per_circuit.get((nick_key, circuit), []), now)
            g = self._fresh(self.per_nick.get(nick_key, []), now)
        return min(C.LOGIN_FAIL_CIRCUIT_MAX_EXTRA, len(c)) + min(
            C.LOGIN_FAIL_GLOBAL_MAX_EXTRA, len(g) // C.LOGIN_FAIL_GLOBAL_STEP_EVERY)

    def fail(self, nick_key: str, circuit: str) -> None:
        now = time.time()
        with self.lock:
            self._prune(now)
            k = (nick_key, circuit)
            self.per_circuit[k] = self._fresh(self.per_circuit.get(k, []), now)[-50:] + [now]
            self.per_nick[nick_key] = self._fresh(self.per_nick.get(nick_key, []), now)[-100:] + [now]

    def success(self, nick_key: str) -> None:
        with self.lock:
            self.per_nick.pop(nick_key, None)
            for k in [k for k in self.per_circuit if k[0] == nick_key]:
                self.per_circuit.pop(k, None)


sessions = SessionStore()
challenges = ChallengeManager()
login_fail_tracker = LoginFailTracker()
circuit_limiter = SlidingWindowLimiter(C.CIRCUIT_RATE_WINDOW, C.CIRCUIT_RATE_MAX)
session_limiter = SlidingWindowLimiter(C.SESSION_RATE_WINDOW, C.SESSION_RATE_MAX)
message_limiter = SlidingWindowLimiter(C.MESSAGE_RATE_WINDOW, C.MESSAGE_RATE_MAX)
forum_write_limiter = SlidingWindowLimiter(C.FORUM_WRITE_WINDOW, C.FORUM_WRITE_MAX)
search_limiter = SlidingWindowLimiter(C.SEARCH_RATE_WINDOW, C.SEARCH_RATE_MAX)
challenge_limiter = SlidingWindowLimiter(C.CHALLENGE_RATE_WINDOW, C.CHALLENGE_RATE_MAX)
# Pre-auth actions (register/login/get_challenge without a session) get a
# tighter per-circuit budget.
preauth_limiter = SlidingWindowLimiter(60, 20)
