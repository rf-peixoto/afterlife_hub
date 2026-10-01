"""Request dispatch. Runs in worker threads; never blocks on the network."""
from __future__ import annotations

import base64
import binascii
import math
import re
import statistics
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from . import config as C
from .crypto import clamp_difficulty, difficulty_for_reputation
from .db import Database
from .security import (Session, SlidingWindowLimiter, challenge_limiter, challenges, forum_write_limiter,
                       login_fail_tracker, message_limiter, preauth_limiter, search_limiter, session_limiter, sessions)
from .util import (audit_log, normalize_multiline, pagination_meta, parse_bool, parse_int, parse_page,
                   validate_comment, validate_description, validate_min_reputation, validate_nickname,
                   validate_password, validate_reward, validate_search_query, validate_thread_body,
                   validate_thread_title, validate_title)

PROTOCOL_VERSION = 3
FP_RE = re.compile(r"^[0-9a-f]{32}$")
password_change_limiter = SlidingWindowLimiter(3600, 5)


@dataclass
class Ctx:
    circuit: str                     # "circ:<id>" or "local:<peer>" in dev mode
    db: Database
    session: Optional[Session] = None
    user: Any = None


def ok(data: Optional[dict[str, Any]] = None, message: str = "OK") -> dict[str, Any]:
    return {"ok": True, "message": message, "data": data or {}}


def err(message: str, code: str = "error", retry_after: Optional[int] = None, data: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    out: dict[str, Any] = {"ok": False, "error": code, "message": message}
    if retry_after is not None:
        out["retry_after"] = int(retry_after)
    if data:
        out["data"] = data
    return out


def _s(request: dict[str, Any], key: str, default: str = "") -> str:
    v = request.get(key, default)
    return v.strip() if isinstance(v, str) else ("" if v is None else str(v).strip())


# ============================================================== session / pow helpers
def _timing_check(ctx: Ctx) -> None:
    """Metronomic-timing signal: flagged at most once per session."""
    s = ctx.session
    if s is None or s.is_admin or s.timing_flagged or len(s.request_times) < C.TIMING_MIN_SAMPLES:
        return
    times = list(s.request_times)
    intervals = [b - a for a, b in zip(times, times[1:]) if b - a > 0]
    if len(intervals) < C.TIMING_MIN_SAMPLES - 1:
        return
    mean = statistics.fmean(intervals)
    if mean > 0 and statistics.pstdev(intervals) / mean < C.TIMING_REGULARITY_CV:
        s.timing_flagged = True
        ctx.db.flag(s.user_id, s.nickname, "metronomic_timing", f"request interval CV below {C.TIMING_REGULARITY_CV} over {len(intervals)} samples")


def require_session(request: dict[str, Any], ctx: Ctx) -> Optional[dict[str, Any]]:
    session = sessions.get(request.get("session_token"))
    if session is None:
        return err("Authentication required.", "auth_required")
    allowed, retry = session_limiter.allow(f"user:{session.user_id}")
    if not allowed:
        audit_log("session_rate_limited", actor=session.nickname, status="blocked", noisy=True)
        return err("Too many requests. Slow down.", "rate_limited", retry)
    user = ctx.db.get_user(session.user_id)
    if user is None or user["is_banned"] or user["status"] != "active":
        sessions.delete(session.token)
        return err("Your session is no longer valid.", "auth_required")
    session.is_admin = bool(user["is_admin"])
    session.request_times.append(time.time())
    ctx.session, ctx.user = session, user
    _timing_check(ctx)
    return None


def _subject(ctx: Ctx) -> str:
    return f"user:{ctx.session.user_id}" if ctx.session else ""


def pow_exempt(ctx: Ctx, purpose: str) -> bool:
    if purpose not in C.POW_WRITE_PURPOSES or ctx.user is None:
        return False
    return bool(ctx.user["is_admin"]) or float(ctx.user["reputation"]) >= C.POW_WRITE_EXEMPT_REP


def require_pow(request: dict[str, Any], ctx: Ctx, purpose: str, subject: str) -> Optional[dict[str, Any]]:
    if pow_exempt(ctx, purpose):
        return None
    cid, nonce = request.get("challenge_id"), request.get("nonce")
    if not cid or nonce is None:
        return err("Proof-of-work required. Call get_challenge first.", "challenge_required")
    accepted, message = challenges.consume(cid, nonce, purpose, subject)
    if not accepted:
        return err(message, "challenge_failed")
    return None


def _write_gate(request: dict[str, Any], ctx: Ctx, action: str) -> Optional[dict[str, Any]]:
    """Quota/read-only check BEFORE any proof-of-work is spent, then PoW."""
    reason = ctx.db.precheck_write(ctx.session.user_id, action)
    if reason:
        return err(reason, "not_allowed")
    return require_pow(request, ctx, action, _subject(ctx))


def _result(res: tuple[bool, str, Any], code: str, data: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    success, message, payload = res
    if success:
        return ok(data if data is not None else (payload if isinstance(payload, dict) else None), message)
    retry = payload.get("retry_after") if isinstance(payload, dict) else None
    return err(message, code, retry, payload if isinstance(payload, dict) and "code" in payload else None)


# ============================================================== pre-auth actions
def a_ping(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    return ok({"server": "AFTERLIFE", "version": PROTOCOL_VERSION}, "Welcome to AFTERLIFE")


def a_get_challenge(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    purpose = _s(request, "purpose")
    if purpose not in C.POW_PURPOSES:
        return err("Invalid challenge purpose.", "validation_error")
    if purpose in C.POW_SESSION_PURPOSES:
        failure = require_session(request, ctx)
        if failure:
            return failure
        if pow_exempt(ctx, purpose):
            return ok({"required": False}, "No proof-of-work needed for your account.")
        limit_key, issuer, subject = f"user:{ctx.session.user_id}", f"user:{ctx.session.user_id}", _subject(ctx)
        difficulty = difficulty_for_reputation(float(ctx.user["reputation"]))
    else:
        allowed, retry = preauth_limiter.allow(f"{ctx.circuit}:challenge")
        if not allowed:
            return err("Requesting challenges too fast. Slow down.", "rate_limited", retry)
        limit_key = issuer = ctx.circuit
        if purpose == "register":
            subject = ""
            difficulty = clamp_difficulty(C.POW_BASE_DIFFICULTY + ctx.db.registration_extra_bits())
        else:
            nickname = _s(request, "nickname")
            if validate_nickname(nickname):
                return err("A valid nickname is required to request a login challenge.", "validation_error")
            subject = nickname.lower()
            difficulty = clamp_difficulty(C.POW_BASE_DIFFICULTY + login_fail_tracker.extra_difficulty(subject, ctx.circuit))
    allowed, retry = challenge_limiter.allow(limit_key)
    if not allowed:
        return err("Requesting challenges too fast. Slow down.", "rate_limited", retry)
    issued, reason = challenges.issue(purpose, subject, difficulty, issuer)
    if issued is None:
        if reason == "too_many_outstanding":
            return err("Too many unsolved challenges. Solve or let them expire first.", "rate_limited", 30)
        return err("Server is busy issuing challenges. Try again shortly.", "server_busy", 10)
    issued["required"] = True
    return ok(issued, "Solve the proof-of-work challenge.")


def a_register(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    allowed, retry = preauth_limiter.allow(f"{ctx.circuit}:register")
    if not allowed:
        return err("Too many attempts. Slow down.", "rate_limited", retry)
    nickname, password = _s(request, "nickname"), request.get("password")
    password = password if isinstance(password, str) else ""
    invite = _s(request, "invite_code") or None
    problem = validate_nickname(nickname, for_registration=True) or validate_password(password)
    if not problem and invite and not C.INVITE_CODE_RE.fullmatch(invite):
        problem = "Invalid invite code format."
    if problem:
        return err(problem, "validation_error")
    failure = require_pow(request, ctx, "register", "")
    if failure:
        return failure
    res = ctx.db.register_user(nickname, password, invite, request.get("public_key") or None)
    audit_log("user_register", actor=nickname, status="success" if res[0] else "fail", details=res[1], noisy=not res[0])
    return _result(res, "register_failed")


def a_login(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    allowed, retry = preauth_limiter.allow(f"{ctx.circuit}:login")
    if not allowed:
        return err("Too many attempts. Slow down.", "rate_limited", retry)
    nickname, password = _s(request, "nickname"), request.get("password")
    # Malformed input is rejected WITHOUT touching the failure tracker, so it
    # cannot be used to raise someone else's login difficulty for free.
    if validate_nickname(nickname) or not isinstance(password, str) or not (1 <= len(password) <= C.MAX_PASSWORD_LEN):
        return err("Invalid credentials.", "login_failed")
    key = nickname.lower()
    failure = require_pow(request, ctx, "login", key)
    if failure:
        return failure
    user, reason = ctx.db.authenticate(nickname, password)
    if user is None:
        if reason == "pending":
            return err("Your account is awaiting administrator approval.", "account_pending")
        login_fail_tracker.fail(key, ctx.circuit)
        audit_log("login_failed", actor=nickname, status="fail", noisy=True)
        return err("Invalid credentials.", "login_failed")
    login_fail_tracker.success(key)
    session = sessions.create(int(user["id"]), str(user["nickname"]), bool(user["is_admin"]))
    audit_log("login_success", actor=session.nickname, status="success")
    with ctx.db.tx() as con:
        key_fp = ctx.db.current_key_fp(con, int(user["id"]))
    return ok({"session_token": session.token, "nickname": session.nickname, "reputation": round(float(user["reputation"]), 3),
               "is_admin": bool(user["is_admin"]), "key_fp": key_fp}, "Login successful.")


def a_logout(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    sessions.delete(request.get("session_token"))
    return ok(message="Logged out.")


# ============================================================== account
def a_profile(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    u = ctx.user
    with ctx.db.tx() as con:
        tc = ctx.db.trust_context(con, u)
        fp = ctx.db.current_key_fp(con, int(u["id"]))
    return ok({"nickname": str(u["nickname"]), "reputation": round(float(u["reputation"]), 3), "trust_level": tc["level"],
               "distinct_job_partners": tc["partners"], "created_at": int(u["created_at"]), "is_admin": bool(u["is_admin"]),
               "pow_difficulty": difficulty_for_reputation(float(u["reputation"])), "pow_exempt": pow_exempt(ctx, "create_job"),
               "key_fp": fp})


def a_change_password(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    allowed, retry = password_change_limiter.allow(f"user:{ctx.session.user_id}")
    if not allowed:
        return err("Too many password change attempts.", "rate_limited", retry)
    old, new = request.get("old_password"), request.get("new_password")
    if not isinstance(old, str) or not isinstance(new, str) or len(old) > C.MAX_PASSWORD_LEN:
        return err("Both old_password and new_password are required.", "validation_error")
    problem = validate_password(new)
    if problem:
        return err(problem, "validation_error")
    success, message, _ = ctx.db.change_password(ctx.session.user_id, old, new)
    audit_log("password_change", actor=ctx.session.nickname, status="success" if success else "fail")
    if not success:
        return err(message, "password_failed")
    sessions.delete_user_sessions(ctx.session.user_id)
    s = sessions.create(ctx.session.user_id, ctx.session.nickname, ctx.session.is_admin)
    return ok({"session_token": s.token}, message)


def a_set_public_key(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    res = ctx.db.set_public_key(ctx.session.user_id, request.get("public_key"))
    audit_log("key_rotate", actor=ctx.session.nickname, status="success" if res[0] else "fail")
    return _result(res, "key_failed")


def a_get_public_key(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    fp = _s(request, "fingerprint")
    nick = _s(request, "nickname")
    if fp:
        if not FP_RE.fullmatch(fp):
            return err("Invalid fingerprint.", "validation_error")
        return _result(ctx.db.get_public_key(ctx.session.user_id, None, fp), "not_found")
    if validate_nickname(nick):
        return err("Invalid nickname.", "validation_error")
    return _result(ctx.db.get_public_key(ctx.session.user_id, nick, None), "not_found")


# ============================================================== jobs
def a_list_jobs(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    status = request.get("status")
    if status is not None and status not in {"open", "awaiting_confirmation", "done", "disputed", "cancelled"}:
        return err("Invalid status filter.", "validation_error")
    items, total, page = ctx.db.list_jobs(ctx.session.user_id, status, parse_page(request))
    return ok({"jobs": items, "pagination": pagination_meta(total, page, C.PAGE_SIZE)})


def a_my_jobs(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    items, total, page = ctx.db.my_jobs(ctx.session.user_id, False, parse_page(request))
    return ok({"jobs": items, "pagination": pagination_meta(total, page, C.PAGE_SIZE)})


def a_my_accepts(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    items, total, page = ctx.db.my_jobs(ctx.session.user_id, True, parse_page(request))
    return ok({"jobs": items, "pagination": pagination_meta(total, page, C.PAGE_SIZE)})


def a_create_job(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    title, desc = _s(request, "title"), _s(request, "description")
    reward_raw, min_rep_raw = _s(request, "reward"), _s(request, "min_reputation", "0") or "0"
    is_private = parse_bool(request.get("is_private", False))
    problem = (validate_title(title) or validate_description(desc) or validate_reward(reward_raw)
               or validate_min_reputation(min_rep_raw) or (None if is_private is not None else "is_private must be true or false."))
    if problem:
        return err(problem, "validation_error")
    failure = _write_gate(request, ctx, "create_job")
    if failure:
        return failure
    res = ctx.db.create_job(ctx.session.user_id, title, desc, int(reward_raw), int(min_rep_raw), bool(is_private))
    audit_log("job_create", actor=ctx.session.nickname, job_id=(res[2] or {}).get("job_id"), status="success" if res[0] else "fail", details=res[1])
    return _result(res, "create_failed")


def _job_id(request: dict[str, Any]) -> Optional[int]:
    return parse_int(request.get("job_id"))


def a_job_details(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    jid = _job_id(request)
    if jid is None:
        return err("Invalid job id.", "validation_error")
    token = _s(request, "unlock_token") or None
    if token and not C.PRIVATE_TOKEN_RE.fullmatch(token):
        token = None
    return _result(ctx.db.job_for_viewer(jid, ctx.session.user_id, token), "not_found")


def a_accept_job(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    jid = _job_id(request)
    if jid is None:
        return err("Invalid job id.", "validation_error")
    token = _s(request, "private_token") or None
    if token and not C.PRIVATE_TOKEN_RE.fullmatch(token):
        return err("Invalid private token.", "accept_failed")
    failure = _write_gate(request, ctx, "accept_job")
    if failure:
        return failure
    res = ctx.db.accept_job(jid, ctx.session.user_id, token)
    audit_log("job_accept", actor=ctx.session.nickname, job_id=jid, status="success" if res[0] else "fail", details=res[1])
    return _result(res, "accept_failed")


def a_withdraw_job(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    jid = _job_id(request)
    if jid is None:
        return err("Invalid job id.", "validation_error")
    return _result(ctx.db.withdraw_accept(jid, ctx.session.user_id), "withdraw_failed")


def a_select_worker(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    jid, wid = _job_id(request), parse_int(request.get("worker_id"))
    if jid is None or wid is None:
        return err("Invalid identifiers.", "validation_error")
    res = ctx.db.select_worker(jid, ctx.session.user_id, wid)
    audit_log("job_select_worker", actor=ctx.session.nickname, job_id=jid, status="success" if res[0] else "fail", details=res[1])
    return _result(res, "select_failed")


def a_set_status(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    jid = _job_id(request)
    if jid is None:
        return err("Invalid job id.", "validation_error")
    res = ctx.db.set_job_status(jid, ctx.session.user_id, _s(request, "status").lower())
    audit_log("job_set_status", actor=ctx.session.nickname, job_id=jid, status="success" if res[0] else "fail", details=res[1])
    return _result(res, "status_failed")


def _worker_decision(request: dict[str, Any], ctx: Ctx, confirm: bool) -> dict[str, Any]:
    jid = _job_id(request)
    if jid is None:
        return err("Invalid job id.", "validation_error")
    res = ctx.db.worker_confirm(jid, ctx.session.user_id, confirm)
    audit_log("job_confirm" if confirm else "job_dispute", actor=ctx.session.nickname, job_id=jid, status="success" if res[0] else "fail", details=res[1])
    return _result(res, "confirm_failed")


def a_confirm_job(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    return _worker_decision(request, ctx, True)


def a_dispute_job(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    return _worker_decision(request, ctx, False)


def a_rate_user(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    nickname, rating = _s(request, "nickname"), _s(request, "rating").lower()
    jid = _job_id(request)
    if validate_nickname(nickname) or rating not in C.RATING_CHOICES or jid is None:
        return err("nickname, rating (positive/negative) and a completed job_id are required.", "validation_error")
    failure = require_pow(request, ctx, "rate_user", _subject(ctx))
    if failure:
        return failure
    res = ctx.db.rate_user(ctx.session.user_id, nickname, rating, jid)
    audit_log("user_rate", actor=ctx.session.nickname, target=nickname, job_id=jid, status="success" if res[0] else "fail", details=res[1])
    return _result(res, "rating_failed")


# ============================================================== blocks / chat
def _nick_action(request: dict[str, Any], ctx: Ctx, block: bool) -> dict[str, Any]:
    nickname = _s(request, "nickname")
    if validate_nickname(nickname):
        return err("Invalid nickname.", "validation_error")
    res = ctx.db.set_block(ctx.session.user_id, nickname, block)
    audit_log("user_block" if block else "user_unblock", actor=ctx.session.nickname, target=nickname, status="success" if res[0] else "fail")
    return _result(res, "block_failed", {})


def a_block_user(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    return _nick_action(request, ctx, True)


def a_unblock_user(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    return _nick_action(request, ctx, False)


def a_list_blocks(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    return ok({"blocks": ctx.db.list_blocks(ctx.session.user_id)})


def a_open_chat(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    nickname = _s(request, "nickname")
    if validate_nickname(nickname):
        return err("Invalid nickname.", "validation_error")
    with ctx.db.tx() as con:
        target = ctx.db.user_by_nick(con, nickname)
        existing = None
        if target is not None:
            low, high = sorted((ctx.session.user_id, int(target["id"])))
            existing = con.execute("SELECT 1 FROM chats WHERE user_low_id = ? AND user_high_id = ?", (low, high)).fetchone()
    if existing is None:               # only NEW chats cost quota + PoW
        failure = _write_gate(request, ctx, "open_chat")
        if failure:
            return failure
    res = ctx.db.open_chat(ctx.session.user_id, nickname)
    audit_log("chat_open", actor=ctx.session.nickname, target=nickname, status="success" if res[0] else "fail")
    return _result(res, "chat_failed")


def a_list_chats(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    items, total, page = ctx.db.list_chats(ctx.session.user_id, parse_page(request))
    return ok({"chats": items, "pagination": pagination_meta(total, page, C.PAGE_SIZE)})


def a_list_messages(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    chat_id = parse_int(request.get("chat_id"))
    before = request.get("before_id")
    before_id = parse_int(before) if before is not None else None
    if chat_id is None or (before is not None and before_id is None):
        return err("Invalid chat id.", "validation_error")
    return _result(ctx.db.list_messages(ctx.session.user_id, chat_id, before_id), "messages_failed")


def a_send_message(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    allowed, retry = message_limiter.allow(f"user:{ctx.session.user_id}")
    if not allowed:
        return err("Sending too fast. Slow down.", "rate_limited", retry)
    chat_id = parse_int(request.get("chat_id"))
    ct, sfp, rfp = _s(request, "ciphertext"), _s(request, "sender_key_fp"), _s(request, "recipient_key_fp")
    if chat_id is None or not FP_RE.fullmatch(sfp) or not FP_RE.fullmatch(rfp):
        return err("chat_id, ciphertext, sender_key_fp and recipient_key_fp are required.", "validation_error")
    if len(ct) > C.E2E_MAX_CIPHERTEXT_B64:
        return err("Message too long.", "validation_error")
    try:
        raw = base64.b64decode(ct, validate=True)
    except (binascii.Error, ValueError):
        return err("Ciphertext must be base64.", "validation_error")
    if len(raw) < 12 + 16 + 1:
        return err("Ciphertext too short.", "validation_error")
    res = ctx.db.send_message(ctx.session.user_id, chat_id, ct, sfp, rfp)
    audit_log("message_send", actor=ctx.session.nickname, chat_id=chat_id, status="success" if res[0] else "fail", noisy=not res[0])
    return _result(res, "send_failed")


# ============================================================== forum
def a_create_thread(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    allowed, retry = (True, 0) if ctx.session.is_admin else forum_write_limiter.allow(f"user:{ctx.session.user_id}")
    if not allowed:
        return err("Posting too fast. Slow down.", "rate_limited", retry)
    title, body = _s(request, "title"), normalize_multiline(request.get("body"))
    problem = validate_thread_title(title) or validate_thread_body(body)
    if problem:
        return err(problem, "validation_error")
    failure = _write_gate(request, ctx, "create_thread")
    if failure:
        return failure
    res = ctx.db.create_thread(ctx.session.user_id, title, body)
    audit_log("thread_create", actor=ctx.session.nickname, thread_id=res[2] if res[0] else None, status="success" if res[0] else "fail", details=res[1])
    return _result(res, "thread_failed", {"thread_id": res[2]} if res[0] else None)


def a_list_threads(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    items, total, page = ctx.db.list_threads(ctx.session.user_id, parse_page(request))
    return ok({"threads": items, "pagination": pagination_meta(total, page, C.PAGE_SIZE)})


def a_search_threads(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    allowed, retry = search_limiter.allow(f"user:{ctx.session.user_id}")
    if not allowed:
        return err("Searching too fast. Slow down.", "rate_limited", retry)
    query = _s(request, "query")
    problem = validate_search_query(query)
    if problem:
        return err(problem, "validation_error")
    items, total, page = ctx.db.search_threads(ctx.session.user_id, query, parse_page(request))
    return ok({"threads": items, "query": query, "pagination": pagination_meta(total, page, C.PAGE_SIZE)})


def a_thread_details(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    tid = parse_int(request.get("thread_id"))
    if tid is None:
        return err("Invalid thread id.", "validation_error")
    success, message, data = ctx.db.thread_for_viewer(tid, ctx.session.user_id, parse_page(request))
    if not success:
        return err(message, "not_found")
    if len(ctx.session.viewed_threads) < 5000:
        ctx.session.viewed_threads.add(tid)
    data["pagination"] = pagination_meta(data.pop("posts_total"), data.pop("posts_page"), C.POSTS_PAGE_SIZE)
    return ok(data, message)


def a_post_comment(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    allowed, retry = (True, 0) if ctx.session.is_admin else forum_write_limiter.allow(f"user:{ctx.session.user_id}")
    if not allowed:
        return err("Posting too fast. Slow down.", "rate_limited", retry)
    tid = parse_int(request.get("thread_id"))
    body = normalize_multiline(request.get("body"))
    if tid is None:
        return err("Invalid thread id.", "validation_error")
    problem = validate_comment(body)
    if problem:
        return err(problem, "validation_error")
    failure = _write_gate(request, ctx, "post_comment")
    if failure:
        return failure
    res = ctx.db.add_post(ctx.session.user_id, tid, body, viewed=tid in ctx.session.viewed_threads or ctx.session.is_admin)
    audit_log("thread_comment", actor=ctx.session.nickname, thread_id=tid, post_id=res[2] if res[0] else None, status="success" if res[0] else "fail", details=res[1])
    return _result(res, "comment_failed", {"comment_id": res[2]} if res[0] else None)


# ============================================================== invites
def a_create_invite(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    res = ctx.db.create_invite(ctx.session.user_id)
    audit_log("invite_create", actor=ctx.session.nickname, status="success" if res[0] else "fail", details=res[1])
    return _result(res, "invite_failed", {"invite_code": res[2]} if res[0] else None)


def a_list_invites(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    return ok({"invites": ctx.db.list_invites(ctx.session.user_id)})


def a_revoke_invite(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    iid = parse_int(request.get("invite_id"))
    if iid is None:
        return err("Invalid invite id.", "validation_error")
    return _result(ctx.db.revoke_invite(ctx.session.user_id, iid, ctx.session.is_admin), "revoke_failed")


# ============================================================== admin
def ad_settings(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    return ok({"registration_mode": ctx.db.registration_mode(), "approval_required": ctx.db.approval_required(),
               "registration_soft_cap_per_hour": C.REGISTRATION_SOFT_CAP_PER_HOUR,
               "registrations_last_hour": ctx.db.registrations_last_hour(), "pending_queue_max": C.PENDING_QUEUE_MAX})


def ad_set_mode(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    mode = _s(request, "mode").lower()
    if mode not in C.VALID_REG_MODES:
        return err(f"Mode must be one of: {', '.join(sorted(C.VALID_REG_MODES))}.", "validation_error")
    ctx.db.set_setting("registration_mode", mode)
    audit_log("admin_registration_mode", actor=ctx.session.nickname, status="success", details=mode)
    return ok(message=f"Registration mode set to {mode}.")


def ad_set_lock(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    enabled = parse_bool(request.get("enabled"))
    if enabled is None:
        return err("enabled must be true or false.", "validation_error")
    ctx.db.set_setting("approval_required", "1" if enabled else "0")
    audit_log("admin_approval_lock", actor=ctx.session.nickname, status="success", details=str(enabled))
    return ok(message=f"Registration approval lock {'enabled' if enabled else 'disabled'}.")


def ad_list_pending(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    items, total, page = ctx.db.list_pending(parse_page(request))
    return ok({"pending": items, "pagination": pagination_meta(total, page, C.ADMIN_PAGE_SIZE)})


def _ad_pending(request: dict[str, Any], ctx: Ctx, approve: bool) -> dict[str, Any]:
    nickname = _s(request, "nickname")
    if validate_nickname(nickname):
        return err("Invalid nickname.", "validation_error")
    res = ctx.db.set_pending_status(nickname, approve)
    audit_log("admin_user_status", actor=ctx.session.nickname, target=nickname, status="success" if res[0] else "fail", details=res[1])
    return _result(res, "status_failed", {})


def ad_approve(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    return _ad_pending(request, ctx, True)


def ad_reject(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    return _ad_pending(request, ctx, False)


def ad_rep(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    nickname = _s(request, "nickname")
    delta = request.get("delta")
    if validate_nickname(nickname) or isinstance(delta, bool) or not isinstance(delta, (int, float)) or not math.isfinite(delta) or abs(delta) > 1_000_000:
        return err("A valid nickname and a finite numeric delta are required.", "validation_error")
    res = ctx.db.admin_adjust_reputation(nickname, float(delta))
    audit_log("admin_rep", actor=ctx.session.nickname, target=nickname, status="success" if res[0] else "fail", details=res[1])
    return _result(res, "rep_failed", {})


def ad_list_flags(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    kind = _s(request, "kind") or None
    if kind and not re.fullmatch(r"[a-z_]{1,40}", kind):
        return err("Invalid kind.", "validation_error")
    items, total, page = ctx.db.list_flags(parse_bool(request.get("include_resolved", False)) is True, kind, parse_page(request))
    return ok({"flags": items, "pagination": pagination_meta(total, page, C.ADMIN_PAGE_SIZE)})


def ad_resolve_flag(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    fid = parse_int(request.get("flag_id"))
    if fid is None:
        return err("Invalid flag id.", "validation_error")
    return ok(message="Flag resolved.") if ctx.db.resolve_flag(fid) else err("Flag not found.", "not_found")


def ad_list_frozen(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    items, total, page = ctx.db.list_frozen_ratings(parse_page(request))
    return ok({"frozen_ratings": items, "pagination": pagination_meta(total, page, C.ADMIN_PAGE_SIZE)})


def ad_resolve_rating(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    r, t, j = parse_int(request.get("rater_id")), parse_int(request.get("target_id")), parse_int(request.get("job_id"))
    apply_it = parse_bool(request.get("apply"))
    if None in (r, t, j) or apply_it is None:
        return err("rater_id, target_id, job_id and apply (true/false) are required.", "validation_error")
    res = ctx.db.resolve_frozen_rating(r, t, j, apply_it)
    audit_log("admin_resolve_rating", actor=ctx.session.nickname, job_id=j, status="success" if res[0] else "fail", details=res[1])
    return _result(res, "resolve_failed", {})


def ad_list_disputes(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    items, total, page = ctx.db.list_disputes(parse_page(request))
    return ok({"disputes": items, "pagination": pagination_meta(total, page, C.ADMIN_PAGE_SIZE)})


def ad_resolve_dispute(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    jid = _job_id(request)
    if jid is None:
        return err("Invalid job id.", "validation_error")
    res = ctx.db.resolve_dispute(jid, _s(request, "outcome").lower())
    audit_log("admin_resolve_dispute", actor=ctx.session.nickname, job_id=jid, status="success" if res[0] else "fail", details=res[1])
    return _result(res, "resolve_failed", {})


def ad_delete_job(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    jid = _job_id(request)
    if jid is None:
        return err("Invalid job id.", "validation_error")
    res = ctx.db.remove_job(jid)
    audit_log("job_delete", actor=ctx.session.nickname, job_id=jid, status="success" if res[0] else "fail")
    return _result(res, "delete_failed", {})


def ad_delete_thread(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    tid = parse_int(request.get("thread_id"))
    if tid is None:
        return err("Invalid thread id.", "validation_error")
    res = ctx.db.delete_thread(tid)
    audit_log("thread_delete", actor=ctx.session.nickname, thread_id=tid, status="success" if res[0] else "fail")
    return _result(res, "delete_failed", {})


def ad_delete_comment(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    pid = parse_int(request.get("comment_id"))
    if pid is None:
        return err("Invalid comment id.", "validation_error")
    res = ctx.db.delete_post(pid)
    audit_log("comment_delete", actor=ctx.session.nickname, post_id=pid, status="success" if res[0] else "fail")
    return _result(res, "delete_failed", {})


def _ad_ban(request: dict[str, Any], ctx: Ctx, wipe: bool) -> dict[str, Any]:
    nickname = _s(request, "nickname")
    if validate_nickname(nickname):
        return err("Invalid nickname.", "validation_error")
    res = ctx.db.ban_user(nickname, wipe)
    if res[0] and res[2] is not None:
        sessions.delete_user_sessions(int(res[2]))
    audit_log("user_wipe" if wipe else "user_ban", actor=ctx.session.nickname, target=nickname, status="success" if res[0] else "fail", details=res[1])
    return _result(res, "ban_failed", {})


def ad_ban(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    return _ad_ban(request, ctx, False)


def ad_wipe(request: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    return _ad_ban(request, ctx, True)


# ============================================================== dispatch
Handler = Callable[[dict[str, Any], Ctx], dict[str, Any]]
PUBLIC: dict[str, Handler] = {"ping": a_ping, "get_challenge": a_get_challenge, "register": a_register,
                              "login": a_login, "logout": a_logout}
USER: dict[str, Handler] = {
    "profile": a_profile, "change_password": a_change_password, "set_public_key": a_set_public_key, "get_public_key": a_get_public_key,
    "list_jobs": a_list_jobs, "my_jobs": a_my_jobs, "my_accepts": a_my_accepts, "create_job": a_create_job,
    "job_details": a_job_details, "accept_job": a_accept_job, "withdraw_job": a_withdraw_job, "select_worker": a_select_worker,
    "set_status": a_set_status, "confirm_job": a_confirm_job, "dispute_job": a_dispute_job, "rate_user": a_rate_user,
    "block_user": a_block_user, "unblock_user": a_unblock_user, "list_blocks": a_list_blocks,
    "open_chat": a_open_chat, "list_chats": a_list_chats, "list_messages": a_list_messages, "send_message": a_send_message,
    "create_thread": a_create_thread, "list_threads": a_list_threads, "search_threads": a_search_threads,
    "thread_details": a_thread_details, "post_comment": a_post_comment,
    "create_invite": a_create_invite, "list_invites": a_list_invites, "revoke_invite": a_revoke_invite,
}
ADMIN: dict[str, Handler] = {
    "admin_get_settings": ad_settings, "admin_set_registration_mode": ad_set_mode, "admin_set_approval_lock": ad_set_lock,
    "admin_list_pending": ad_list_pending, "admin_approve_user": ad_approve, "admin_reject_user": ad_reject,
    "admin_rep": ad_rep, "admin_list_flags": ad_list_flags, "admin_resolve_flag": ad_resolve_flag,
    "admin_list_frozen_ratings": ad_list_frozen, "admin_resolve_rating": ad_resolve_rating,
    "admin_list_disputes": ad_list_disputes, "admin_resolve_dispute": ad_resolve_dispute,
    "delete_job": ad_delete_job, "delete_thread": ad_delete_thread, "delete_comment": ad_delete_comment,
    "ban_user": ad_ban, "wipe_user": ad_wipe,
}


def handle_request(request: Any, ctx: Ctx) -> dict[str, Any]:
    if not isinstance(request, dict):
        return err("Request must be a JSON object.", "bad_request")
    action = request.get("action")
    if not isinstance(action, str):
        return err("Missing action.", "bad_request")
    if action in PUBLIC:
        return PUBLIC[action](request, ctx)
    handler = USER.get(action) or ADMIN.get(action)
    if handler is None:
        audit_log("request_rejected", action="unknown_action", status="fail", noisy=True)
        return err("Unknown action.", "unknown_action")
    failure = require_session(request, ctx)
    if failure:
        return failure
    if action in ADMIN and not ctx.session.is_admin:
        return err("Admin only.", "not_allowed")
    return handler(request, ctx)
