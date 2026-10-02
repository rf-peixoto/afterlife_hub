#!/usr/bin/env python3
"""Regression tests: one or more per finding of the security review.
Run: python3 tests/test_security.py   (no pytest needed)"""
from __future__ import annotations

import base64
import json
import os
import socket
import sqlite3
import stat
import sys
import threading
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from harness import ADMIN_PW, Api, ServerProc, admin, cl, new_circ, proxy_line, rand_text, user  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []
SRV: ServerProc


def test(fn):
    def run():
        t = time.time()
        try:
            fn()
            RESULTS.append((fn.__name__, True, f"{time.time() - t:.1f}s"))
            print(f"PASS {fn.__name__} ({time.time() - t:.1f}s)", flush=True)
        except Exception as exc:
            RESULTS.append((fn.__name__, False, f"{exc.__class__.__name__}: {exc}"))
            print(f"FAIL {fn.__name__}: {exc}", flush=True)
            traceback.print_exc()
    run.__name__ = fn.__name__
    TESTS.append(run)
    return run


TESTS: list = []


def job_flow(author: Api, worker: Api, worker_id: int, confirm: bool = True) -> int:
    r = author.write("create_job", title="job", description="d", reward="5", min_reputation="0", is_private=False)
    assert r["ok"], r
    jid = r["data"]["job_id"]
    r = worker.write("accept_job", job_id=jid)
    assert r["ok"], r
    assert author.rq("select_worker", job_id=jid, worker_id=worker_id)["ok"]
    assert author.rq("set_status", job_id=jid, status="done")["ok"]
    if confirm:
        r = worker.rq("confirm_job", job_id=jid)
        assert r["ok"], r
    return jid


def uid(a: Api, nick: str) -> int:
    con = sqlite3.connect(SRV.dir / "data" / "db")
    try:
        return int(con.execute("SELECT id FROM users WHERE nickname = ?", (nick,)).fetchone()[0])
    finally:
        con.close()


def rep(a: Api) -> float:
    return float(a.rq("profile")["data"]["reputation"])


# ---------------------------------------------------------------- #1 slowloris
@test
def t01_slowloris_idle_sockets_do_not_block_service():
    socks = []
    for i in range(300):
        s = socket.create_connection(("127.0.0.1", SRV.port))
        s.sendall(proxy_line(new_circ()))      # header, then nothing
        socks.append(s)
    t = time.time()
    r = Api(SRV).rq("ping")
    assert r["ok"] and time.time() - t < 2, (r, time.time() - t)
    # idle sockets are cut at the request deadline (3s in tests)
    socks[0].settimeout(10)
    t = time.time()
    data = socks[0].recv(1000)
    assert b"timed out" in data and time.time() - t < 6, (data, time.time() - t)
    for s in socks:
        s.close()


@test
def t01b_per_circuit_connection_cap():
    circ = new_circ()
    socks = []
    for _ in range(4):
        s = socket.create_connection(("127.0.0.1", SRV.port))
        s.sendall(proxy_line(circ))
        socks.append(s)
    time.sleep(0.3)
    r = Api(SRV, circ).rq("ping")
    assert not r["ok"] and r["error"] == "rate_limited", r
    assert Api(SRV).rq("ping")["ok"]          # other circuits unaffected
    for s in socks:
        s.close()


@test
def t01c_missing_proxy_header_rejected_in_production_mode():
    r = Api(SRV).raw({"action": "ping"}, header=False)
    assert r == {}, r


# ---------------------------------------------------------------- #2 per-circuit challenge buckets
@test
def t02_one_circuit_cannot_exhaust_challenges_for_everyone():
    attacker = Api(SRV)
    limited = False
    for _ in range(40):
        r = attacker.challenge("login", nickname="someone")
        if not r["ok"]:
            limited = True
            break
    assert limited, "attacker circuit was never limited"
    r = Api(SRV).challenge("login", nickname="someone")
    assert r["ok"], r


# ---------------------------------------------------------------- #3 / login escalation
@test
def t03_overlength_password_does_not_escalate_victim():
    user(SRV, "victim3")
    atk = Api(SRV)
    for _ in range(15):
        atk.rq("login", nickname="victim3", password="x" * 500)
    d = Api(SRV).challenge("login", nickname="victim3")["data"]["difficulty"]
    assert d == 2, d


@test
def t03b_third_party_failures_cap_at_plus_three_bits():
    user(SRV, "victim3b")
    for i in range(25):                        # valid PoW, wrong password, from many circuits
        a = Api(SRV)
        a.rq("login", nickname="victim3b", password="wrongpassword", **a.pow("login", nickname="victim3b"))
    d = Api(SRV).challenge("login", nickname="victim3b")["data"]["difficulty"]
    assert d <= 2 + 3, d
    a = Api(SRV)
    assert a.login("victim3b")["ok"]


@test
def t03c_attacker_circuit_escalates_itself():
    user(SRV, "victim3c")
    a = Api(SRV)
    for _ in range(4):
        a.rq("login", nickname="victim3c", password="wrongpassword", **a.pow("login", nickname="victim3c"))
    assert a.challenge("login", nickname="victim3c")["data"]["difficulty"] >= 2 + 4


# ---------------------------------------------------------------- #4 simhash overflow
@test
def t04_forum_posts_never_overflow():
    ad = admin(SRV)
    ok = 0
    for i in range(40):
        r = ad.rq("create_thread", title=f"thread {i}", body=rand_text(15))
        ok += r["ok"]
    assert ok == 40, ok
    tid = ad.rq("list_threads")["data"]["threads"][0]["id"]
    ad.rq("thread_details", thread_id=tid)
    for i in range(20):
        assert ad.rq("post_comment", thread_id=tid, body=rand_text(10))["ok"]
    assert "OverflowError" not in SRV.stdout()


# ---------------------------------------------------------------- #5 master key
@test
def t05_master_key_file_is_safe_and_wrong_key_refuses_start():
    key = SRV.dir / "secrets" / "master.key"
    text = key.read_text()
    assert text.startswith("afterlife-master-key-v2:")
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    other = ServerProc()
    try:
        other.stop()
        other_key = other.dir / "secrets" / "master.key"
        good = other_key.read_text()
        other_key.write_text(text)             # a different, valid key -> canary must fail
        other.start(expect_ok=False)
        other.proc.wait(10)
        assert other.proc.returncode == 2 and "canary" in other.stdout(), other.stdout()
        other_key.write_text("garbage\n")
        other.start(expect_ok=False)
        other.proc.wait(10)
        assert other.proc.returncode == 2 and "not an AFTERLIFE v2 key" in other.stdout()
        other_key.write_text(good.replace("\n", "") + "   \n\n")   # whitespace never alters the key
        other.start()
        assert Api(other).rq("ping")["ok"]
    finally:
        other.cleanup()


# ---------------------------------------------------------------- #6 single attempt per challenge
@test
def t06_challenge_consumed_on_first_attempt():
    a = Api(SRV)
    d = a.challenge("register")["data"]
    r = a.rq("register", nickname="pow6user", password="password1234", challenge_id=d["challenge_id"], nonce="999999999999")
    good = cl.solve_pow(d["prefix"], d["difficulty"], d["scrypt"])
    if r["ok"]:
        return                                 # bogus nonce happened to be valid at 2 bits
    r = a.rq("register", nickname="pow6user", password="password1234", challenge_id=d["challenge_id"], nonce=good)
    assert not r["ok"] and "not found" in r["message"], r


# ---------------------------------------------------------------- #7 challenge binding
@test
def t07_challenges_are_bound_to_their_subject():
    a = user(SRV, "bind7a")
    b = user(SRV, "bind7b")
    ad = admin(SRV)
    ad.rq("admin_rep", nickname="bind7b", delta=-8)
    # session purposes need a session
    r = Api(SRV).challenge("create_job")
    assert not r["ok"] and r["error"] == "auth_required", r
    # a challenge minted by A cannot be spent by B
    pf = a.pow("create_job")
    r = b.rq("create_job", title="t", description="d", reward="1", min_reputation="0", is_private=False, **pf)
    assert not r["ok"] and "different account" in r["message"], r
    # B's own challenge carries the higher difficulty
    assert b.challenge("create_job")["data"]["difficulty"] == 2 + 8
    # login challenge for nick X cannot log in nick Y
    x = Api(SRV)
    pf = x.pow("login", nickname="bind7a")
    r = x.rq("login", nickname="bind7b", password="password1234", **pf)
    assert not r["ok"] and "different account" in r["message"], r


# ---------------------------------------------------------------- #8 rating farm
@test
def t08_sybil_pair_cannot_mint_reputation():
    a, b = user(SRV, "syb8a"), user(SRV, "syb8b")
    ida, idb = uid(a, "syb8a"), uid(b, "syb8b")
    for i in range(4):
        jid = job_flow(a, b, idb)
        a.rq("rate_user", nickname="syb8b", rating="positive", job_id=jid, **a.pow("rate_user"))
        b.rq("rate_user", nickname="syb8a", rating="positive", job_id=jid, **b.pow("rate_user"))
    assert rep(a) == 0 and rep(b) == 0, (rep(a), rep(b))


@test
def t08b_trusted_pair_ratings_decay_and_are_budgeted():
    a, b = user(SRV, "tr8a"), user(SRV, "tr8b")
    ad = admin(SRV)
    ad.rq("admin_rep", nickname="tr8a", delta=10)
    idb = uid(b, "tr8b")
    gains = []
    for i in range(4):
        jid = job_flow(a, b, idb)
        before = rep(b)
        a.rq("rate_user", nickname="tr8b", rating="positive", job_id=jid, **a.pow("rate_user"))
        gains.append(round(rep(b) - before, 4))
    assert gains[0] == 1.0 and gains[1] == 0.5 and gains[2] == 0.25, gains
    assert sum(gains) <= 3.0 + 1e-9


# ---------------------------------------------------------------- #9 registration flood
@test
def t09_pending_queue_bounded_paginated_and_reject_frees_nick():
    srv = ServerProc(AFTERLIFE_PENDING_QUEUE_MAX="3", AFTERLIFE_REG_MAX_PER_HOUR="2")
    try:
        ad = admin(srv)
        ad.rq("admin_set_approval_lock", enabled=True)
        results = [Api(srv).register(f"pend{i}")["ok"] for i in range(5)]
        assert results == [True, True, True, False, False], results
        r = ad.rq("admin_list_pending")
        assert r["data"]["pagination"]["total"] == 3
        assert ad.rq("admin_reject_user", nickname="pend0")["ok"]
        assert Api(srv).register("pend0")["ok"]              # nickname released
        # soft cap -> registration gets more expensive instead of being queued
        assert Api(srv).challenge("register")["data"]["difficulty"] > 2
    finally:
        srv.cleanup()


# ---------------------------------------------------------------- #10 accept_job controls
@test
def t10_accept_job_needs_pow_quota_and_cannot_loop():
    author, spam = user(SRV, "auth10"), user(SRV, "spam10")
    jid = author.write("create_job", title="real", description="d", reward="9", min_reputation="0", is_private=False)["data"]["job_id"]
    r = spam.rq("accept_job", job_id=jid)
    assert not r["ok"] and r["error"] == "challenge_required", r
    assert spam.write("accept_job", job_id=jid)["ok"]
    assert spam.rq("withdraw_job", job_id=jid)["ok"]
    r = spam.write("accept_job", job_id=jid)
    assert not r["ok"] and "cannot accept it again" in r["message"], r
    chats = author.rq("list_chats")["data"]["chats"]
    assert [c["unread_count"] for c in chats] == [1], chats


@test
def t10b_readonly_window_applies_to_accept_and_precedes_pow():
    srv = ServerProc(AFTERLIFE_READONLY_WINDOW="3600")
    try:
        ad = admin(srv)
        jid = ad.rq("create_job", title="x", description="d", reward="1", min_reputation="0", is_private=False)["data"]["job_id"]
        u = user(srv, "newbie10")
        r = u.rq("accept_job", job_id=jid)                    # no PoW attached: told read-only first
        assert not r["ok"] and "read-only" in r["message"], r
    finally:
        srv.cleanup()


# ---------------------------------------------------------------- #11 private token cost
@test
def t11_private_token_guessing_is_cheap_for_server():
    ad = admin(SRV)
    u = user(SRV, "guess11")
    jid = ad.rq("create_job", title="p", description="secret", reward="1", min_reputation="0", is_private=True)["data"]["job_id"]
    t = time.time()
    for _ in range(20):
        r = u.rq("job_details", job_id=jid, unlock_token="A" * 24)
        assert r["data"]["description"] is None
    assert time.time() - t < 3, time.time() - t


# ---------------------------------------------------------------- #12 no global kill switch
@test
def t12_one_circuit_flood_does_not_affect_others():
    flood = Api(SRV)
    limited = 0
    for _ in range(140):
        limited += not flood.rq("ping")["ok"]
    assert limited > 0
    assert Api(SRV).rq("ping")["ok"]


# ---------------------------------------------------------------- #13 flag queue
@test
def t13_flags_are_deduplicated_and_not_spammable():
    u = user(SRV, "flag13")
    ad = admin(SRV)
    tid = ad.rq("create_thread", title="flagthread", body="hello world body")["data"]["thread_id"]
    ad.rq("admin_rep", nickname="flag13", delta=6)            # PoW-exempt user
    for _ in range(3):
        u.rq("post_comment", thread_id=999999, body="nonexistent")
    for _ in range(4):
        assert u.rq("post_comment", thread_id=tid, body=rand_text(4))["ok"]
    flags = [f for f in ad.rq("admin_list_flags")["data"]["flags"] if f["nickname"] == "flag13"]
    unseen = [f for f in flags if f["kind"] == "unseen_thread_comment"]
    assert len(unseen) == 1 and unseen[0]["count"] == 4, flags


@test
def t13b_metronomic_flag_once_per_session():
    u = user(SRV, "metro13")
    for _ in range(40):
        u.rq("profile")
        time.sleep(0.05)
    ad = admin(SRV)
    flags = [f for f in ad.rq("admin_list_flags", kind="metronomic_timing")["data"]["flags"] if f["nickname"] == "metro13"]
    assert len(flags) <= 1 and (not flags or flags[0]["count"] == 1), flags


# ---------------------------------------------------------------- #14 frozen rating discard
@test
def t14_discarded_frozen_rating_cannot_be_resubmitted():
    ad = admin(SRV)
    target = user(SRV, "tgt14")
    tid = uid(target, "tgt14")
    raters = []
    for i in range(4):
        r = user(SRV, f"r14x{i}")
        ad.rq("admin_rep", nickname=f"r14x{i}", delta=10)
        jid = job_flow(r, target, tid)
        raters.append((r, jid, f"r14x{i}"))
    frozen = None
    for r, jid, nick in raters:
        res = r.rq("rate_user", nickname="tgt14", rating="negative", job_id=jid, **r.pow("rate_user"))
        assert res["ok"], res
        if res["data"].get("frozen"):
            frozen = (r, jid, nick)
    assert frozen is not None
    r, jid, nick = frozen
    assert ad.rq("admin_resolve_rating", rater_id=uid(r, nick), target_id=tid, job_id=jid, apply=False)["ok"]
    res = r.rq("rate_user", nickname="tgt14", rating="negative", job_id=jid, **r.pow("rate_user"))
    assert not res["ok"] and "already rated" in res["message"], res


# ---------------------------------------------------------------- #15 confirmation workflow
@test
def t15_worker_must_confirm_and_can_dispute():
    a, w = user(SRV, "boss15"), user(SRV, "work15")
    ad = admin(SRV)
    ad.rq("admin_rep", nickname="boss15", delta=10)
    wid = uid(w, "work15")
    jid = job_flow(a, w, wid, confirm=False)
    d = w.rq("job_details", job_id=jid)["data"]
    assert d["status"] == "awaiting_confirmation" and d["viewer_is_selected"]
    r = a.rq("rate_user", nickname="work15", rating="negative", job_id=jid, **a.pow("rate_user"))
    assert not r["ok"] and "confirmed" in r["message"], r
    assert w.rq("dispute_job", job_id=jid)["ok"]
    assert any(x["job_id"] == jid for x in ad.rq("admin_list_disputes")["data"]["disputes"])
    assert ad.rq("admin_resolve_dispute", job_id=jid, outcome="cancelled")["ok"]
    assert a.rq("set_status", job_id=jid, status="done")["ok"] is False   # cancelled -> done not allowed
    jid2 = job_flow(a, w, wid, confirm=True)
    assert w.rq("job_details", job_id=jid2)["data"]["status"] == "done"
    assert rep(w) > 0


# ---------------------------------------------------------------- #16 impersonation
@test
def t16_nickname_confusables_and_reserved_names():
    for nick in ("Admin", "adm1n", "a_d_m_i_n", "System", "moderator2", "AfterLife"):
        r = Api(SRV).register(nick)
        assert not r["ok"], (nick, r)
    user(SRV, "alice16")
    for nick in ("ALICE16", "a1ice16", "Alice_16"):
        r = Api(SRV).register(nick)
        assert not r["ok"], (nick, r)


# ---------------------------------------------------------------- #17 pagination
@test
def t17_threads_and_chats_are_paginated():
    ad = admin(SRV)
    tid = ad.rq("create_thread", title="big", body="big thread")["data"]["thread_id"]
    ad.rq("thread_details", thread_id=tid)
    for i in range(45):
        ad.rq("post_comment", thread_id=tid, body=f"comment {i}")
    d = ad.rq("thread_details", thread_id=tid, page=3)["data"]
    assert len(d["posts"]) == 5 and d["pagination"]["total"] == 45, d["pagination"]


# ---------------------------------------------------------------- #18 logs
@test
def t18_log_privacy_permissions_and_flood_suppression():
    log = SRV.dir / "data" / "server.log"
    assert stat.S_IMODE(log.stat().st_mode) == 0o600
    size = log.stat().st_size
    for _ in range(100):
        Api(SRV).rq("no_such_action")
    assert log.stat().st_size - size < 2000, log.stat().st_size - size
    a, b = user(SRV, "priv18a"), user(SRV, "priv18b")
    a.write("open_chat", nickname="priv18b")
    text = log.read_text()
    chat_lines = [l for l in text.splitlines() if "chat_open" in l]
    assert chat_lines and all("priv18" not in l for l in chat_lines), chat_lines


@test
def t18b_log_rotation_bounds_disk():
    srv = ServerProc(AFTERLIFE_LOG_MAX_BYTES="2000", AFTERLIFE_LOG_BACKUPS="2")
    try:
        for i in range(60):
            Api(srv).register(f"rot{i}x")
        files = list((srv.dir / "data").glob("server.log*"))
        assert len(files) <= 3 and all(f.stat().st_size < 4000 for f in files), [(f.name, f.stat().st_size) for f in files]
    finally:
        srv.cleanup()


# ---------------------------------------------------------------- #19 admin bootstrap
@test
def t19_bootstrap_password_file_consumed_and_never_reapplied():
    assert not (SRV.dir / "secrets" / "bootstrap_admin_password").exists()
    srv = ServerProc()
    try:
        a = admin(srv)
        r = a.rq("change_password", old_password=ADMIN_PW, new_password="brandnewpassword1")
        assert r["ok"], r
        srv.stop()
        (srv.dir / "secrets" / "bootstrap_admin_password").write_text(ADMIN_PW)   # stale file on restart
        srv.start()
        assert not Api(srv).login("admin", ADMIN_PW)["ok"]
        assert Api(srv).login("admin", "brandnewpassword1")["ok"]
        assert not (srv.dir / "secrets" / "bootstrap_admin_password").exists()
        assert ADMIN_PW not in json.dumps(dict(srv.env))
    finally:
        srv.cleanup()


@test
def t19b_bootstrap_never_promotes_existing_user():
    srv = ServerProc()
    try:
        user(srv, "mallory")
        srv.stop()
        con = sqlite3.connect(srv.dir / "data" / "db")
        con.execute("UPDATE users SET is_admin = 0")      # simulate: no admin left
        con.commit()
        con.close()
        srv.env["AFTERLIFE_BOOTSTRAP_ADMIN_USERNAME"] = "Mallory"
        (srv.dir / "secrets" / "bootstrap_admin_password").write_text("anotherpassword99")
        srv.start(expect_ok=False)
        srv.proc.wait(10)
        assert srv.proc.returncode == 2 and "collides" in srv.stdout(), srv.stdout()
    finally:
        srv.cleanup()


# ---------------------------------------------------------------- #21 login disclosure
@test
def t21_pending_status_needs_correct_password():
    srv = ServerProc()
    try:
        ad = admin(srv)
        ad.rq("admin_set_approval_lock", enabled=True)
        assert Api(srv).register("pend21")["ok"]
        a = Api(srv)
        r = a.rq("login", nickname="pend21", password="wrongpassword", **a.pow("login", nickname="pend21"))
        assert r["error"] == "login_failed", r
        r = a.rq("login", nickname="pend21", password="password1234", **a.pow("login", nickname="pend21"))
        assert r["error"] == "account_pending", r
    finally:
        srv.cleanup()


# ---------------------------------------------------------------- low-severity items
@test
def tl_strict_json_and_ids():
    a = user(SRV, "low1")
    assert a.raw(b'{"action":"list_jobs","page":Infinity,"session_token":"' + a.token.encode() + b'"}\n')["error"] == "bad_request"
    assert a.rq("list_jobs", page=10**30)["ok"]
    assert a.rq("job_details", job_id=1e308)["error"] == "validation_error"
    assert a.rq("job_details", job_id=True)["error"] == "validation_error"
    deep = b'{"action":"ping","x":' + b"[" * 50 + b"]" * 50 + b"}\n"
    assert a.raw(deep)["error"] == "bad_request"


@test
def tl_ban_then_wipe_penalizes_inviter_once_and_keeps_partner_history():
    ad = admin(SRV)
    inviter = user(SRV, "inv20")
    ad.rq("admin_rep", nickname="inv20", delta=10)
    code = ad.rq("create_invite")["data"]["invite_code"]
    con = sqlite3.connect(SRV.dir / "data" / "db")
    # make the invite look like it came from inv20
    import hashlib  # noqa
    con.execute("UPDATE invites SET issuer_id = ? WHERE id = (SELECT MAX(id) FROM invites)", (uid(inviter, "inv20"),))
    con.commit()
    con.close()
    bad = Api(SRV)
    assert bad.register("bad20", invite_code=code)["ok"]
    bad.login("bad20")
    ad.rq("admin_rep", nickname="bad20", delta=10)
    w = user(SRV, "part20")
    job_flow(bad, w, uid(w, "part20"))
    before = rep(inviter)
    assert ad.rq("ban_user", nickname="bad20")["ok"]
    assert ad.rq("wipe_user", nickname="bad20")["ok"]
    assert round(before - rep(inviter), 3) == 2.0, (before, rep(inviter))
    assert w.rq("profile")["data"]["distinct_job_partners"] == 1


# ---------------------------------------------------------------- E2E chat
@test
def te2e_server_never_sees_plaintext_and_keys_are_enforced():
    import tempfile
    os.environ["AFTERLIFE_HOME"] = tempfile.mkdtemp()
    a, b = Api(SRV), Api(SRV)
    ka, kb = cl.KeyRing(Path("/dev/null"), []), cl.KeyRing(Path("/dev/null"), [])
    ea, eb = ka.add_new_key(), kb.add_new_key()
    assert a.register("e2ea", public_key=ea["pub"])["ok"] and b.register("e2eb", public_key=eb["pub"])["ok"]
    a.login("e2ea")
    b.login("e2eb")
    chat = a.write("open_chat", nickname="e2eb")["data"]
    cid = chat["chat_id"]
    assert chat["other_key_fp"] == eb["fp"]
    secret = "meet at the usual place at 9"
    ct = cl.e2e_encrypt(ka.private_for(ea["fp"]), ea["fp"], base64.b64decode(eb["pub"]), eb["fp"], cid, secret)
    r = a.rq("send_message", chat_id=cid, ciphertext=ct, sender_key_fp=ea["fp"], recipient_key_fp=eb["fp"])
    assert r["ok"], r
    # wrong recipient key -> rejected
    r = a.rq("send_message", chat_id=cid, ciphertext=ct, sender_key_fp=ea["fp"], recipient_key_fp="0" * 32)
    assert not r["ok"] and r["data"]["code"] == "key_changed", r
    # nothing readable on the server side
    raw_db = b"".join(p.read_bytes() for p in (SRV.dir / "data").glob("db*"))
    assert secret.encode() not in raw_db
    # recipient decrypts
    msgs = b.rq("list_messages", chat_id=cid)["data"]["messages"]
    m = [x for x in msgs if x["message_type"] == "e2e"][0]
    pub_a = base64.b64decode(b.rq("get_public_key", fingerprint=m["sender_key_fp"])["data"]["public_key"])
    plain = cl.e2e_decrypt(kb.private_for(eb["fp"]), eb["fp"], pub_a, ea["fp"], cid, m["sender_key_fp"], m["recipient_key_fp"], m["body"])
    assert plain == secret
    # tampering is detected
    bad = base64.b64encode(bytes([base64.b64decode(m["body"])[0] ^ 1]) + base64.b64decode(m["body"])[1:]).decode()
    try:
        cl.e2e_decrypt(kb.private_for(eb["fp"]), eb["fp"], pub_a, ea["fp"], cid, m["sender_key_fp"], m["recipient_key_fp"], bad)
        raise AssertionError("tampered message decrypted")
    except cl.InvalidTag:
        pass
    # key rotation: system notice + old messages still decryptable with retired key
    e2 = ka.add_new_key()
    assert a.rq("set_public_key", public_key=e2["pub"])["ok"]
    notices = [x for x in b.rq("list_messages", chat_id=cid)["data"]["messages"] if x["message_type"] == "system"]
    assert any("changed their encryption key" in n["body"] for n in notices)


@test
def te2e_keyring_encrypted_with_password():
    import tempfile
    os.environ["AFTERLIFE_HOME"] = tempfile.mkdtemp()
    cl.HOME = Path(os.environ["AFTERLIFE_HOME"])
    ring = cl.KeyRing(cl.KeyRing.path_for("x.onion", "bob"), [])
    e = ring.add_new_key()
    ring.save("correct horse battery")
    raw = ring.path.read_text()
    assert e["priv"] not in raw and stat.S_IMODE(ring.path.stat().st_mode) == 0o600
    assert cl.KeyRing.load("x.onion", "bob", "correct horse battery").current["fp"] == e["fp"]
    try:
        cl.KeyRing.load("x.onion", "bob", "wrong")
        raise AssertionError("wrong password unlocked keyring")
    except cl.ClientError:
        pass


# ---------------------------------------------------------------- client transport / hardening
@test
def tc_client_socks5_through_mock_tor_proxy():
    """A minimal SOCKS5 server that, like tor, receives the hostname (no local DNS)."""
    seen = {}
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(5)
    sport = lsock.getsockname()[1]

    def serve():
        conn, _ = lsock.accept()
        conn.recv(3)
        conn.sendall(b"\x05\x02")
        ver, ulen = conn.recv(2)
        user = conn.recv(ulen)
        plen = conn.recv(1)[0]
        conn.recv(plen)
        conn.sendall(b"\x01\x00")
        head = conn.recv(5)
        name = conn.recv(head[4])
        port = int.from_bytes(conn.recv(2), "big")
        seen.update(name=name.decode(), port=port, user=user)
        up = socket.create_connection(("127.0.0.1", SRV.port))
        up.sendall(proxy_line(new_circ()))
        conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        data = conn.recv(65536)
        up.sendall(data)
        resp = b""
        while not resp.endswith(b"\n"):
            resp += up.recv(65536)
        conn.sendall(resp)
        conn.close()
        up.close()

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    onion = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
    t = cl.Transport(onion, 2077, "127.0.0.1", sport)
    r = t.roundtrip({"action": "ping"})
    th.join(5)
    assert r["ok"] and seen["name"] == onion and seen["port"] == 2077 and len(seen["user"]) == 16, (r, seen)


@test
def tc_onion_validation_pow_bounds_and_output_sanitizing():
    assert cl.valid_v3_onion("duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion")
    assert not cl.valid_v3_onion("duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczae.onion")   # checksum
    assert not cl.valid_v3_onion("example.com")
    for bad in ({"n": 1 << 20, "r": 8, "p": 1, "dklen": 32}, {"n": 8192, "r": 64, "p": 1, "dklen": 32}):
        try:
            cl.solve_pow("ab" * 16, 3, bad)
            raise AssertionError("accepted bad params")
        except cl.ClientError:
            pass
    try:
        cl.solve_pow("ab" * 16, 60, {"n": 8192, "r": 8, "p": 1, "dklen": 32})
        raise AssertionError("accepted absurd difficulty")
    except cl.ClientError:
        pass
    assert cl.safe("hi\x1b[2J\x07there‮") == "hi[2Jthere"


@test
def tc_client_survives_network_failure():
    t = cl.Transport("127.0.0.1", 1, direct=True)
    try:
        t.roundtrip({"action": "ping"})
        raise AssertionError("no error")
    except cl.ClientError:
        pass


# ---------------------------------------------------------------- additional coverage
@test
def tx_auto_confirm_after_timeout():
    srv = ServerProc(AFTERLIFE_JOB_CONFIRM_TIMEOUT="1")
    try:
        import harness
        global SRV
        old, SRV = SRV, srv
        try:
            ad = admin(srv)
            w = user(srv, "auto22")
            jid = job_flow(ad, w, uid(w, "auto22"), confirm=False)
            time.sleep(2.5)   # whole-second timestamps
            sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
            os.environ["AFTERLIFE_JOB_CONFIRM_TIMEOUT"] = "1"
            import importlib
            import afterlife_server.config as C
            importlib.reload(C)
            from afterlife_server.crypto import CryptoBox
            from afterlife_server import db as dbmod
            importlib.reload(dbmod)
            d = dbmod.Database(srv.dir / "data" / "db", CryptoBox(srv.dir / "secrets" / "master.key"))
            n = d.auto_confirm_stale()
            st = w.rq("job_details", job_id=jid)["data"]["status"]
            assert st == "done", (n, st, C.JOB_CONFIRM_TIMEOUT_SECONDS)
        finally:
            SRV = old
    finally:
        srv.cleanup()


@test
def tx_invites_capped_per_30_days():
    srv = ServerProc(AFTERLIFE_TRUST_L2_AGE="0")
    try:
        import afterlife_server  # noqa
        ad = admin(srv)
        u = user(srv, "inv23")
        ad.rq("admin_rep", nickname="inv23", delta=20)
        con = sqlite3.connect(srv.dir / "data" / "db")
        # give inv23 three distinct paying partners so it reaches trust level 2
        u23 = con.execute("SELECT id FROM users WHERE nickname='inv23'").fetchone()[0]
        for i in range(3):
            con.execute("INSERT INTO users (nickname, nick_skeleton, password_hash, created_at) VALUES (?, ?, 'x', 0)", (f"p{i}q", f"p{i}q"))
            pid = con.execute("SELECT id FROM users WHERE nickname=?", (f"p{i}q",)).fetchone()[0]
            con.execute("INSERT INTO jobs (author_id, title_enc, description_enc, reward, created_at, updated_at, status) VALUES (?, 'x', 'x', 1, 0, 0, 'done')", (pid,))
            jid = con.execute("SELECT MAX(id) FROM jobs").fetchone()[0]
            con.execute("INSERT INTO job_completions (job_id, author_id, worker_id, rep_gain, created_at) VALUES (?, ?, ?, 1.0, 0)", (jid, pid, u23))
        con.commit()
        con.close()
        made = [u.rq("create_invite")["ok"] for _ in range(5)]
        assert made == [True, True, True, False, False], made
    finally:
        srv.cleanup()


@test
def tx_chat_messages_cursor_pagination():
    a, b = Api(SRV), Api(SRV)
    ka, kb = cl.KeyRing(Path("/dev/null"), []), cl.KeyRing(Path("/dev/null"), [])
    ea, eb = ka.add_new_key(), kb.add_new_key()
    a.register("pag24a", public_key=ea["pub"]); b.register("pag24b", public_key=eb["pub"])
    a.login("pag24a"); b.login("pag24b")
    ad = admin(SRV)
    cid = a.write("open_chat", nickname="pag24b")["data"]["chat_id"]
    for i in range(10):     # 10 messages at the 10/30s burst limit
        ct = cl.e2e_encrypt(ka.private_for(ea["fp"]), ea["fp"], base64.b64decode(eb["pub"]), eb["fp"], cid, f"m{i}")
        assert a.rq("send_message", chat_id=cid, ciphertext=ct, sender_key_fp=ea["fp"], recipient_key_fp=eb["fp"])["ok"]
    con = sqlite3.connect(SRV.dir / "data" / "db")
    con.executemany("INSERT INTO messages (chat_id, sender_id, message_type, body, sender_key_fp, recipient_key_fp, created_at) "
                    "SELECT chat_id, sender_id, message_type, body, sender_key_fp, recipient_key_fp, created_at FROM messages WHERE chat_id = ? AND message_type='e2e' LIMIT 1",
                    [(cid,)] * 100)
    con.commit(); con.close()
    p1 = b.rq("list_messages", chat_id=cid)["data"]
    assert len(p1["messages"]) == 50 and p1["has_more"]
    p2 = b.rq("list_messages", chat_id=cid, before_id=p1["next_before_id"])["data"]
    assert len(p2["messages"]) == 50 and max(m["id"] for m in p2["messages"]) < min(m["id"] for m in p1["messages"])


@test
def tx_proxy_parser_matches_tor_format():
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from afterlife_server.net import ProxyHeaderError, parse_proxy_v1
    # tor: "PROXY TCP6 %s:%x:%x %s %d %d\r\n" with prefix "fc00:dead:beef:4dad:" and dst "::1"
    gid = 0x12345678
    line = f"PROXY TCP6 fc00:dead:beef:4dad::{gid >> 16:x}:{gid & 0xffff:x} ::1 65535 2077\r\n".encode()
    assert parse_proxy_v1(line) == f"circ:{gid}"
    assert parse_proxy_v1(b"PROXY TCP6 fc00:dead:beef:4dad::0:2a ::1 65535 2077\r\n") == "circ:42"
    for bad in (b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n", b"PROXY TCP6 2001:db8::1 ::1 1 2\r\n", b"PROXY TCP6 fc00:dead:beef:4dad::1 ::1 1 2\n"):
        try:
            parse_proxy_v1(bad)
            raise AssertionError(bad)
        except ProxyHeaderError:
            pass


@test
def tk_key_export_import_and_local_peer_keys():
    import tempfile
    home = Path(tempfile.mkdtemp())
    cl.HOME = home
    ring = cl.KeyRing(cl.KeyRing.path_for("x.onion", "amy"), [])
    k1, k2 = ring.add_new_key(), ring.add_new_key()
    ring.save("account password 1")
    exp = home / "export.json"
    ring.export_to(exp, "export passphrase")
    assert k1["priv"] not in exp.read_text() and stat.S_IMODE(exp.stat().st_mode) == 0o600
    # second device: has its own key, imports the old ones; its own key stays current
    other = cl.KeyRing(cl.KeyRing.path_for("x.onion", "amy2"), [])
    own = other.add_new_key()
    assert other.import_from(exp, "export passphrase") == 2
    assert other.current["fp"] == own["fp"] and other.private_for(k1["fp"]) and other.private_for(k2["fp"])
    assert other.import_from(exp, "export passphrase") == 0          # idempotent
    for bad_pw in ("wrong",):
        try:
            other.import_from(exp, bad_pw)
            raise AssertionError("wrong passphrase accepted")
        except cl.ClientError:
            pass
    # a corrupt export (private key not matching its public key) is refused
    import json as _j
    blob = [dict(k1, priv=k2["priv"])]
    bad = home / "bad.json"
    tmp = cl.KeyRing(bad, blob)
    tmp.export_to(bad, "export passphrase")
    try:
        other.import_from(bad, "export passphrase")
        raise AssertionError("corrupt export accepted")
    except cl.ClientError:
        pass
    # contacts' public keys are stored locally after the first verified fetch
    a = Api(SRV)
    kr = cl.KeyRing(Path("/dev/null"), [])
    e = kr.add_new_key()
    assert a.register("peerkey1", public_key=e["pub"])["ok"]
    b = user(SRV, "peerkey2")
    client = cl.RemoteClient(cl.Transport("127.0.0.1", SRV.port, direct=True))
    client.session_token = b.token
    client.pins = cl.PeerPins("x.onion", "peerkey2")
    # route through a PROXY-header shim: server requires it in tests
    client.request = lambda payload: b.rq(payload.pop("action"), **payload)
    assert client.fetch_pubkey(e["fp"]) == base64.b64decode(e["pub"])
    fresh = cl.RemoteClient(cl.Transport("127.0.0.1", 1, direct=True))   # unreachable server
    fresh.pins = cl.PeerPins("x.onion", "peerkey2")
    assert fresh.fetch_pubkey(e["fp"]) == base64.b64decode(e["pub"])      # served from local disk


@test
def tc_client_explains_tor_onion_errors():
    for code, needle in ((4, "date -u"), (0xF0, "descriptor was not found"), (0xF2, "introduction")):
        lsock = socket.socket()
        lsock.bind(("127.0.0.1", 0))
        lsock.listen(1)
        port = lsock.getsockname()[1]

        def serve(code=code):
            conn, _ = lsock.accept()
            conn.recv(3); conn.sendall(b"\x05\x02")
            ver, ulen = conn.recv(2); conn.recv(ulen); plen = conn.recv(1)[0]; conn.recv(plen)
            conn.sendall(b"\x01\x00")
            head = conn.recv(5); conn.recv(head[4] + 2)
            conn.sendall(bytes([5, code, 0, 1]) + b"\x00" * 6)
            conn.close()
        th = threading.Thread(target=serve, daemon=True)
        th.start()
        t = cl.Transport("duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion", 2077, "127.0.0.1", port)
        try:
            t.roundtrip({"action": "ping"})
            raise AssertionError("no error")
        except cl.ClientError as exc:
            assert needle in str(exc), (code, str(exc))
        th.join(5)
        lsock.close()


def main() -> int:
    global SRV
    only = sys.argv[1:]
    SRV = ServerProc()
    import harness
    harness.SRV = SRV
    try:
        for t in TESTS:
            if not only or any(o in t.__name__ for o in only):
                t()
    finally:
        SRV.cleanup()
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} passed")
    for name, _, msg in failed:
        print(f"  FAILED {name}: {msg}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
