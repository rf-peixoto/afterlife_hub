"""Test harness: runs a real server process and talks to it exactly like tor does
(PROXY v1 header carrying a circuit id, then one JSON line)."""
from __future__ import annotations

import json
import os
import random
import shutil
import socket
import string
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import client as cl  # noqa: E402

BASE_ENV = {
    "AFTERLIFE_BOOTSTRAP_ADMIN_USERNAME": "admin",
    "AFTERLIFE_POW_DIFFICULTY": "2",
    "AFTERLIFE_READONLY_WINDOW": "0",
    "AFTERLIFE_TRUST_L1_AGE": "0",
    "AFTERLIFE_JOB_MIN_AGE": "0",
    "AFTERLIFE_REQUIRE_PROXY_HEADER": "1",
    "AFTERLIFE_REQUEST_DEADLINE": "3",
}
ADMIN_PW = "adminpassword123"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class ServerProc:
    def __init__(self, **env: str) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="afterlife-test-"))
        (self.dir / "secrets").mkdir()
        (self.dir / "secrets" / "bootstrap_admin_password").write_text(ADMIN_PW + "\n")
        self.port = free_port()
        self.env = {**os.environ, **BASE_ENV, **env,
                    "AFTERLIFE_PORT": str(self.port), "AFTERLIFE_DB_PATH": str(self.dir / "data" / "db"),
                    "AFTERLIFE_MASTER_KEY_PATH": str(self.dir / "secrets" / "master.key"),
                    "AFTERLIFE_BOOTSTRAP_PASSWORD_FILE": str(self.dir / "secrets" / "bootstrap_admin_password"),
                    "AFTERLIFE_LOG_PATH": str(self.dir / "data" / "server.log")}
        self.proc: Optional[subprocess.Popen] = None
        self.start()

    def start(self, expect_ok: bool = True) -> None:
        self.out = open(self.dir / "stdout.txt", "ab")
        self.proc = subprocess.Popen([sys.executable, str(ROOT / "server.py")], env=self.env, stdout=self.out, stderr=subprocess.STDOUT, cwd=str(ROOT))
        if not expect_ok:
            return
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return
            except OSError:
                if self.proc.poll() is not None:
                    raise RuntimeError("server died: " + self.stdout())
                time.sleep(0.1)
        raise RuntimeError("server did not start: " + self.stdout())

    def stdout(self) -> str:
        return (self.dir / "stdout.txt").read_text(errors="replace")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def cleanup(self) -> None:
        self.stop()
        shutil.rmtree(self.dir, ignore_errors=True)


def proxy_line(circ: int) -> bytes:
    return f"PROXY TCP6 fc00:dead:beef:4dad::{circ >> 16:x}:{circ & 0xffff:x} ::1 65535 2077\r\n".encode()


_circ_counter = [1000]


def new_circ() -> int:
    _circ_counter[0] += 1
    return _circ_counter[0]


class Api:
    def __init__(self, srv: ServerProc, circ: Optional[int] = None) -> None:
        self.srv = srv
        self.circ = circ if circ is not None else new_circ()
        self.token: Optional[str] = None
        self.nick: Optional[str] = None

    def raw(self, payload: Any, circ: Optional[int] = None, header: bool = True) -> dict[str, Any]:
        s = socket.create_connection(("127.0.0.1", self.srv.port), timeout=20)
        data = (proxy_line(circ or self.circ) if header else b"") + (payload if isinstance(payload, bytes) else json.dumps(payload).encode() + b"\n")
        s.sendall(data)
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
        return json.loads(buf) if buf else {}

    def rq(self, action: str, **kw: Any) -> dict[str, Any]:
        p = {"action": action, **kw}
        if self.token and "session_token" not in kw:
            p["session_token"] = self.token
        return self.raw(p)

    def challenge(self, purpose: str, **kw: Any) -> dict[str, Any]:
        return self.rq("get_challenge", purpose=purpose, **kw)

    def pow(self, purpose: str, **kw: Any) -> dict[str, Any]:
        r = self.challenge(purpose, **kw)
        assert r["ok"], r
        d = r["data"]
        if d.get("required") is False:
            return {}
        return {"challenge_id": d["challenge_id"], "nonce": cl.solve_pow(d["prefix"], d["difficulty"], d["scrypt"])}

    def register(self, nick: str, pw: str = "password1234", **kw: Any) -> dict[str, Any]:
        return self.rq("register", nickname=nick, password=pw, **self.pow("register"), **kw)

    def login(self, nick: str, pw: str = "password1234") -> dict[str, Any]:
        r = self.rq("login", nickname=nick, password=pw, **self.pow("login", nickname=nick))
        if r.get("ok"):
            self.token, self.nick = r["data"]["session_token"], nick
        return r

    def write(self, action: str, **kw: Any) -> dict[str, Any]:
        return self.rq(action, **kw, **self.pow(action))


def rand_text(n: int = 12) -> str:
    return " ".join("".join(random.choices(string.ascii_lowercase, k=6)) for _ in range(n))


def user(srv: ServerProc, nick: str, pw: str = "password1234") -> Api:
    a = Api(srv)
    r = a.register(nick, pw)
    assert r.get("ok"), r
    r = a.login(nick, pw)
    assert r.get("ok"), r
    return a


def admin(srv: ServerProc) -> Api:
    a = Api(srv)
    r = a.login("admin", ADMIN_PW)
    assert r.get("ok"), r
    return a
