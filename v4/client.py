#!/usr/bin/env python3
"""AFTERLIFE terminal client.

Connects through Tor's SOCKS port itself (SOCKS5 with remote name resolution),
so no proxychains is needed and the .onion name never touches local DNS.
Chats are end-to-end encrypted: X25519 + HKDF-SHA256 + ChaCha20-Poly1305.
Private keys never leave this machine; they are stored encrypted with your
password under ~/.afterlife/.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import re
import secrets
import socket
import struct
import sys
import textwrap
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:  # pragma: no cover
    sys.exit("The 'cryptography' package is required: pip install cryptography")

PROTOCOL_VERSION = 3
DEFAULT_PORT = 2077
SOCKET_TIMEOUT = 60
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
WRAP_WIDTH = 92
HOME = Path(os.environ.get("AFTERLIFE_HOME", Path.home() / ".afterlife"))
# Operators may hard-pin their address here (or via AFTERLIFE_ONION / --pin).
PINNED_ONION = os.environ.get("AFTERLIFE_ONION", "").strip().lower()

# Bounds for server-supplied proof-of-work parameters: a malicious or fake
# server must not be able to hang or crash the client.
POW_MAX_N = 1 << 15
POW_MAX_R = 16
POW_MAX_P = 4
POW_MAX_DIFFICULTY = 24

MESSAGE_RE = re.compile(r"^[A-Za-z0-9 _.,:;!?()\-\[\]@]{1,128}$")
FP_RE = re.compile(r"^[0-9a-f]{32}$")

RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
GREEN, CYAN, MAGENTA, YELLOW, RED, WHITE = "\033[32m", "\033[36m", "\033[35m", "\033[33m", "\033[31m", "\033[37m"
STATUS_COLORS = {"OPEN": GREEN, "DONE": CYAN, "CANCELLED": RED, "AWAITING_CONFIRMATION": YELLOW, "DISPUTED": MAGENTA}


# ============================================================== output safety
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")


def safe(value: Any) -> str:
    """Strip terminal control/escape and bidi characters from anything that came
    from the network before it is printed."""
    return _CTRL_RE.sub("", str(value))


def c(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"


def hr(char: str = "─") -> str:
    return char * WRAP_WIDTH


def line(char: str = "─", color: str = DIM) -> str:
    return c(hr(char), color)


def clear() -> None:
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


def pause() -> None:
    try:
        input(c("\n[ press enter to continue ] ", DIM))
    except EOFError:
        pass


def wrap(text: str, indent: str = "") -> str:
    width = max(20, WRAP_WIDTH - len(indent))
    return "\n".join(indent + p for p in textwrap.wrap(safe(text), width=width)) if text else ""


def wrap_block(text: str, indent: str = "") -> str:
    out = []
    for raw in safe(text).split("\n"):
        out.append(indent.rstrip() if not raw.strip() else wrap(raw, indent))
    return "\n".join(out)


def fmt_ts(ts: Any) -> str:
    try:
        return datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M") if ts else "-"
    except (TypeError, ValueError, OverflowError, OSError):
        return "-"


def banner() -> str:
    inner = WRAP_WIDTH - 2
    return "\n".join([c("╔" + "═" * inner + "╗", CYAN),
                      c("║", CYAN) + c("A F T E R L I F E".center(inner), MAGENTA + BOLD) + c("║", CYAN),
                      c("║", CYAN) + c("private freelancer terminal".center(inner), DIM) + c("║", CYAN),
                      c("╚" + "═" * inner + "╝", CYAN)])


def section(title: str, subtitle: Optional[str] = None) -> None:
    print(banner())
    print(c(f"[ {title} ]", CYAN + BOLD))
    if subtitle:
        print(c(subtitle, DIM))
    print(line())


def key_value(label: str, value: Any, color: str = WHITE) -> None:
    print(c(f"{label:<16}: ", DIM) + c(safe(value), color))


def status_badge(status: Any) -> str:
    s = safe(status or "unknown").upper()
    return c(f"● {s.replace('_', ' ')}", STATUS_COLORS.get(s, WHITE))


def format_rep(rep: Any) -> str:
    try:
        v = float(rep)
    except (TypeError, ValueError):
        return c(safe(rep), WHITE)
    t = f"{v:.3f}".rstrip("0").rstrip(".")
    return c(t, RED + BOLD) if v < 0 else c(f"+{t}", GREEN) if v > 0 else c("0", WHITE)


# ============================================================== errors
class ClientError(Exception):
    """Network/transport problem; the menu shows it and carries on."""


class SessionExpired(Exception):
    pass


# ============================================================== onion address checks
_B32 = "abcdefghijklmnopqrstuvwxyz234567"


def _b32decode(s: str) -> bytes:
    bits = 0
    nbits = 0
    out = bytearray()
    for ch in s:
        bits = (bits << 5) | _B32.index(ch)
        nbits += 5
        if nbits >= 8:
            nbits -= 8
            out.append((bits >> nbits) & 0xFF)
    return bytes(out)


def valid_v3_onion(host: str) -> bool:
    """56 base32 chars + '.onion', version 3, correct checksum. Catches typos and
    most look-alike addresses copied by hand."""
    host = host.lower()
    if not re.fullmatch(r"[a-z2-7]{56}\.onion", host):
        return False
    raw = _b32decode(host[:56])
    if len(raw) != 35:
        return False
    pubkey, checksum, version = raw[:32], raw[32:34], raw[34:]
    if version != b"\x03":
        return False
    return hashlib.sha3_256(b".onion checksum" + pubkey + version).digest()[:2] == checksum


def _private_write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    tmp = path.with_name(path.name + f".{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(data)
    os.replace(tmp, path)


def _load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def check_known_host(host: str, assume_yes: bool) -> bool:
    """Trust-on-first-use pinning of the server address. Phishing clones of an
    onion service are the most common real-world attack; this makes a changed
    or mistyped address impossible to miss."""
    if PINNED_ONION and host.lower() != PINNED_ONION:
        print(c(f"[ REFUSED ] {host} does not match the pinned address {PINNED_ONION}.", RED + BOLD))
        return False
    path = HOME / "known_hosts.json"
    known = _load_json(path, {})
    if host.lower() in known:
        return True
    print(c("[ NEW ADDRESS ] you have never connected to this onion address before:", YELLOW + BOLD))
    print(c(f"  {host}", WHITE + BOLD))
    print(c("  Verify it character-by-character against a source you trust (signed announcement,", DIM))
    print(c("  the operator in person). Fake look-alike onion services are common.", DIM))
    if not assume_yes and not yes_no("trust and remember this address? [yes/no]> "):
        return False
    known[host.lower()] = {"first_seen": int(time.time())}
    _private_write(path, json.dumps(known, indent=1))
    return True


# ============================================================== transport
@dataclass
class Transport:
    host: str
    port: int
    socks_host: str = "127.0.0.1"
    socks_port: int = 9050
    direct: bool = False
    # A random SOCKS username isolates this client's circuits from other apps
    # using the same Tor (IsolateSOCKSAuth is on by default).
    isolation: str = field(default_factory=lambda: secrets.token_hex(8))

    def _socks_connect(self) -> socket.socket:
        sock = socket.create_connection((self.socks_host, self.socks_port), timeout=SOCKET_TIMEOUT)
        try:
            user = self.isolation.encode()
            sock.sendall(b"\x05\x01\x02")                       # username/password auth (for isolation only)
            if self._recv_exact(sock, 2) != b"\x05\x02":
                raise ClientError("Tor SOCKS port refused authentication method")
            sock.sendall(b"\x01" + bytes([len(user)]) + user + b"\x01x")
            if self._recv_exact(sock, 2)[1] != 0:
                raise ClientError("Tor SOCKS authentication failed")
            name = self.host.encode("ascii")
            sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack(">H", self.port))
            head = self._recv_exact(sock, 4)
            if head[1] != 0:
                reasons = {1: "general failure", 4: "host unreachable (service offline or wrong address)",
                           5: "connection refused", 6: "TTL expired (circuit timeout)"}
                raise ClientError(f"Tor could not reach the service: {reasons.get(head[1], f'error {head[1]}')}")
            atyp = head[3]
            skip = {1: 4, 4: 16}.get(atyp)
            if skip is None:
                skip = self._recv_exact(sock, 1)[0]
            self._recv_exact(sock, skip + 2)
            return sock
        except Exception:
            sock.close()
            raise

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ClientError("connection closed by Tor")
            buf += chunk
        return buf

    def roundtrip(self, payload: dict[str, Any]) -> dict[str, Any]:
        raw = json.dumps(payload).encode("utf-8") + b"\n"
        try:
            if self.direct:
                sock = socket.create_connection((self.host, self.port), timeout=SOCKET_TIMEOUT)
            else:
                sock = self._socks_connect()
            with sock:
                sock.settimeout(SOCKET_TIMEOUT)
                sock.sendall(raw)
                data = b""
                while not data.endswith(b"\n"):
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > MAX_RESPONSE_BYTES:
                        raise ClientError("server response too large; ignoring it")
        except ConnectionRefusedError:
            raise ClientError("connection refused — is Tor running? (default SOCKS port 9050)" if not self.direct else "connection refused")
        except socket.timeout:
            raise ClientError("timed out — Tor circuits can be slow; try again")
        except OSError as exc:
            raise ClientError(f"network error: {exc}")
        if not data:
            raise ClientError("no response from server")
        try:
            resp = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ClientError("malformed response from server")
        if not isinstance(resp, dict):
            raise ClientError("malformed response from server")
        return resp


# ============================================================== end-to-end crypto
def key_fingerprint(pub: bytes) -> str:
    return hashlib.sha256(b"afterlife-x25519-v1" + pub).hexdigest()[:32]


def fmt_fp(fp: str) -> str:
    return " ".join(fp[i:i + 4] for i in range(0, len(fp), 4))


def _kdf_password(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=1 << 15, r=8, p=1, maxmem=128 * 1024 * 1024, dklen=32)


class KeyRing:
    """All of this account's X25519 private keys (current + retired, so old
    messages stay readable after a rotation), encrypted at rest with a key
    derived from the account password."""

    def __init__(self, path: Path, keys: list[dict[str, str]]) -> None:
        self.path = path
        self.keys = keys      # [{"fp","pub","priv"}] base64 raw keys, newest last

    @staticmethod
    def path_for(host: str, nickname: str) -> Path:
        return HOME / "keys" / host.lower() / f"{nickname.lower()}.json"

    @classmethod
    def load(cls, host: str, nickname: str, password: str) -> Optional["KeyRing"]:
        path = cls.path_for(host, nickname)
        blob = _load_json(path, None)
        if blob is None:
            return None
        try:
            salt, nonce, ct = (base64.b64decode(blob[k]) for k in ("salt", "nonce", "ct"))
            plain = ChaCha20Poly1305(_kdf_password(password, salt)).decrypt(nonce, ct, b"afterlife-keyring-v1")
            return cls(path, json.loads(plain))
        except (InvalidTag, KeyError, ValueError, TypeError):
            raise ClientError(f"could not unlock your key file {path} with this password")

    def save(self, password: str) -> None:
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        ct = ChaCha20Poly1305(_kdf_password(password, salt)).encrypt(nonce, json.dumps(self.keys).encode(), b"afterlife-keyring-v1")
        _private_write(self.path, json.dumps({"version": 1, "salt": base64.b64encode(salt).decode(),
                                              "nonce": base64.b64encode(nonce).decode(), "ct": base64.b64encode(ct).decode()}))

    def export_to(self, dest: Path, passphrase: str) -> None:
        """A portable copy of all your private keys, encrypted with a passphrase."""
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        ct = ChaCha20Poly1305(_kdf_password(passphrase, salt)).encrypt(nonce, json.dumps(self.keys).encode(), b"afterlife-keyring-v1")
        _private_write(dest, json.dumps({"version": 1, "salt": base64.b64encode(salt).decode(),
                                         "nonce": base64.b64encode(nonce).decode(), "ct": base64.b64encode(ct).decode()}))

    def import_from(self, src: Path, passphrase: str) -> int:
        """Merge keys from an exported file. Returns how many keys were new.
        Imported keys are placed before this device's own keys, so the key
        this device already publishes stays current."""
        blob = _load_json(src, None)
        if blob is None:
            raise ClientError(f"cannot read {src}")
        try:
            salt, nonce, ct = (base64.b64decode(blob[k]) for k in ("salt", "nonce", "ct"))
            incoming = json.loads(ChaCha20Poly1305(_kdf_password(passphrase, salt)).decrypt(nonce, ct, b"afterlife-keyring-v1"))
        except (InvalidTag, KeyError, ValueError, TypeError):
            raise ClientError("wrong passphrase or not an AFTERLIFE key export")
        known = {k["fp"] for k in self.keys}
        new = []
        for k in incoming:
            pub = base64.b64decode(k["pub"])
            priv = X25519PrivateKey.from_private_bytes(base64.b64decode(k["priv"]))
            derived = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            if derived != pub or key_fingerprint(pub) != k["fp"]:
                raise ClientError("export file is corrupt (key mismatch)")
            if k["fp"] not in known:
                new.append(k)
        self.keys = new + self.keys
        return len(new)

    def add_new_key(self) -> dict[str, str]:
        priv = X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        raw_priv = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        entry = {"fp": key_fingerprint(pub), "pub": base64.b64encode(pub).decode(), "priv": base64.b64encode(raw_priv).decode()}
        self.keys.append(entry)
        return entry

    @property
    def current(self) -> Optional[dict[str, str]]:
        return self.keys[-1] if self.keys else None

    def private_for(self, fp: str) -> Optional[X25519PrivateKey]:
        for k in self.keys:
            if k["fp"] == fp:
                return X25519PrivateKey.from_private_bytes(base64.b64decode(k["priv"]))
        return None


def _session_key(my_priv: X25519PrivateKey, peer_pub: bytes, fp_a: str, fp_b: str) -> ChaCha20Poly1305:
    shared = my_priv.exchange(X25519PublicKey.from_public_bytes(peer_pub))
    info = ("afterlife-e2e-v1|" + "|".join(sorted([fp_a, fp_b]))).encode()
    return ChaCha20Poly1305(HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared))


def _aad(chat_id: int, sender_fp: str, recipient_fp: str) -> bytes:
    return f"afterlife-e2e-v1|{chat_id}|{sender_fp}|{recipient_fp}".encode()


def e2e_encrypt(my_priv: X25519PrivateKey, my_fp: str, peer_pub: bytes, peer_fp: str, chat_id: int, text: str) -> str:
    nonce = secrets.token_bytes(12)
    ct = _session_key(my_priv, peer_pub, my_fp, peer_fp).encrypt(nonce, text.encode("utf-8"), _aad(chat_id, my_fp, peer_fp))
    return base64.b64encode(nonce + ct).decode()


def e2e_decrypt(my_priv: X25519PrivateKey, my_fp: str, peer_pub: bytes, peer_fp: str, chat_id: int,
                sender_fp: str, recipient_fp: str, body: str) -> str:
    raw = base64.b64decode(body, validate=True)
    plain = _session_key(my_priv, peer_pub, my_fp, peer_fp).decrypt(raw[:12], raw[12:], _aad(chat_id, sender_fp, recipient_fp))
    return plain.decode("utf-8")


class PeerPins:
    """Stored ON THIS COMPUTER: trust-on-first-use pins of other users' key
    fingerprints, plus every verified public key seen, so after the first
    contact encryption needs nothing from the server."""

    def __init__(self, host: str, me: str) -> None:
        self.path = HOME / "peers" / host.lower() / f"{me.lower()}.json"
        self.data: dict[str, list[str]] = _load_json(self.path, {})
        self.keys_path = HOME / "peers" / host.lower() / f"{me.lower()}.pubkeys.json"
        self.pubkeys: dict[str, str] = _load_json(self.keys_path, {})

    def get_pubkey(self, fp: str) -> Optional[bytes]:
        raw = self.pubkeys.get(fp)
        if not raw:
            return None
        try:
            pub = base64.b64decode(raw, validate=True)
        except ValueError:
            return None
        return pub if len(pub) == 32 and key_fingerprint(pub) == fp else None

    def store_pubkey(self, fp: str, pub: bytes) -> None:
        if self.pubkeys.get(fp) == base64.b64encode(pub).decode():
            return
        self.pubkeys[fp] = base64.b64encode(pub).decode()
        _private_write(self.keys_path, json.dumps(self.pubkeys, indent=1))

    def status(self, nickname: str, fp: str) -> str:
        pins = self.data.get(nickname.lower())
        if not pins:
            return "new"
        return "pinned" if fp in pins else "changed"

    def pin(self, nickname: str, fp: str) -> None:
        self.data.setdefault(nickname.lower(), [])
        if fp not in self.data[nickname.lower()]:
            self.data[nickname.lower()].append(fp)
        _private_write(self.path, json.dumps(self.data, indent=1))


# ============================================================== client
@dataclass
class RemoteClient:
    transport: Transport
    session_token: Optional[str] = None
    nickname: Optional[str] = None
    is_admin: bool = False
    keyring: Optional[KeyRing] = None
    password: Optional[str] = None        # kept in memory only to re-save the keyring
    pins: Optional[PeerPins] = None
    pubkey_cache: dict[str, bytes] = field(default_factory=dict)

    @property
    def host(self) -> str:
        return self.transport.host

    def request(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.session_token:
            payload.setdefault("session_token", self.session_token)
        resp = self.transport.roundtrip(payload)
        if resp.get("error") == "auth_required" and payload.get("action") not in {"login", "register", "get_challenge"}:
            self.session_token = None
            raise SessionExpired(safe(resp.get("message", "session expired")))
        return resp

    # ---- E2E helpers
    def fetch_pubkey(self, fingerprint: str) -> Optional[bytes]:
        if fingerprint in self.pubkey_cache:
            return self.pubkey_cache[fingerprint]
        if self.pins is not None:
            local = self.pins.get_pubkey(fingerprint)
            if local is not None:
                self.pubkey_cache[fingerprint] = local
                return local
        resp = self.request({"action": "get_public_key", "fingerprint": fingerprint})
        if not resp.get("ok"):
            return None
        try:
            pub = base64.b64decode(resp["data"]["public_key"], validate=True)
        except (KeyError, ValueError, TypeError):
            return None
        if len(pub) != 32 or key_fingerprint(pub) != fingerprint:   # the server cannot substitute a key for a fingerprint
            return None
        self.pubkey_cache[fingerprint] = pub
        if self.pins is not None:
            self.pins.store_pubkey(fingerprint, pub)
        return pub


def _leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        bits += 8 - byte.bit_length()
        break
    return bits


def solve_pow(prefix: str, difficulty: int, params: dict[str, Any]) -> str:
    n, r, p, dklen = int(params.get("n", 0)), int(params.get("r", 0)), int(params.get("p", 0)), int(params.get("dklen", 32))
    if not (2 <= n <= POW_MAX_N and n & (n - 1) == 0 and 1 <= r <= POW_MAX_R and 1 <= p <= POW_MAX_P and dklen == 32
            and 1 <= difficulty <= POW_MAX_DIFFICULTY and re.fullmatch(r"[0-9a-f]{16,64}", prefix)):
        raise ClientError("server sent unreasonable proof-of-work parameters; refusing to solve")
    salt = prefix.encode()
    nonce = 0
    while True:
        digest = hashlib.scrypt(f"{prefix}:{nonce}".encode(), salt=salt, n=n, r=r, p=p, maxmem=128 * 1024 * 1024, dklen=32)
        if _leading_zero_bits(digest) >= difficulty:
            return str(nonce)
        nonce += 1


def obtain_pow(client: RemoteClient, purpose: str, extra: Optional[dict[str, Any]] = None) -> Optional[dict[str, Any]]:
    """Returns {} when the server says no PoW is needed, the solved fields, or
    None on failure."""
    resp = client.request({"action": "get_challenge", "purpose": purpose, **(extra or {})})
    if not resp.get("ok"):
        show_result(resp)
        return None
    data = resp.get("data", {})
    if data.get("required") is False:
        return {}
    difficulty = int(data.get("difficulty", 0))
    if difficulty > 6:
        print(c(f"solving anti-bot challenge ({difficulty} bits)... press Ctrl-C to cancel", DIM))
    start = time.time()
    try:
        nonce = solve_pow(str(data.get("prefix", "")), difficulty, data.get("scrypt") or {})
    except KeyboardInterrupt:
        print(c("cancelled.", YELLOW))
        return None
    if difficulty > 6:
        print(c(f"solved in {time.time() - start:.1f}s", GREEN))
    return {"challenge_id": data.get("challenge_id"), "nonce": nonce}


# ============================================================== input helpers
def _input(text: str) -> str:
    try:
        return input(c(text, MAGENTA))
    except EOFError:
        raise SystemExit(0)


def ask(text: str, allow_blank: bool = False) -> str:
    while True:
        v = _input(text).strip()
        if v or allow_blank:
            return v
        print(c("input required.", RED))


def ask_hidden(text: str) -> str:
    while True:
        try:
            v = getpass.getpass(c(text, MAGENTA))
        except EOFError:
            raise SystemExit(0)
        if v:
            return v
        print(c("input required.", RED))


def ask_int(text: str) -> int:
    while True:
        raw = _input(text).strip()
        if re.fullmatch(r"\d{1,18}", raw) and int(raw) > 0:
            return int(raw)
        print(c("enter a valid positive number.", RED))


def yes_no(text: str) -> bool:
    while True:
        v = _input(text).strip().lower()
        if v in {"y", "yes"}:
            return True
        if v in {"n", "no"}:
            return False
        print(c("answer with yes or no.", RED))


def ask_multiline(text: str) -> Optional[str]:
    print(c(text, MAGENTA))
    print(c("  (finish with a single '.' on a line, or '/cancel' to abort)", DIM))
    lines: list[str] = []
    while True:
        try:
            raw = input()
        except EOFError:
            break
        if raw.strip() == "/cancel":
            return None
        if raw.strip() == ".":
            break
        lines.append(raw)
    out = "\n".join(lines).strip()
    if not out:
        print(c("input required.", RED))
    return out


def normalize_choice(v: str) -> str:
    return v.strip().lower().replace("_", " ").replace("-", " ")


def choose(text: str, mapping: dict[str, str]) -> str:
    norm = {normalize_choice(k): v for k, v in mapping.items()}
    while True:
        v = normalize_choice(_input(text))
        if v in norm:
            return norm[v]
        print(c("unknown option.", RED))


def show_result(resp: dict[str, Any]) -> None:
    print(line("·"))
    if resp.get("ok"):
        print(c(f"[ OK ] {safe(resp.get('message', 'done.'))}", GREEN))
    else:
        msg = safe(resp.get("message", "request failed."))
        if resp.get("retry_after"):
            msg += f" retry after {safe(resp['retry_after'])}s."
        print(c(f"[ FAIL ] {msg}", RED))


# ============================================================== rendering
def print_jobs(jobs: list[dict[str, Any]], include_author: bool = True) -> None:
    if not jobs:
        print(c("no contracts found.", YELLOW))
        return
    for job in jobs:
        print(c(f"[ CONTRACT #{int(job['id']):04d} ]", CYAN + BOLD) + "  " + c(safe(job["title"]), WHITE + BOLD))
        key_value("Reward", job["reward"])
        key_value("Min rep", job.get("min_reputation", 0), CYAN)
        print(c(f"{'Status':<16}: ", DIM) + status_badge(job.get("status")))
        key_value("Accepts", job.get("accept_count", 0))
        if include_author:
            key_value("Author", job.get("author_display", ""))
        if job.get("you_are_selected") and job.get("status") == "awaiting_confirmation":
            print(c("[ ACTION NEEDED ] confirm or dispute completion in job details", YELLOW + BOLD))
        if job.get("not_enough_reputation"):
            print(c("[NOT ENOUGH REPUTATION]", RED + BOLD))
        print(line())


def page_status(pg: Optional[dict[str, Any]]) -> None:
    if pg:
        print(line("·"))
        print(c(f"page {safe(pg.get('page', 1))}/{safe(pg.get('total_pages', 1))}  ({safe(pg.get('total', 0))} total)", DIM))


def nav_choices(pg: Optional[dict[str, Any]], extra: Optional[list[str]] = None) -> dict[str, str]:
    opts: dict[str, str] = {}
    if pg and pg.get("has_prev"):
        opts["prev"] = "prev"
    if pg and pg.get("has_next"):
        opts["next"] = "next"
    for e in extra or []:
        opts[e] = e
    opts["back"] = "back"
    return opts


def apply_nav(choice: str, page: int, pg: Optional[dict[str, Any]]) -> Optional[int]:
    if choice == "next" and pg and pg.get("has_next"):
        return page + 1
    if choice == "prev" and pg and pg.get("has_prev"):
        return max(1, page - 1)
    return None


# ============================================================== auth + keys
def ensure_keyring(client: RemoteClient, server_fp: Optional[str]) -> None:
    """Unlock (or create) this account's key file and reconcile it with the key
    the server advertises for us."""
    assert client.nickname and client.password
    try:
        ring = KeyRing.load(client.host, client.nickname, client.password)
    except ClientError as exc:
        print(c(f"[ KEYS ] {exc}. Encrypted chat is unavailable this session.", RED))
        return
    if ring is None:
        ring = KeyRing(KeyRing.path_for(client.host, client.nickname), [])
        if server_fp:
            print(c("[ KEYS ] this device has no private key for your account.", YELLOW + BOLD))
            print(c("  Messages encrypted to your old key cannot be read here. Copy your key file", DIM))
            print(c("  Use 'keys -> export' on your other device and 'keys -> import' here, or create a new key now.", DIM))
            if not yes_no("create a new key and publish it (rotates your key)? [yes/no]> "):
                return
        ring.add_new_key()
        ring.save(client.password)
    client.keyring = ring
    cur = ring.current
    if cur and server_fp != cur["fp"]:
        if server_fp and ring.private_for(server_fp) is None:
            print(c("[ KEYS ] the server lists a key for you that this device does not hold.", YELLOW + BOLD))
            print(c(f"  server: {fmt_fp(server_fp)}\n  local : {fmt_fp(cur['fp'])}", DIM))
            if not yes_no("publish your local key as current? [yes/no]> "):
                return
        resp = client.request({"action": "set_public_key", "public_key": cur["pub"]})
        if not resp.get("ok"):
            show_result(resp)


def auth_menu(client: RemoteClient) -> None:
    while not client.session_token:
        clear()
        section("AUTH // SESSION GATE", "available actions: login, register, quit")
        choice = choose("auth@gateway> ", {"login": "login", "register": "register", "quit": "quit", "exit": "quit"})
        try:
            if choice == "login":
                nickname = ask("nickname> ")
                password = ask_hidden("password> ")
                pow_fields = obtain_pow(client, "login", {"nickname": nickname})
                if pow_fields is None:
                    pause()
                    continue
                resp = client.request({"action": "login", "nickname": nickname, "password": password, **pow_fields})
                show_result(resp)
                if not resp.get("ok"):
                    pause()
                    continue
                data = resp.get("data", {})
                client.session_token = data.get("session_token")
                client.nickname = safe(data.get("nickname", nickname))
                client.is_admin = bool(data.get("is_admin"))
                client.password = password
                client.pins = PeerPins(client.host, client.nickname)
                ensure_keyring(client, data.get("key_fp"))
                time.sleep(0.4)
            elif choice == "register":
                nickname = ask("new nickname> ")
                password = ask_hidden("new password (10+ chars)> ")
                if ask_hidden("repeat password> ") != password:
                    print(c("passwords do not match.", RED))
                    pause()
                    continue
                print(c("an invite code may be required depending on the server's registration mode.", DIM))
                invite = ask("invite code [blank if none]> ", allow_blank=True)
                ring = KeyRing(KeyRing.path_for(client.host, nickname), [])
                entry = ring.add_new_key()
                pow_fields = obtain_pow(client, "register")
                if pow_fields is None:
                    pause()
                    continue
                req = {"action": "register", "nickname": nickname, "password": password, "public_key": entry["pub"], **pow_fields}
                if invite:
                    req["invite_code"] = invite
                resp = client.request(req)
                show_result(resp)
                if resp.get("ok"):
                    ring.save(password)
                    print(c(f"your encryption key fingerprint: {fmt_fp(entry['fp'])}", CYAN))
                    print(c(f"key file (back it up!): {ring.path}", DIM))
                    if resp.get("data", {}).get("pending"):
                        print(c("[ PENDING ] an administrator must approve your account before you can log in.", YELLOW + BOLD))
                pause()
            else:
                raise SystemExit(0)
        except ClientError as exc:
            print(c(f"[ CONNECTION ] {exc}", RED))
            pause()


# ============================================================== menus
def view_profile(client: RemoteClient) -> None:
    clear()
    section("PROFILE // IDENTITY NODE")
    resp = client.request({"action": "profile"})
    if not resp.get("ok"):
        show_result(resp)
        pause()
        return
    d = resp["data"]
    key_value("Nickname", d.get("nickname"), WHITE + BOLD)
    print(c(f"{'Reputation':<16}: ", DIM) + format_rep(d.get("reputation", 0)))
    key_value("Role", "admin" if d.get("is_admin") else "member", CYAN)
    key_value("Trust level", d.get("trust_level"), CYAN)
    key_value("Job partners", d.get("distinct_job_partners"))
    key_value("PoW", "exempt" if d.get("pow_exempt") else f"{safe(d.get('pow_difficulty'))} bits", DIM)
    key_value("Key fingerprint", fmt_fp(d["key_fp"]) if d.get("key_fp") else "none published", CYAN)
    key_value("Created", fmt_ts(d.get("created_at")))
    print(line())
    print(c("commands: password, back", CYAN))
    if choose("profile@node> ", {"password": "password", "back": "back"}) == "password":
        old = ask_hidden("current password> ")
        new = ask_hidden("new password (10+ chars)> ")
        if ask_hidden("repeat new password> ") != new:
            print(c("passwords do not match.", RED))
            pause()
            return
        resp = client.request({"action": "change_password", "old_password": old, "new_password": new})
        show_result(resp)
        if resp.get("ok"):
            client.session_token = resp["data"].get("session_token")
            client.password = new
            if client.keyring:
                client.keyring.save(new)
                print(c("your local key file was re-encrypted with the new password.", DIM))
        pause()


def list_jobs_menu(client: RemoteClient, status: Optional[str], action: str = "list_jobs", title: str = "JOB BOARD") -> None:
    page = 1
    while True:
        clear()
        section(f"{title} // {(status or 'all').upper().replace('_', ' ')}")
        resp = client.request({"action": action, "status": status, "page": page} if action == "list_jobs" else {"action": action, "page": page})
        if not resp.get("ok"):
            show_result(resp)
            pause()
            return
        data = resp["data"]
        print_jobs(data.get("jobs", []), include_author=action != "my_jobs")
        pg = data.get("pagination")
        page = int(pg.get("page", page)) if pg else page
        page_status(pg)
        cmds = nav_choices(pg, ["view"])
        print(c("commands: " + ", ".join(cmds), CYAN))
        ch = choose("jobs@node> ", cmds)
        new_page = apply_nav(ch, page, pg)
        if new_page is not None:
            page = new_page
        elif ch == "view":
            job_details_menu(client, ask_int("contract id> "))
        else:
            return


def create_job_menu(client: RemoteClient) -> None:
    clear()
    section("CREATE CONTRACT // BROADCAST")
    print(c("plain text only; forbidden characters: ' \" \\ / % +", DIM))
    print(line("·"))
    req = {"action": "create_job", "title": ask("title> "), "description": ask("description> "), "reward": ask("reward> "),
           "min_reputation": ask("minimum reputation [0]> ", allow_blank=True) or "0",
           "is_private": yes_no("private contract? [yes/no]> ")}
    pow_fields = obtain_pow(client, "create_job")
    if pow_fields is None:
        pause()
        return
    resp = client.request({**req, **pow_fields})
    show_result(resp)
    if resp.get("ok"):
        d = resp.get("data", {})
        key_value("Contract", d.get("job_id"), GREEN)
        if d.get("private_token"):
            print(c("[ PRIVATE TOKEN // SHOWN ONCE — STORE SECURELY ]", YELLOW + BOLD))
            print(c(safe(d["private_token"]), MAGENTA))
    pause()


def print_job_details(d: dict[str, Any]) -> None:
    print(c(f"[ CONTRACT #{int(d['id']):04d} ]", MAGENTA + BOLD))
    print(line("═", CYAN))
    print(c(safe(d["title"]), WHITE + BOLD))
    print(line("·"))
    key_value("Reward", d["reward"])
    key_value("Min rep", d.get("min_reputation", 0), CYAN)
    print(c(f"{'Status':<16}: ", DIM) + status_badge(d.get("status")))
    key_value("Author", d.get("author_display"))
    key_value("Private", "yes" if d.get("is_private") else "no", YELLOW if d.get("is_private") else WHITE)
    key_value("Accepts", d.get("accept_count", 0))
    if d.get("viewer_reputation") is not None:
        print(c(f"{'Your reputation':<16}: ", DIM) + format_rep(d["viewer_reputation"]))
    if d.get("not_enough_reputation"):
        print(c("[NOT ENOUGH REPUTATION]", RED + BOLD))
    print()
    if d.get("description_visible"):
        print(c("[ DESCRIPTION ]", CYAN))
        print(wrap(d.get("description") or "", "  "))
    else:
        print(c("[ DESCRIPTION LOCKED ] provide the unlock token, or be the author/admin.", YELLOW))
    if d.get("viewer_is_selected") and d.get("status") == "awaiting_confirmation":
        print(c("\n[ ACTION NEEDED ] the author marked this job done. 'confirm' if the work was completed, otherwise 'dispute'.", YELLOW + BOLD))
    if d.get("worker_pool") is not None:
        print(c("\n[ ACCEPTED WORKERS ]", CYAN))
        for w in d["worker_pool"] or []:
            mark = c("  <selected>", GREEN + BOLD) if d.get("selected_worker_id") == w["id"] else ""
            print(c(f"  [{int(w['id'])}] ", MAGENTA) + c(safe(w["nickname"]), WHITE) + c(f"  rep={safe(w['reputation'])}", DIM) + mark)
        if not d["worker_pool"]:
            print(c("  no workers yet.", DIM))


def job_details_menu(client: RemoteClient, job_id: Optional[int] = None) -> None:
    if job_id is None:
        clear()
        section("CONTRACT DETAILS")
        job_id = ask_int("contract id> ")
    token = None
    while True:
        req: dict[str, Any] = {"action": "job_details", "job_id": job_id}
        if token:
            req["unlock_token"] = token
        resp = client.request(req)
        if not resp.get("ok"):
            show_result(resp)
            pause()
            return
        d = resp["data"]
        clear()
        section("CONTRACT DETAILS // LIVE VIEW")
        print_job_details(d)
        print(line("═", CYAN))
        st = d.get("status")
        cmds = ["back"]
        if d.get("is_private") and not d.get("description_visible"):
            cmds.append("unlock")
        if st == "open" and not d.get("is_author") and not d.get("viewer_has_accepted") and not d.get("viewer_has_withdrawn") and not d.get("not_enough_reputation"):
            cmds.append("accept")
        if st == "open" and d.get("viewer_has_accepted") and not d.get("viewer_is_selected"):
            cmds.append("withdraw")
        if d.get("viewer_is_selected") and st == "awaiting_confirmation":
            cmds += ["confirm", "dispute"]
        if d.get("is_author") or d.get("is_admin"):
            if st == "open":
                cmds += ["select worker", "done", "cancel"]
            if st == "awaiting_confirmation":
                cmds += ["reopen", "cancel"]
            if st == "cancelled":
                cmds.append("reopen")
        if d.get("is_admin"):
            cmds.append("delete")
        print(c("commands: " + ", ".join(cmds), CYAN))
        ch = choose("contract@view> ", {k: k for k in cmds})
        if ch == "back":
            return
        if ch == "unlock":
            token = ask("unlock token> ")
            continue
        if ch == "accept":
            areq: dict[str, Any] = {"action": "accept_job", "job_id": job_id}
            if d.get("is_private"):
                areq["private_token"] = token or ask("private token> ")
            pf = obtain_pow(client, "accept_job")
            if pf is None:
                pause()
                continue
            show_result(client.request({**areq, **pf}))
        elif ch == "withdraw":
            if yes_no("withdraw? you will NOT be able to accept this job again. [yes/no]> "):
                show_result(client.request({"action": "withdraw_job", "job_id": job_id}))
        elif ch == "confirm":
            show_result(client.request({"action": "confirm_job", "job_id": job_id}))
        elif ch == "dispute":
            if yes_no("dispute this completion? an administrator will review it. [yes/no]> "):
                show_result(client.request({"action": "dispute_job", "job_id": job_id}))
        elif ch == "select worker":
            show_result(client.request({"action": "select_worker", "job_id": job_id, "worker_id": ask_int("worker id> ")}))
        elif ch == "done":
            show_result(client.request({"action": "set_status", "job_id": job_id, "status": "done"}))
        elif ch == "cancel":
            show_result(client.request({"action": "set_status", "job_id": job_id, "status": "cancelled"}))
        elif ch == "reopen":
            show_result(client.request({"action": "set_status", "job_id": job_id, "status": "open"}))
        elif ch == "delete":
            if yes_no(f"remove contract #{job_id}? [yes/no]> "):
                r = client.request({"action": "delete_job", "job_id": job_id})
                show_result(r)
                if r.get("ok"):
                    pause()
                    return
        pause()


def rate_user_menu(client: RemoteClient) -> None:
    clear()
    section("REPUTATION // RATE USER")
    print(c("you may only rate the other party of a job whose completion was confirmed.", DIM))
    print(line("·"))
    nickname = ask("counterparty nickname> ")
    job_id = ask_int("completed contract id> ")
    rating = choose("rating [positive/negative]> ", {"positive": "positive", "negative": "negative"})
    pf = obtain_pow(client, "rate_user")
    if pf is None:
        pause()
        return
    resp = client.request({"action": "rate_user", "nickname": nickname, "rating": rating, "job_id": job_id, **pf})
    show_result(resp)
    pause()


def blocks_menu(client: RemoteClient) -> None:
    while True:
        clear()
        section("BLOCK LIST // RELATION FILTER")
        resp = client.request({"action": "list_blocks"})
        if not resp.get("ok"):
            show_result(resp)
            pause()
            return
        blocks = resp["data"].get("blocks", [])
        if not blocks:
            print(c("you have not blocked anyone.", YELLOW))
        for b in blocks:
            print(c(safe(b["nickname"]), WHITE + BOLD) + c(f"  rep={safe(b['reputation'])}", DIM))
        print(line())
        ch = choose("blocks@node> ", {"block": "block", "unblock": "unblock", "back": "back"})
        if ch == "back":
            return
        show_result(client.request({"action": f"{ch}_user", "nickname": ask("nickname> ")}))
        pause()


# ---------------------------------------------------------------- chat
def verify_peer_key(client: RemoteClient, nickname: str, fp: str, interactive: bool = True) -> bool:
    status = client.pins.status(nickname, fp) if client.pins else "new"
    if status == "pinned":
        return True
    if status == "new":
        if client.pins:
            client.pins.pin(nickname, fp)
        print(c(f"[ KEY ] first key seen for {safe(nickname)}: {fmt_fp(fp)} (pinned). Compare it with them out of band.", CYAN))
        return True
    print(c(f"[ WARNING ] {safe(nickname)}'s encryption key CHANGED to {fmt_fp(fp)}.", RED + BOLD))
    print(c("  This happens when they reinstall or rotate keys — or if someone (including the server)", DIM))
    print(c("  is trying to intercept your messages. Verify the new fingerprint with them out of band.", DIM))
    if interactive and yes_no("trust the new key? [yes/no]> "):
        client.pins.pin(nickname, fp)
        return True
    return False


def decrypt_message(client: RemoteClient, chat_id: int, other_nick: str, msg: dict[str, Any]) -> tuple[str, str]:
    """Returns (text, marker)."""
    if msg.get("message_type") == "system":
        return safe(msg.get("body", "")), "system"
    ring = client.keyring
    sfp, rfp = str(msg.get("sender_key_fp") or ""), str(msg.get("recipient_key_fp") or "")
    if ring is None or not FP_RE.fullmatch(sfp) or not FP_RE.fullmatch(rfp):
        return "[encrypted message — no key on this device]", "warn"
    mine_sent = ring.private_for(sfp) is not None and msg.get("sender_nickname") == client.nickname
    my_fp, peer_fp = (sfp, rfp) if mine_sent else (rfp, sfp)
    priv = ring.private_for(my_fp)
    peer_pub = client.fetch_pubkey(peer_fp)
    if priv is None or peer_pub is None:
        return "[encrypted message — key not available on this device]", "warn"
    try:
        text = e2e_decrypt(priv, my_fp, peer_pub, peer_fp, chat_id, sfp, rfp, str(msg.get("body", "")))
    except (InvalidTag, ValueError):
        return "[message failed authentication — tampered or corrupt]", "warn"
    marker = "ok"
    if not mine_sent and client.pins and client.pins.status(other_nick, sfp) == "changed":
        marker = "unverified"
    return safe(text), marker


def view_chat(client: RemoteClient, chat_id: int) -> None:
    before: Optional[int] = None
    while True:
        req: dict[str, Any] = {"action": "list_messages", "chat_id": chat_id}
        if before:
            req["before_id"] = before
        resp = client.request(req)
        if not resp.get("ok"):
            show_result(resp)
            pause()
            return
        d = resp["data"]
        other = safe(d.get("other_nickname", "?"))
        clear()
        section(f"CHAT #{chat_id:04d} WITH {other}", "end-to-end encrypted — the server cannot read these messages")
        if d.get("other_key_fp"):
            verify_peer_key(client, other, d["other_key_fp"])
            print(c(f"their key: {fmt_fp(d['other_key_fp'])}", DIM))
        msgs = d.get("messages", [])
        if not msgs:
            print(c("no messages.", YELLOW))
        for m in msgs:
            text, marker = decrypt_message(client, chat_id, other, m)
            if marker == "system":
                print(c(f"#{int(m['id']):04d}  {fmt_ts(m.get('created_at'))}  [SYSTEM NOTICE]", YELLOW + BOLD))
            else:
                who = safe(m.get("sender_nickname") or "?")
                tag = c("  [UNVERIFIED KEY]", RED + BOLD) if marker == "unverified" else ""
                print(c(f"#{int(m['id']):04d}  {fmt_ts(m.get('created_at'))}  {who}", WHITE + BOLD) + tag)
            print(wrap(text, "  "), )
            print(line("·"))
        cmds = ["send", "refresh", "back"] + (["older"] if d.get("has_more") else []) + (["newest"] if before else [])
        print(c("commands: " + ", ".join(cmds), CYAN))
        ch = choose("chat@view> ", {k: k for k in cmds})
        if ch == "back":
            return
        if ch == "older":
            before = d.get("next_before_id")
        elif ch == "newest":
            before = None
        elif ch == "send":
            send_message(client, chat_id, other, d)
            before = None


def send_message(client: RemoteClient, chat_id: int, other: str, chat: dict[str, Any]) -> None:
    ring = client.keyring
    if ring is None or ring.current is None:
        print(c("you have no encryption key on this device; cannot send.", RED))
        pause()
        return
    peer_fp = chat.get("other_key_fp")
    if not peer_fp or not FP_RE.fullmatch(str(peer_fp)):
        print(c(f"{other} has not published an encryption key yet.", YELLOW))
        pause()
        return
    if not verify_peer_key(client, other, peer_fp):
        print(c("not sending to an unverified key.", YELLOW))
        pause()
        return
    text = ask("message (max 128 chars)> ")
    if not MESSAGE_RE.fullmatch(text) or any(ch in "'\"\\/%+" for ch in text):
        print(c("plain text only, 1-128 characters, no ' \" \\ / % +", RED))
        pause()
        return
    peer_pub = client.fetch_pubkey(peer_fp)
    me = ring.current
    if peer_pub is None:
        print(c("could not fetch a valid key for the other user.", RED))
        pause()
        return
    ct = e2e_encrypt(ring.private_for(me["fp"]), me["fp"], peer_pub, peer_fp, chat_id, text)
    resp = client.request({"action": "send_message", "chat_id": chat_id, "ciphertext": ct,
                           "sender_key_fp": me["fp"], "recipient_key_fp": peer_fp})
    show_result(resp)
    if not resp.get("ok") and (resp.get("data") or {}).get("code") == "key_changed":
        print(c("keys changed since you opened the chat; refresh and verify before sending again.", YELLOW))
    pause()


def chats_menu(client: RemoteClient) -> None:
    page = 1
    while True:
        clear()
        section("PRIVATE MESSAGES // END-TO-END ENCRYPTED")
        resp = client.request({"action": "list_chats", "page": page})
        if not resp.get("ok"):
            show_result(resp)
            pause()
            return
        data = resp["data"]
        chats = data.get("chats", [])
        if not chats:
            print(c("no chats found.", YELLOW))
        for ch in chats:
            print(c(f"[ CHAT #{int(ch['chat_id']):04d} ]", CYAN + BOLD) + c(f"  {safe(ch['other_nickname'])}", WHITE + BOLD)
                  + (c("  [blocked]", RED) if ch.get("blocked") else ""))
            key_value("Updated", fmt_ts(ch.get("updated_at")))
            key_value("Unread", ch.get("unread_count", 0), YELLOW if ch.get("unread_count") else WHITE)
            last = ch.get("last_message")
            if last:
                text, _ = decrypt_message(client, int(ch["chat_id"]), safe(ch["other_nickname"]), last)
                print(wrap(text[:WRAP_WIDTH * 2], "  "))
            print(line())
        pg = data.get("pagination")
        page = int(pg.get("page", page)) if pg else page
        page_status(pg)
        cmds = nav_choices(pg, ["open", "view", "my key"])
        print(c("commands: " + ", ".join(cmds), CYAN))
        choice = choose("chat@node> ", cmds)
        new_page = apply_nav(choice, page, pg)
        if new_page is not None:
            page = new_page
        elif choice == "open":
            nickname = ask("chat with nickname> ")
            pf = obtain_pow(client, "open_chat")
            if pf is None:
                pause()
                continue
            r = client.request({"action": "open_chat", "nickname": nickname, **pf})
            show_result(r)
            if r.get("ok") and r.get("data"):
                pause()
                view_chat(client, int(r["data"]["chat_id"]))
            else:
                pause()
        elif choice == "view":
            view_chat(client, ask_int("chat id> "))
        elif choice == "my key":
            key_menu(client)
        else:
            return


def key_menu(client: RemoteClient) -> None:
    while True:
        clear()
        section("ENCRYPTION KEYS", "your private key exists only on this computer; the server never sees it")
        ring = client.keyring
        if ring and ring.current:
            key_value("Your fingerprint", fmt_fp(ring.current["fp"]), CYAN)
            key_value("Stored locally at", ring.path, DIM)
            key_value("Retired keys", max(0, len(ring.keys) - 1), DIM)
            print(c("  That file is on THIS machine, encrypted with your account password. It is never uploaded.", DIM))
            print(c("  Only your PUBLIC key is sent to the server, so others can encrypt messages to you.", DIM))
        else:
            print(c("no key on this device.", YELLOW))
        print(c("Read your fingerprint to your contacts through another channel so they can verify it.", DIM))
        print(line("·"))
        print(c("commands: export (backup / move to another device), import, rotate, back", CYAN))
        ch = choose("keys@node> ", {"export": "export", "import": "import", "rotate": "rotate", "back": "back"})
        if ch == "back":
            return
        if ch == "export":
            if ring is None or not ring.keys:
                print(c("nothing to export.", YELLOW))
                pause()
                continue
            default = Path.home() / f"afterlife-keys-{client.nickname}.json"
            dest = Path(ask(f"save to [{default}]> ", allow_blank=True) or default).expanduser()
            pw = ask_hidden("passphrase to protect the export (10+ chars)> ")
            if len(pw) < 10 or ask_hidden("repeat passphrase> ") != pw:
                print(c("passphrases must match and be at least 10 characters.", RED))
                pause()
                continue
            ring.export_to(dest, pw)
            print(c(f"[ OK ] exported {len(ring.keys)} key(s) to {dest} (encrypted). Keep it offline.", GREEN))
            pause()
        elif ch == "import":
            if not client.password or not client.nickname:
                pause()
                continue
            src = Path(ask("exported key file> ")).expanduser()
            pw = ask_hidden("export passphrase> ")
            if ring is None:
                ring = KeyRing(KeyRing.path_for(client.host, client.nickname), [])
                client.keyring = ring
            try:
                added = ring.import_from(src, pw)
            except ClientError as exc:
                print(c(f"[ FAIL ] {exc}", RED))
                pause()
                continue
            ring.save(client.password)
            print(c(f"[ OK ] imported {added} new key(s); older messages encrypted to them are readable here now.", GREEN))
            if ring.current and yes_no("publish the newest imported key as your current key? (answer no to keep this device's key) [yes/no]> "):
                newest = ring.keys[added - 1] if added else ring.current
                ring.keys.remove(newest)
                ring.keys.append(newest)
                resp = client.request({"action": "set_public_key", "public_key": newest["pub"]})
                show_result(resp)
                ring.save(client.password)
            pause()
        elif ch == "rotate" and client.password:
            if ring is None:
                ring = KeyRing(KeyRing.path_for(client.host, client.nickname or "x"), [])
                client.keyring = ring
            entry = ring.add_new_key()
            resp = client.request({"action": "set_public_key", "public_key": entry["pub"]})
            show_result(resp)
            if resp.get("ok"):
                ring.save(client.password)
                print(c(f"new fingerprint: {fmt_fp(entry['fp'])}", CYAN))
            else:
                ring.keys.pop()
            pause()


# ---------------------------------------------------------------- forum
def view_thread(client: RemoteClient, thread_id: int) -> None:
    page = 1
    while True:
        resp = client.request({"action": "thread_details", "thread_id": thread_id, "page": page})
        if not resp.get("ok"):
            show_result(resp)
            pause()
            return
        d = resp["data"]
        clear()
        section("FORUM // THREAD VIEW")
        print(c(f"[ THREAD #{int(d['id']):04d} ]", MAGENTA + BOLD))
        print(line("═", CYAN))
        print(c(safe(d["title"]), WHITE + BOLD))
        key_value("Author", d.get("author_display"))
        key_value("Posted", fmt_ts(d.get("created_at")))
        print(line("·"))
        print(wrap_block(d.get("body") or "", "  "))
        print()
        pg = d.get("pagination")
        print(c(f"[ REPLIES // {safe(pg.get('total', 0)) if pg else 0} ]", CYAN))
        for p in d.get("posts", []):
            # The reply header uses a marker no body line can produce (bodies are
            # indented and cannot contain '▌'), so replies cannot be forged.
            print(c(f"▌ #{int(p['id']):04d}  {fmt_ts(p.get('created_at'))}  {safe(p.get('author_display'))}", WHITE + BOLD))
            print(wrap_block(p.get("body") or "", "  │ "))
        page_status(pg)
        cmds = nav_choices(pg, ["comment"] + (["delete thread", "delete comment"] if d.get("is_admin") else []))
        print(c("commands: " + ", ".join(cmds), CYAN))
        ch = choose("thread@view> ", cmds)
        np = apply_nav(ch, page, pg)
        if np is not None:
            page = np
        elif ch == "comment":
            body = ask_multiline("reply>")
            if body:
                pf = obtain_pow(client, "post_comment")
                if pf is not None:
                    show_result(client.request({"action": "post_comment", "thread_id": thread_id, "body": body, **pf}))
            pause()
        elif ch == "delete thread":
            if yes_no(f"delete thread #{thread_id}? [yes/no]> "):
                r = client.request({"action": "delete_thread", "thread_id": thread_id})
                show_result(r)
                pause()
                if r.get("ok"):
                    return
        elif ch == "delete comment":
            show_result(client.request({"action": "delete_comment", "comment_id": ask_int("comment id> ")}))
            pause()
        else:
            return


def print_threads(threads: list[dict[str, Any]]) -> None:
    if not threads:
        print(c("no threads found.", YELLOW))
    for th in threads:
        print(c(f"[ THREAD #{int(th['id']):04d} ]", CYAN + BOLD) + c(f"  {safe(th['title'])}", WHITE + BOLD))
        key_value("Author", th.get("author_display"))
        key_value("Replies", th.get("reply_count", 0))
        key_value("Last activity", fmt_ts(th.get("updated_at")))
        print(line())


def forum_menu(client: RemoteClient, query: Optional[str] = None) -> None:
    page = 1
    while True:
        clear()
        section("FORUM // " + (f"SEARCH: {safe(query)}" if query else "COMMUNITY BOARD"))
        req = {"action": "search_threads", "query": query, "page": page} if query else {"action": "list_threads", "page": page}
        resp = client.request(req)
        if not resp.get("ok"):
            show_result(resp)
            pause()
            return
        data = resp["data"]
        print_threads(data.get("threads", []))
        pg = data.get("pagination")
        page = int(pg.get("page", page)) if pg else page
        page_status(pg)
        cmds = nav_choices(pg, ["view"] + ([] if query else ["create", "search"]))
        print(c("commands: " + ", ".join(cmds), CYAN))
        ch = choose("forum@node> ", cmds)
        np = apply_nav(ch, page, pg)
        if np is not None:
            page = np
        elif ch == "view":
            view_thread(client, ask_int("thread id> "))
        elif ch == "search":
            forum_menu(client, ask("search query (3+ chars)> "))
        elif ch == "create":
            title = ask("title> ")
            body = ask_multiline("body>")
            if body:
                pf = obtain_pow(client, "create_thread")
                if pf is not None:
                    r = client.request({"action": "create_thread", "title": title, "body": body, **pf})
                    show_result(r)
            pause()
        else:
            return


def invites_menu(client: RemoteClient) -> None:
    while True:
        clear()
        section("INVITES // VOUCH FOR NEW MEMBERS", "each invite ties a new account to you; if they are banned you lose reputation")
        resp = client.request({"action": "list_invites"})
        if not resp.get("ok"):
            show_result(resp)
            pause()
            return
        for inv in resp["data"].get("invites", []) or []:
            print(c(f"  [#{int(inv['id']):04d}] ", MAGENTA) + c(safe(inv["state"]), WHITE) + c(f"  created {fmt_ts(inv.get('created_at'))}", DIM))
        print(line())
        ch = choose("invites@node> ", {"create": "create", "revoke": "revoke", "back": "back"})
        if ch == "create":
            r = client.request({"action": "create_invite"})
            show_result(r)
            if r.get("ok") and r.get("data", {}).get("invite_code"):
                print(c("[ INVITE CODE // SHOWN ONCE ]", YELLOW + BOLD))
                print(c(safe(r["data"]["invite_code"]), MAGENTA + BOLD))
            pause()
        elif ch == "revoke":
            show_result(client.request({"action": "revoke_invite", "invite_id": ask_int("invite id> ")}))
            pause()
        else:
            return


def admin_paged(client: RemoteClient, action: str, key: str, render, extra: Optional[dict[str, Any]] = None) -> None:
    page = 1
    while True:
        r = client.request({"action": action, "page": page, **(extra or {})})
        if not r.get("ok"):
            show_result(r)
            pause()
            return
        items = r["data"].get(key, [])
        if not items:
            print(c("nothing here.", YELLOW))
        for it in items:
            render(it)
        pg = r["data"].get("pagination")
        page_status(pg)
        cmds = nav_choices(pg)
        ch = choose("admin@list> ", cmds)
        np = apply_nav(ch, page, pg)
        if np is None:
            return
        page = np
        clear()


def admin_menu(client: RemoteClient) -> None:
    cmds = ["mode", "lock", "pending", "approve", "reject", "rep", "flags", "resolve flag", "frozen", "resolve rating",
            "disputes", "resolve dispute", "ban", "wipe", "back"]
    while True:
        clear()
        section("ADMIN CONSOLE // MODERATION GRID")
        r = client.request({"action": "admin_get_settings"})
        if r.get("ok"):
            s = r["data"]
            key_value("Registration", s.get("registration_mode"), CYAN)
            key_value("Approval lock", "ON" if s.get("approval_required") else "off", YELLOW if s.get("approval_required") else WHITE)
            key_value("Signups/hour", f"{safe(s.get('registrations_last_hour'))} (PoW rises above {safe(s.get('registration_soft_cap_per_hour'))})", DIM)
        print(line("·"))
        print(c("commands: " + ", ".join(cmds), CYAN))
        ch = choose("admin@node> ", {k: k for k in cmds})
        if ch == "back":
            return
        clear()
        if ch == "mode":
            m = choose("registration mode [open/invite/closed]> ", {"open": "open", "invite": "invite", "closed": "closed"})
            show_result(client.request({"action": "admin_set_registration_mode", "mode": m}))
        elif ch == "lock":
            show_result(client.request({"action": "admin_set_approval_lock", "enabled": yes_no("require approval for ALL new accounts? [yes/no]> ")}))
        elif ch == "pending":
            admin_paged(client, "admin_list_pending", "pending", lambda u: print(
                c(f"  {safe(u['nickname'])}", WHITE + BOLD) + c(f"  registered {fmt_ts(u.get('created_at'))}"
                                                                 + (f"  invited by {safe(u['invited_by'])}" if u.get("invited_by") else ""), DIM)))
            continue
        elif ch in ("approve", "reject"):
            show_result(client.request({"action": f"admin_{ch}_user", "nickname": ask("nickname> ")}))
        elif ch == "rep":
            raw = ask("reputation delta (e.g. 5 or -3.5)> ")
            try:
                delta = float(raw)
            except ValueError:
                print(c("invalid number.", RED))
                pause()
                continue
            show_result(client.request({"action": "admin_rep", "nickname": ask("nickname> "), "delta": delta}))
        elif ch == "flags":
            include = yes_no("include resolved? [yes/no]> ")
            admin_paged(client, "admin_list_flags", "flags", lambda f: (
                print(c(f"  #{int(f['id']):04d} ", MAGENTA) + (c("[resolved]", DIM) if f.get("resolved") else c("[open]", YELLOW))
                      + c(f" {safe(f['kind'])} x{safe(f.get('count', 1))} ", RED) + c(safe(f.get("nickname") or f"user {f.get('user_id')}"), WHITE)),
                print(c("     " + safe(f.get("detail", "")) + f"  (last {fmt_ts(f.get('last_seen_at'))})", DIM))), {"include_resolved": include})
            continue
        elif ch == "resolve flag":
            show_result(client.request({"action": "admin_resolve_flag", "flag_id": ask_int("flag id> ")}))
        elif ch == "frozen":
            admin_paged(client, "admin_list_frozen_ratings", "frozen_ratings", lambda f: print(
                c(f"  {safe(f['rater'])} -> {safe(f['target'])} ", WHITE) + c(f"(job {int(f['job_id'])}, value {int(f['rating_value'])})  "
                                                                               f"rater_id={int(f['rater_id'])} target_id={int(f['target_id'])}", DIM)))
            continue
        elif ch == "resolve rating":
            show_result(client.request({"action": "admin_resolve_rating", "rater_id": ask_int("rater_id> "), "target_id": ask_int("target_id> "),
                                        "job_id": ask_int("job_id> "), "apply": yes_no("apply it? [yes = apply / no = discard]> ")}))
        elif ch == "disputes":
            admin_paged(client, "admin_list_disputes", "disputes", lambda dd: print(
                c(f"  job #{int(dd['job_id'])}", WHITE + BOLD) + c(f"  author {safe(dd['author'])}  worker {safe(dd['worker'])}  opened {fmt_ts(dd.get('created_at'))}", DIM)))
            continue
        elif ch == "resolve dispute":
            jid = ask_int("job id> ")
            outcome = choose("outcome [done/open/cancelled]> ", {"done": "done", "open": "open", "cancelled": "cancelled"})
            show_result(client.request({"action": "admin_resolve_dispute", "job_id": jid, "outcome": outcome}))
        elif ch in ("ban", "wipe"):
            nick = ask(f"nickname to {ch}> ")
            if yes_no(f"{ch} {nick}? [yes/no]> "):
                show_result(client.request({"action": "ban_user" if ch == "ban" else "wipe_user", "nickname": nick}))
        pause()


def main_menu(client: RemoteClient) -> None:
    choices = {"open jobs": "open", "open": "open", "done jobs": "done", "done": "done", "cancelled jobs": "cancelled",
               "cancelled": "cancelled", "create job": "create", "create": "create", "job details": "details", "details": "details",
               "my authored jobs": "mine", "my jobs": "mine", "my accepted": "accepted", "accepted": "accepted",
               "profile": "profile", "rate": "rate", "blocks": "blocks", "chats": "chats", "forum": "forum",
               "invites": "invites", "keys": "keys", "admin": "admin", "logout": "logout", "quit": "quit", "exit": "quit"}
    while client.session_token:
        clear()
        section("MAIN GRID // OPERATOR CONSOLE")
        key_value("Operator", (client.nickname or "?") + (" [admin]" if client.is_admin else ""), GREEN)
        print(c("commands: open jobs, done jobs, cancelled jobs, create job, job details, my jobs, my accepted, profile, rate, "
                "blocks, chats, keys, forum, invites" + (", admin" if client.is_admin else "") + ", logout, quit", CYAN))
        print(line("·"))
        ch = choose("afterlife@node> ", choices)
        try:
            if ch in ("open", "done", "cancelled"):
                list_jobs_menu(client, ch)
            elif ch == "create":
                create_job_menu(client)
            elif ch == "details":
                job_details_menu(client)
            elif ch == "mine":
                list_jobs_menu(client, None, "my_jobs", "MY CONTRACTS")
            elif ch == "accepted":
                list_jobs_menu(client, None, "my_accepts", "ACCEPTED CONTRACTS")
            elif ch == "profile":
                view_profile(client)
            elif ch == "rate":
                rate_user_menu(client)
            elif ch == "blocks":
                blocks_menu(client)
            elif ch == "chats":
                chats_menu(client)
            elif ch == "keys":
                key_menu(client)
            elif ch == "forum":
                forum_menu(client)
            elif ch == "invites":
                invites_menu(client)
            elif ch == "admin":
                if client.is_admin:
                    admin_menu(client)
            elif ch == "logout":
                try:
                    client.request({"action": "logout"})
                except ClientError:
                    pass
                client.session_token = None
            else:
                raise SystemExit(0)
        except ClientError as exc:
            print(c(f"[ CONNECTION ] {exc}", RED))
            pause()
        except SessionExpired as exc:
            print(c(f"[ SESSION ] {exc} — please log in again.", YELLOW))
            pause()
    client.nickname = None
    client.is_admin = False
    client.keyring = None
    client.password = None
    client.pubkey_cache.clear()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="AFTERLIFE client. Talks to Tor's SOCKS port directly (no proxychains).")
    p.add_argument("--host", default=PINNED_ONION or "", help="the service's .onion address")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--socks", default="127.0.0.1:9050", help="Tor SOCKS address (Tor Browser uses 127.0.0.1:9150)")
    p.add_argument("--direct", action="store_true", help="development only: connect without Tor")
    p.add_argument("--yes", action="store_true", help="trust a new onion address without asking")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    clear()
    section("NODE LINK // TOR HIDDEN SERVICE", "traffic routed through the onion network")
    host = (args.host or ask("onion address> ")).strip().lower()
    if not args.direct:
        if not valid_v3_onion(host):
            sys.exit(c("not a valid v3 .onion address (check for typos: 56 characters + .onion, valid checksum).", RED))
        if not check_known_host(host, args.yes):
            sys.exit(c("aborted.", YELLOW))
    shost, _, sport = args.socks.rpartition(":")
    transport = Transport(host, args.port, shost or "127.0.0.1", int(sport or 9050), direct=args.direct)
    client = RemoteClient(transport)
    try:
        resp = client.request({"action": "ping"})
        if not resp.get("ok"):
            sys.exit(c("[ LINK ERROR ] server responded unexpectedly.", RED))
        if resp.get("data", {}).get("version") != PROTOCOL_VERSION:
            print(c(f"[ WARN ] server protocol {safe(resp.get('data', {}).get('version'))}, client {PROTOCOL_VERSION}. Update your client.", YELLOW))
        print(c("[ LINK UP ] connection established.", GREEN))
    except ClientError as exc:
        sys.exit(c(f"[ CONNECTION FAILURE ] {exc}", RED))
    time.sleep(0.4)
    while True:
        auth_menu(client)
        main_menu(client)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c("\n[ session interrupted ]", RED))
