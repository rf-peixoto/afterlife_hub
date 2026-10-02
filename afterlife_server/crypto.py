"""At-rest encryption, password hashing and proof-of-work primitives."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import secrets
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from . import config as C

KEY_FILE_HEADER = "afterlife-master-key-v2:"


class DecryptionError(Exception):
    pass


def _write_secret_file(path: Path, data: str) -> None:
    """Create a 0600 file atomically (never world-readable, even briefly)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, data.encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def load_or_create_master_secret(path: Path) -> bytes:
    """The key file is ASCII (header + base64), so no whitespace stripping can
    ever alter the secret. Anything unexpected is a hard error."""
    if path.exists():
        text = path.read_text(encoding="ascii")
        line = text.strip()  # safe: base64 alphabet contains no whitespace
        if not line.startswith(KEY_FILE_HEADER):
            raise RuntimeError(f"{path} is not an AFTERLIFE v2 key file. Refusing to start.")
        try:
            secret = base64.b64decode(line[len(KEY_FILE_HEADER):], validate=True)
        except (binascii.Error, ValueError):
            raise RuntimeError(f"{path} is corrupt (invalid base64). Refusing to start.")
        if len(secret) != 32:
            raise RuntimeError(f"{path} is corrupt (wrong key length). Refusing to start.")
        return secret
    secret = secrets.token_bytes(32)
    _write_secret_file(path, KEY_FILE_HEADER + base64.b64encode(secret).decode("ascii") + "\n")
    return secret


class CryptoBox:
    def __init__(self, master_path: Path) -> None:
        master = load_or_create_master_secret(master_path)
        self.fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(b"afterlife-fernet" + master).digest()))
        self._search_key = hashlib.sha256(b"afterlife-search-index" + master).digest()
        self._token_key = hashlib.sha256(b"afterlife-token-hmac" + master).digest()

    def enc(self, value: str) -> str:
        return self.fernet.encrypt(value.encode("utf-8")).decode("ascii")

    def dec(self, value: Optional[str]) -> str:
        """Fails loudly: a ciphertext that does not decrypt means the key is
        wrong or data is corrupt; it is never silently shown as empty."""
        if value is None or value == "":
            return ""
        try:
            return self.fernet.decrypt(value.encode("ascii")).decode("utf-8")
        except (InvalidToken, UnicodeError) as exc:
            raise DecryptionError("stored ciphertext could not be decrypted") from exc

    def term_hmac(self, term: str) -> str:
        return hmac.new(self._search_key, term.encode("utf-8"), hashlib.sha256).hexdigest()

    def token_digest(self, token: str) -> str:
        """Keyed digest for high-entropy random tokens (private-job tokens,
        invite codes). A single HMAC is enough: the tokens are 128+ bit random,
        so a slow KDF would only hand attackers a CPU-exhaustion lever."""
        return hmac.new(self._token_key, token.encode("utf-8"), hashlib.sha256).hexdigest()


# ============================================================== passwords
PBKDF2_ITERATIONS = 310_000


def pbkdf2_hash(value: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2${PBKDF2_ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def pbkdf2_verify(value: str, stored: str) -> bool:
    try:
        scheme, iters, salt_b64, digest_b64 = stored.split("$")
        if scheme != "pbkdf2":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), base64.b64decode(salt_b64), int(iters))
        return hmac.compare_digest(digest, base64.b64decode(digest_b64))
    except Exception:
        return False


# A fixed dummy hash so a login for a non-existent user costs the same as a real one.
DUMMY_PASSWORD_HASH = pbkdf2_hash(secrets.token_hex(16))


# ============================================================== proof of work
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
    return hashlib.scrypt(f"{prefix}:{nonce}".encode("utf-8"), salt=prefix.encode("utf-8"),
                          n=C.POW_SCRYPT_N, r=C.POW_SCRYPT_R, p=C.POW_SCRYPT_P,
                          maxmem=C.POW_SCRYPT_MAXMEM, dklen=32)


def pow_solution_ok(prefix: str, nonce: str, difficulty: int) -> bool:
    if not nonce.isdigit() or len(nonce) > 20:
        return False
    return leading_zero_bits(pow_digest(prefix, nonce)) >= difficulty


def clamp_difficulty(value: int) -> int:
    return max(C.POW_MIN_DIFFICULTY, min(C.POW_MAX_DIFFICULTY, int(value)))


def difficulty_for_reputation(rep: float) -> int:
    """-1 bit per +10 reputation; +1 bit per negative reputation point."""
    import math
    if rep >= 0:
        d = C.POW_BASE_DIFFICULTY - int(rep // 10)
    else:
        d = C.POW_BASE_DIFFICULTY + int(math.ceil(-rep))
    return clamp_difficulty(d)
