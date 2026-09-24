#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import socket
import sys
import textwrap
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

DEFAULT_HOST = os.environ.get("AFTERLIFE_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("AFTERLIFE_PORT", "2077"))
SOCKET_TIMEOUT = 25
MAX_RESPONSE_BYTES = int(os.environ.get("AFTERLIFE_MAX_RESPONSE_BYTES", "1048576"))
WRAP_WIDTH = 92
BOOT_DELAY = 0.12

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
YELLOW = "\033[33m"
RED = "\033[31m"
WHITE = "\033[37m"

STATUS_COLORS = {"OPEN": GREEN, "DONE": CYAN, "CANCELLED": RED}


def c(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"


def hr(char: str = "─") -> str:
    return char * WRAP_WIDTH


def line(char: str = "─", color: str = DIM) -> str:
    return c(hr(char), color)


def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def pause() -> None:
    input(c("\n[ press enter to continue ] ", DIM))


def wrap(text: str, indent: str = "") -> str:
    width = max(20, WRAP_WIDTH - len(indent))
    return "\n".join(indent + part for part in textwrap.wrap(text, width=width)) if text else ""


def wrap_block(text: str, indent: str = "") -> str:
    """Wrap multi-line text while preserving the author's own line breaks."""
    if not text:
        return ""
    out: list[str] = []
    for raw_line in text.split("\n"):
        if raw_line.strip() == "":
            out.append(indent.rstrip())
        else:
            out.append(wrap(raw_line, indent=indent))
    return "\n".join(out)


def fmt_ts(ts: Optional[int]) -> str:
    if not ts:
        return "-"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def banner() -> str:
    inner = WRAP_WIDTH - 2
    title = "A F T E R L I F E".center(inner)
    subtitle = "private freelancer terminal".center(inner)
    return "\n".join([
        c("╔" + "═" * inner + "╗", CYAN),
        c("║", CYAN) + c(title, MAGENTA + BOLD) + c("║", CYAN),
        c("║", CYAN) + c(subtitle, DIM) + c("║", CYAN),
        c("╚" + "═" * inner + "╝", CYAN),
    ])


def section(title: str, subtitle: Optional[str] = None) -> None:
    print(banner())
    print(c(f"[ {title} ]", CYAN + BOLD))
    if subtitle:
        print(c(subtitle, DIM))
    print(line())


def prompt(text: str, color: str = MAGENTA) -> str:
    return c(text, color)


def status_badge(status: str) -> str:
    normalized = str(status or "UNKNOWN").upper()
    return c(f"● {normalized}", STATUS_COLORS.get(normalized, WHITE))


def key_value(label: str, value: str, value_color: str = WHITE) -> None:
    print(c(f"{label:<16}: ", DIM) + c(str(value), value_color))


def boot_sequence() -> None:
    for item in [
        "initializing terminal shell...",
        "routing through tor network...",
        "establishing hidden service uplink...",
    ]:
        print(c(f"> {item}", DIM))
        time.sleep(BOOT_DELAY)


@dataclass
class RemoteClient:
    host: str
    port: int
    session_token: Optional[str] = None
    nickname: Optional[str] = None
    is_admin: bool = False

    def request(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.session_token:
            payload.setdefault("session_token", self.session_token)
        raw = json.dumps(payload).encode("utf-8") + b"\n"
        with socket.create_connection((self.host, self.port), timeout=SOCKET_TIMEOUT) as sock:
            sock.settimeout(SOCKET_TIMEOUT)
            sock.sendall(raw)
            chunks = b""
            while not chunks.endswith(b"\n"):
                data = sock.recv(4096)
                if not data:
                    break
                chunks += data
                if len(chunks) > MAX_RESPONSE_BYTES:
                    raise RuntimeError(f"Server response exceeded {MAX_RESPONSE_BYTES} bytes.")
        if not chunks:
            raise RuntimeError("No response from server.")
        return json.loads(chunks.decode("utf-8").strip())

    def ping(self) -> bool:
        return bool(self.request({"action": "ping"}).get("ok"))


def _leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        bits += 8 - byte.bit_length()
        break
    return bits


def solve_pow(prefix: str, difficulty: int, scrypt_params: dict[str, Any]) -> str:
    """Brute-force a nonce such that the memory-hard scrypt digest of
    'prefix:nonce' has >= difficulty leading zero bits. scrypt makes each guess
    memory-hard, so a GPU/ASIC gains little over an ordinary CPU. The parameters
    are dictated by the server via the challenge."""
    n = int(scrypt_params.get("n", 1 << 13))
    r = int(scrypt_params.get("r", 8))
    p = int(scrypt_params.get("p", 1))
    dklen = int(scrypt_params.get("dklen", 32))
    salt = prefix.encode("utf-8")
    maxmem = 256 * 1024 * 1024
    nonce = 0
    while True:
        candidate = str(nonce)
        digest = hashlib.scrypt(
            f"{prefix}:{candidate}".encode("utf-8"),
            salt=salt, n=n, r=r, p=p, maxmem=maxmem, dklen=dklen,
        )
        if _leading_zero_bits(digest) >= difficulty:
            return candidate
        nonce += 1


def obtain_pow(client: RemoteClient, purpose: str, extra: Optional[dict[str, Any]] = None) -> Optional[dict[str, Any]]:
    """Fetch and solve a proof-of-work challenge for `purpose`. Returns the
    fields to attach to the protected request, or None on failure. `extra`
    carries any fields the server needs to size the challenge (e.g. the nickname
    for a login, so failed-login escalation applies)."""
    payload = {"action": "get_challenge", "purpose": purpose}
    if extra:
        payload.update(extra)
    resp = client.request(payload)
    if not resp.get("ok"):
        show_result(resp)
        return None
    data = resp.get("data", {})
    prefix = str(data.get("prefix", ""))
    difficulty = int(data.get("difficulty", 5))
    scrypt_params = data.get("scrypt", {}) or {}
    challenge_id = data.get("challenge_id")
    print(c(f"solving memory-hard anti-bot challenge (difficulty {difficulty} bits)... this can take a while", DIM))
    start = time.time()
    nonce = solve_pow(prefix, difficulty, scrypt_params)
    print(c(f"challenge solved in {time.time() - start:.1f}s", GREEN))
    return {"challenge_id": challenge_id, "nonce": nonce}


def maybe_pow(client: RemoteClient, purpose: str) -> Optional[dict[str, Any]]:
    """Obtain PoW for a write action only if the server still requires it for
    this account (trusted users are exempt). Returns {} when no PoW is needed,
    the solved fields when it is, or None on failure."""
    payload = {"action": "get_challenge", "purpose": purpose}
    resp = client.request(payload)
    if not resp.get("ok"):
        # Trusted accounts are exempt; the server may still issue a trivial
        # challenge, so only treat hard failures as fatal.
        show_result(resp)
        return None
    data = resp.get("data", {})
    prefix = str(data.get("prefix", ""))
    difficulty = int(data.get("difficulty", 1))
    scrypt_params = data.get("scrypt", {}) or {}
    challenge_id = data.get("challenge_id")
    if difficulty > 1:
        print(c(f"solving memory-hard anti-bot challenge (difficulty {difficulty} bits)...", DIM))
    start = time.time()
    nonce = solve_pow(prefix, difficulty, scrypt_params)
    if difficulty > 1:
        print(c(f"challenge solved in {time.time() - start:.1f}s", GREEN))
    return {"challenge_id": challenge_id, "nonce": nonce}


# =========================
# Input helpers
# =========================
def ask(prompt_text: str, allow_blank: bool = False) -> str:
    while True:
        value = input(prompt(prompt_text)).strip()
        if value or allow_blank:
            return value
        print(c("input required.", RED))


def ask_hidden(prompt_text: str) -> str:
    while True:
        value = getpass.getpass(prompt(prompt_text)).strip()
        if value:
            return value
        print(c("input required.", RED))


def ask_int(prompt_text: str, allow_negative: bool = False) -> int:
    while True:
        raw = input(prompt(prompt_text)).strip()
        try:
            value = int(raw)
            if not allow_negative and value < 0:
                raise ValueError
            return value
        except ValueError:
            print(c("enter a valid number.", RED))


def yes_no(prompt_text: str) -> bool:
    while True:
        value = input(prompt(prompt_text)).strip().lower()
        if value in {"y", "yes"}:
            return True
        if value in {"n", "no"}:
            return False
        print(c("answer with yes or no.", RED))


def ask_multiline(prompt_text: str) -> Optional[str]:
    """Collect a multi-line block. End with a single '.' on its own line.
    Type '/cancel' on its own line to abort (returns None)."""
    print(prompt(prompt_text))
    print(c("  (type your text; finish with a single '.' on a line, or '/cancel' to abort)", DIM))
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
    text = "\n".join(lines).strip()
    if not text:
        print(c("input required.", RED))
        return ""
    return text


def normalize_choice(value: str) -> str:
    return value.strip().lower().replace("_", " ").replace("-", " ")


def choose(prompt_text: str, mapping: dict[str, str]) -> str:
    normalized = {normalize_choice(k): v for k, v in mapping.items()}
    while True:
        value = normalize_choice(input(prompt(prompt_text)))
        if value in normalized:
            return normalized[value]
        print(c("unknown option.", RED))


def show_result(response: dict[str, Any]) -> None:
    print(line("·"))
    if response.get("ok"):
        print(c(f"[ OK ] {response.get('message', 'operation completed.')}", GREEN))
    else:
        message = response.get("message", "request failed.")
        retry_after = response.get("retry_after")
        if retry_after:
            message = f"{message} retry after {retry_after}s."
        print(c(f"[ FAIL ] {message}", RED))


# =========================
# Rendering helpers
# =========================
def format_rep(rep: float) -> str:
    try:
        value = float(rep)
    except (TypeError, ValueError):
        return c(str(rep), WHITE)
    text = f"{value:.3f}".rstrip("0").rstrip(".")
    if value < 0:
        return c(text, RED + BOLD)
    if value > 0:
        return c(f"+{text}", GREEN)
    return c("0", WHITE)


def print_jobs(jobs: list[dict[str, Any]], include_author: bool = True, completed_mode: bool = False) -> None:
    if not jobs:
        print(c("no contracts found.", YELLOW))
        return
    for job in jobs:
        print(c(f"[ CONTRACT #{int(job['id']):04d} ]", CYAN + BOLD))
        print(c(str(job["title"]), WHITE + BOLD))
        key_value("Reward", str(job["reward"]))
        key_value("Min rep", str(job.get("min_reputation", 0)), CYAN)
        key_value("Status", status_badge(str(job.get("status", "open"))))
        if not completed_mode:
            key_value("Accepts", str(job.get("accept_count", 0)))
            if include_author and job.get("author_display"):
                key_value("Author", str(job["author_display"]))
        if job.get("not_enough_reputation"):
            print(c("[NOT ENOUGH REPUTATION]", RED + BOLD))
        print(line())


def print_job_details(data: dict[str, Any]) -> None:
    print(c(f"[ CONTRACT #{int(data['id']):04d} // SECURE VIEW ]", MAGENTA + BOLD))
    print(line("═", CYAN))
    print(c(str(data["title"]), WHITE + BOLD))
    print(line("·"))
    key_value("Reward", str(data["reward"]))
    key_value("Min rep", str(data.get("min_reputation", 0)), CYAN)
    key_value("Status", status_badge(str(data["status"])))
    key_value("Author", str(data.get("author_display") or data["author_nickname"]))
    key_value("Private", "yes" if data["is_private"] else "no", YELLOW if data["is_private"] else WHITE)
    key_value("Accepts", str(data.get("accept_count", 0)))
    if data.get("viewer_reputation") is not None:
        print(c(f"Your reputation: ", DIM) + format_rep(data["viewer_reputation"]))
    if data.get("not_enough_reputation"):
        print(c("[NOT ENOUGH REPUTATION]", RED + BOLD))
    print()
    if data.get("description_visible"):
        print(c("[ DESCRIPTION // DECRYPTED ]", CYAN))
        print(wrap(data.get("description") or "", indent="  "))
    else:
        print(c("[ DESCRIPTION LOCKED ] provide unlock token or be the author/admin.", YELLOW))
    if data.get("worker_pool") is not None:
        print()
        print(c("[ ACCEPTED WORKERS ]", CYAN))
        if data["worker_pool"]:
            for worker in data["worker_pool"]:
                marker = c("  <selected>", GREEN + BOLD) if data.get("selected_worker_id") == worker["id"] else ""
                print(c(f"  [{worker['id']}] ", MAGENTA) + c(worker["nickname"], WHITE) + c(f"  rep={worker['reputation']}", DIM) + marker)
        else:
            print(c("  no workers assigned yet.", DIM))


def print_chats(chats: list[dict[str, Any]]) -> None:
    if not chats:
        print(c("no chats found.", YELLOW))
        return
    for chat in chats:
        print(c(f"[ CHAT #{int(chat['chat_id']):04d} ]", CYAN + BOLD) + c(f"  {chat['other_nickname']}", WHITE + BOLD))
        key_value("Updated", fmt_ts(chat.get("updated_at")))
        key_value("Unread", str(chat.get("unread_count", 0)), YELLOW if chat.get("unread_count", 0) else WHITE)
        preview = str(chat.get("last_message") or "")
        if preview:
            print(wrap(preview[:WRAP_WIDTH * 2], indent="  "))
        print(line())


def print_messages(data: dict[str, Any]) -> None:
    print(c(f"[ CHAT #{int(data['chat_id']):04d} WITH {data['other_nickname']} ]", CYAN + BOLD))
    print(line())
    messages = data.get("messages", [])
    if not messages:
        print(c("no messages in this chat.", YELLOW))
        return
    for msg in messages:
        sender = str(msg.get("sender_nickname") or "system")
        color = YELLOW if msg.get("message_type") == "system" else WHITE
        print(c(f"#{int(msg['id']):04d}  {fmt_ts(msg.get('created_at'))}  {sender}", color + BOLD))
        print(wrap(str(msg.get("body") or ""), indent="  "))
        print(line("·"))


def print_blocks(blocks: list[dict[str, Any]]) -> None:
    if not blocks:
        print(c("you have not blocked anyone.", YELLOW))
        return
    for item in blocks:
        print(c(str(item["nickname"]), WHITE + BOLD) + c(f"  rep={item['reputation']}", DIM))
    print(line())


def print_threads(threads: list[dict[str, Any]], heading: Optional[str] = None) -> None:
    if heading:
        print(c(heading, CYAN))
        print(line("·"))
    if not threads:
        print(c("no threads found.", YELLOW))
        return
    for th in threads:
        print(c(f"[ THREAD #{int(th['id']):04d} ]", CYAN + BOLD) + c(f"  {th['title']}", WHITE + BOLD))
        key_value("Author", str(th.get("author_display") or th.get("author_nickname", "?")))
        key_value("Replies", str(th.get("reply_count", 0)))
        key_value("Last activity", fmt_ts(th.get("updated_at")))
        print(line())


def print_thread_detail(data: dict[str, Any]) -> None:
    print(c(f"[ THREAD #{int(data['id']):04d} ]", MAGENTA + BOLD))
    print(line("═", CYAN))
    print(c(str(data["title"]), WHITE + BOLD))
    key_value("Author", str(data.get("author_display") or data["author_nickname"]))
    key_value("Posted", fmt_ts(data.get("created_at")))
    print(line("·"))
    print(wrap_block(str(data.get("body") or ""), indent="  "))
    print()
    posts = data.get("posts", [])
    print(c(f"[ REPLIES // {len(posts)} ]", CYAN))
    if not posts:
        print(c("  no replies yet.", DIM))
        return
    for p in posts:
        print(c(f"  #{int(p['id']):04d}  {fmt_ts(p.get('created_at'))}  {p.get('author_display') or p.get('author_nickname')}", WHITE + BOLD))
        print(wrap_block(str(p.get("body") or ""), indent="    "))
        print(c("  " + hr("·"), DIM))


# =========================
# Menus
# =========================
def connect_prompt(args: argparse.Namespace) -> RemoteClient:
    clear()
    section("NODE LINK // TOR HIDDEN SERVICE", "traffic routed through the onion network")
    boot_sequence()
    print(line("·"))
    host = ask(f"uplink host [{args.host}]> ", allow_blank=True) or args.host
    port_raw = ask(f"uplink port [{args.port}]> ", allow_blank=True) or str(args.port)
    try:
        port = int(port_raw)
    except ValueError:
        port = args.port
    client = RemoteClient(host=host, port=port)
    try:
        if client.ping():
            print(c("[ LINK UP ] connection established.", GREEN))
            key_value("Remote", f"{host}:{port}", CYAN)
        else:
            print(c("[ LINK ERROR ] server responded unexpectedly.", RED))
    except Exception as exc:
        print(c(f"[ CONNECTION FAILURE ] {exc}", RED))
        sys.exit(1)
    time.sleep(0.4)
    return client


def auth_menu(client: RemoteClient) -> None:
    choices = {"login": "login", "register": "register", "quit": "quit", "exit": "quit"}
    while not client.session_token:
        clear()
        section("AUTH // SESSION GATE", "available actions: login, register, quit")
        choice = choose("auth@gateway> ", choices)
        if choice == "login":
            nickname = ask("nickname> ")
            password = ask_hidden("password> ")
            pow_fields = obtain_pow(client, "login", extra={"nickname": nickname})
            if pow_fields is None:
                pause()
                continue
            response = client.request({"action": "login", "nickname": nickname, "password": password, **pow_fields})
            show_result(response)
            if response.get("ok"):
                data = response.get("data", {})
                client.session_token = data.get("session_token")
                client.nickname = data.get("nickname")
                client.is_admin = bool(data.get("is_admin"))
                time.sleep(0.5)
            else:
                pause()
        elif choice == "register":
            nickname = ask("new nickname> ")
            password = ask_hidden("new password> ")
            print(c("an invite code may be required depending on the server's registration mode.", DIM))
            invite_code = ask("invite code [blank if none]> ", allow_blank=True)
            pow_fields = obtain_pow(client, "register")
            if pow_fields is None:
                pause()
                continue
            req = {"action": "register", "nickname": nickname, "password": password, **pow_fields}
            if invite_code:
                req["invite_code"] = invite_code
            response = client.request(req)
            show_result(response)
            if response.get("ok") and response.get("data", {}).get("pending"):
                print(c("[ PENDING ] an administrator must approve your account before you can log in.", YELLOW + BOLD))
            pause()
        else:
            raise SystemExit(0)


def view_profile(client: RemoteClient) -> None:
    clear()
    section("PROFILE // IDENTITY NODE")
    response = client.request({"action": "profile"})
    if not response.get("ok"):
        show_result(response)
        pause()
        return
    data = response["data"]
    nickname = str(data["nickname"])
    if data.get("is_banned"):
        nickname = f"[banned] {nickname}"
    key_value("Nickname", nickname, YELLOW if data.get("is_banned") else WHITE + BOLD)
    print(c("Reputation       : ", DIM) + format_rep(data.get("reputation", 0)))
    key_value("Role", "admin" if data.get("is_admin") else "member", CYAN)
    if data.get("trust_level") is not None:
        key_value("Trust level", str(data.get("trust_level")), CYAN)
    if data.get("distinct_job_partners") is not None:
        key_value("Job partners", str(data.get("distinct_job_partners")))
    if data.get("pow_difficulty") is not None:
        key_value("PoW difficulty", f"{data.get('pow_difficulty')} bits", DIM)
    key_value("Created", fmt_ts(data.get("created_at")))
    print(line())
    pause()


def page_status(pg: Optional[dict[str, Any]]) -> None:
    """Print a 'page X/Y (N total)' status line for a paginated response."""
    if not pg:
        return
    print(line("·"))
    print(c(f"page {pg.get('page', 1)}/{pg.get('total_pages', 1)}  "
            f"({pg.get('total', 0)} total)", DIM))


def nav_choices(pg: Optional[dict[str, Any]], extra: Optional[list[str]] = None) -> dict[str, str]:
    """Build a choose() map of navigation + extra commands based on pagination."""
    opts: dict[str, str] = {}
    if pg and pg.get("has_prev"):
        opts["prev"] = "prev"
    if pg and pg.get("has_next"):
        opts["next"] = "next"
    for e in (extra or []):
        opts[e] = e
    opts["back"] = "back"
    return opts


def apply_nav(choice: str, page: int, pg: Optional[dict[str, Any]]) -> Optional[int]:
    """Translate a nav command into a new page number, or None if not a nav command."""
    if choice == "next" and pg and pg.get("has_next"):
        return page + 1
    if choice == "prev" and pg and pg.get("has_prev"):
        return max(1, page - 1)
    return None


def list_jobs_menu(client: RemoteClient, status: Optional[str] = None, completed_mode: bool = False) -> None:
    page = 1
    while True:
        clear()
        section(f"JOB BOARD // {(status or 'all').upper()} CONTRACTS")
        response = client.request({"action": "list_jobs", "status": status, "page": page})
        if not response.get("ok"):
            show_result(response)
            pause()
            return
        data = response["data"]
        print_jobs(data.get("jobs", []), completed_mode=completed_mode)
        pg = data.get("pagination")
        page = pg.get("page", page) if pg else page
        page_status(pg)
        cmds = nav_choices(pg)
        print(c("commands: " + ", ".join(cmds), CYAN))
        choice = choose("jobs@node> ", cmds)
        new_page = apply_nav(choice, page, pg)
        if new_page is not None:
            page = new_page
        else:
            return


def create_job_menu(client: RemoteClient) -> None:
    clear()
    section("CREATE CONTRACT // BROADCAST")
    print(c("forbidden characters in text fields: ' \" \\ / % +", DIM))
    print(line("·"))
    title = ask("title> ")
    description = ask("description> ")
    reward = ask("reward> ")
    min_reputation = ask("minimum reputation [can be negative]> ")
    is_private = yes_no("private contract? [yes/no]> ")
    pow_fields = maybe_pow(client, "create_job")
    if pow_fields is None:
        pause()
        return
    response = client.request({
        "action": "create_job",
        "title": title,
        "description": description,
        "reward": reward,
        "min_reputation": min_reputation,
        "is_private": is_private,
        **pow_fields,
    })
    show_result(response)
    if response.get("ok"):
        data = response.get("data", {})
        key_value("Contract", str(data.get("job_id")), GREEN)
        if data.get("private_token"):
            print(c("[ PRIVATE TOKEN // STORE SECURELY ]", YELLOW + BOLD))
            print(c(str(data["private_token"]), MAGENTA))
    pause()


def job_details_menu(client: RemoteClient) -> None:
    clear()
    section("CONTRACT DETAILS // SECURE VIEW")
    job_id = ask_int("contract id> ")
    unlock_token = ask("unlock token [blank if none]> ", allow_blank=True)
    response = client.request({"action": "job_details", "job_id": job_id, **({"unlock_token": unlock_token} if unlock_token else {})})
    if not response.get("ok"):
        show_result(response)
        pause()
        return
    data = response["data"]
    while True:
        clear()
        section("CONTRACT DETAILS // LIVE VIEW")
        print_job_details(data)
        print(line("═", CYAN))
        commands = ["back"]
        if client.session_token and not data.get("not_enough_reputation") and not data.get("is_author") and str(data.get("status", "")).lower() == "open":
            commands.append("accept")
        if client.session_token and data.get("viewer_has_accepted"):
            commands.append("withdraw")
        if data.get("is_author") or data.get("is_admin"):
            commands.extend(["select worker", "done", "cancelled", "reopen"])
        if data.get("is_admin"):
            commands.append("delete")
        print(c("commands: " + ", ".join(commands), CYAN))
        choice = choose("contract@view> ", {k: k for k in commands})
        if choice == "accept":
            accept_request = {"action": "accept_job", "job_id": data["id"]}
            if data.get("is_private"):
                private_token = ask("private token> ", allow_blank=True)
                if private_token:
                    accept_request["private_token"] = private_token
            show_result(client.request(accept_request))
            pause()
        elif choice == "withdraw":
            show_result(client.request({"action": "withdraw_job", "job_id": data["id"]}))
            pause()
        elif choice == "select worker":
            worker_id = ask_int("worker id> ")
            show_result(client.request({"action": "select_worker", "job_id": data["id"], "worker_id": worker_id}))
            pause()
        elif choice == "done":
            show_result(client.request({"action": "set_status", "job_id": data["id"], "status": "done"}))
            pause()
        elif choice == "cancelled":
            show_result(client.request({"action": "set_status", "job_id": data["id"], "status": "cancelled"}))
            pause()
        elif choice == "reopen":
            show_result(client.request({"action": "set_status", "job_id": data["id"], "status": "open"}))
            pause()
        elif choice == "delete":
            if yes_no(f"delete contract #{data['id']} permanently? [yes/no]> "):
                resp = client.request({"action": "delete_job", "job_id": data["id"]})
                show_result(resp)
                pause()
                if resp.get("ok"):
                    return
        else:
            return
        refresh = client.request({"action": "job_details", "job_id": data["id"], **({"unlock_token": unlock_token} if unlock_token else {})})
        if not refresh.get("ok"):
            show_result(refresh)
            pause()
            return
        data = refresh["data"]


def my_jobs_menu(client: RemoteClient) -> None:
    clear()
    section("MY CONTRACTS // AUTHORED")
    response = client.request({"action": "my_jobs"})
    if not response.get("ok"):
        show_result(response)
        pause()
        return
    print_jobs(response["data"]["jobs"], include_author=False)
    pause()


def my_accepts_menu(client: RemoteClient) -> None:
    clear()
    section("MY CONTRACTS // ACCEPTED + COMPLETED")
    response = client.request({"action": "my_accepts"})
    if not response.get("ok"):
        show_result(response)
        pause()
        return
    print_jobs(response["data"]["jobs"], completed_mode=True)
    pause()


def rate_user_menu(client: RemoteClient) -> None:
    clear()
    section("REPUTATION // RATE USER")
    print(c("you may only rate the other party of a job you completed together.", DIM))
    print(c("find the contract id under 'my authored jobs' or 'my accepted'.", DIM))
    print(line("·"))
    nickname = ask("counterparty nickname> ")
    job_id = ask_int("completed contract id> ")
    rating = choose("rating [positive/negative]> ", {"positive": "positive", "negative": "negative"})
    pow_fields = obtain_pow(client, "rate_user")
    if pow_fields is None:
        pause()
        return
    resp = client.request({"action": "rate_user", "nickname": nickname, "rating": rating, "job_id": job_id, **pow_fields})
    show_result(resp)
    if resp.get("ok") and resp.get("data", {}).get("frozen"):
        print(c("[ HELD ] this rating was frozen for moderator review (rating-burst detected).", YELLOW))
    pause()


def blocks_menu(client: RemoteClient) -> None:
    while True:
        clear()
        section("BLOCK LIST // RELATION FILTER")
        response = client.request({"action": "list_blocks"})
        if not response.get("ok"):
            show_result(response)
            pause()
            return
        print_blocks(response["data"].get("blocks", []))
        print(c("commands: block, unblock, back", CYAN))
        choice = choose("blocks@node> ", {"block": "block", "unblock": "unblock", "back": "back"})
        if choice == "block":
            nickname = ask("nickname> ")
            show_result(client.request({"action": "block_user", "nickname": nickname}))
            pause()
        elif choice == "unblock":
            nickname = ask("nickname> ")
            show_result(client.request({"action": "unblock_user", "nickname": nickname}))
            pause()
        else:
            return


def chats_menu(client: RemoteClient) -> None:
    while True:
        clear()
        section("PRIVATE MESSAGES // ENCRYPTED")
        response = client.request({"action": "list_chats"})
        if not response.get("ok"):
            show_result(response)
            pause()
            return
        chats = response["data"].get("chats", [])
        print_chats(chats)
        print(c("commands: open, view, send, back", CYAN))
        print(c("(open starts/ensures a chat with a nickname; view opens a chat by its id)", DIM))
        choice = choose("chat@node> ", {"open": "open", "view": "view", "send": "send", "back": "back"})
        if choice == "open":
            nickname = ask("chat <nickname> > ")
            pow_fields = maybe_pow(client, "open_chat")
            if pow_fields is None:
                pause()
                continue
            resp = client.request({"action": "open_chat", "nickname": nickname, **pow_fields})
            show_result(resp)
            if resp.get("ok") and resp.get("data"):
                key_value("Chat id", str(resp["data"].get("chat_id")), GREEN)
                print(c("use 'view' with this chat id to read it, or 'send' to message.", DIM))
            pause()
        elif choice == "view":
            chat_id = ask_int("chat id> ")
            # Viewing lists every message and marks them read, which makes a
            # separate single-message "read" command unnecessary.
            resp = client.request({"action": "list_messages", "chat_id": chat_id})
            if resp.get("ok"):
                clear()
                section("PRIVATE MESSAGES // CHAT VIEW")
                print_messages(resp["data"])
                print(line("·"))
                key_value("Chat id", str(chat_id), GREEN)
                print(c("use 'send' with this chat id to reply.", DIM))
            else:
                show_result(resp)
            pause()
        elif choice == "send":
            chat_id = ask_int("chat id> ")
            message = ask("message> ")
            show_result(client.request({"action": "send_message", "chat_id": chat_id, "message": message}))
            pause()
        else:
            return


def ban_user_menu(client: RemoteClient) -> None:
    clear()
    section("ADMIN BAN // PERMANENT ACTION")
    nickname = ask("nickname to ban> ")
    if yes_no(f"ban {nickname} permanently? [yes/no]> "):
        show_result(client.request({"action": "ban_user", "nickname": nickname}))
    else:
        print(c("operation cancelled.", YELLOW))
    pause()


def wipe_user_menu(client: RemoteClient) -> None:
    clear()
    section("ADMIN WIPE // PURGE CONTENT")
    print(c("wipe = ban the account AND delete all of its jobs, threads, and comments.", DIM))
    print(c("the account row itself and existing chats are preserved.", DIM))
    print(line("·"))
    nickname = ask("nickname to wipe> ")
    if yes_no(f"wipe {nickname} (ban + delete all their jobs/threads/comments)? [yes/no]> "):
        show_result(client.request({"action": "wipe_user", "nickname": nickname}))
    else:
        print(c("operation cancelled.", YELLOW))
    pause()


def view_thread(client: RemoteClient, thread_id: int) -> None:
    while True:
        response = client.request({"action": "thread_details", "thread_id": thread_id})
        if not response.get("ok"):
            show_result(response)
            pause()
            return
        data = response["data"]
        clear()
        section("FORUM // THREAD VIEW")
        print_thread_detail(data)
        print(line("═", CYAN))
        commands = ["back"]
        if client.session_token:
            commands.append("comment")
        if data.get("is_admin"):
            commands.extend(["delete thread", "delete comment"])
        print(c("commands: " + ", ".join(commands), CYAN))
        choice = choose("thread@view> ", {k: k for k in commands})
        if choice == "comment":
            body = ask_multiline("reply>")
            if body is None:
                print(c("reply cancelled.", YELLOW))
                pause()
                continue
            if body == "":
                pause()
                continue
            pow_fields = maybe_pow(client, "post_comment")
            if pow_fields is None:
                pause()
                continue
            show_result(client.request({"action": "post_comment", "thread_id": thread_id, "body": body, **pow_fields}))
            pause()
        elif choice == "delete thread":
            if yes_no(f"delete thread #{thread_id} permanently? [yes/no]> "):
                resp = client.request({"action": "delete_thread", "thread_id": thread_id})
                show_result(resp)
                pause()
                if resp.get("ok"):
                    return
        elif choice == "delete comment":
            comment_id = ask_int("comment id to delete> ")
            show_result(client.request({"action": "delete_comment", "comment_id": comment_id}))
            pause()
        else:
            return


def forum_search_menu(client: RemoteClient) -> None:
    clear()
    section("FORUM // SEARCH THREADS")
    print(c("search query (at least 3 characters)", DIM))
    query = ask("search query> ")
    page = 1
    while True:
        resp = client.request({"action": "search_threads", "query": query, "page": page})
        if not resp.get("ok"):
            show_result(resp)
            pause()
            return
        data = resp["data"]
        clear()
        section("FORUM // SEARCH RESULTS")
        print_threads(data.get("threads", []), heading=f"results for: {query}")
        pg = data.get("pagination")
        page = pg.get("page", page) if pg else page
        page_status(pg)
        cmds = nav_choices(pg, extra=["view"])
        print(c("commands: " + ", ".join(cmds), CYAN))
        choice = choose("search@node> ", cmds)
        new_page = apply_nav(choice, page, pg)
        if new_page is not None:
            page = new_page
        elif choice == "view":
            view_thread(client, ask_int("thread id> "))
        else:
            return


def forum_menu(client: RemoteClient) -> None:
    page = 1
    while True:
        clear()
        section("FORUM // COMMUNITY BOARD", "text-only threads — no emoji, no images")
        response = client.request({"action": "list_threads", "page": page})
        if not response.get("ok"):
            show_result(response)
            pause()
            return
        data = response["data"]
        print_threads(data.get("threads", []))
        pg = data.get("pagination")
        page = pg.get("page", page) if pg else page
        page_status(pg)
        cmds = nav_choices(pg, extra=["view", "create", "search"])
        print(c("commands: " + ", ".join(cmds), CYAN))
        choice = choose("forum@node> ", cmds)
        new_page = apply_nav(choice, page, pg)
        if new_page is not None:
            page = new_page
            continue
        if choice == "view":
            thread_id = ask_int("thread id> ")
            view_thread(client, thread_id)
        elif choice == "create":
            clear()
            section("FORUM // NEW THREAD")
            print(c("forbidden characters in text: ' \" \\ / % +", DIM))
            print(line("·"))
            title = ask("title> ")
            body = ask_multiline("body>")
            if body is None:
                print(c("thread cancelled.", YELLOW))
                pause()
                continue
            if body == "":
                pause()
                continue
            pow_fields = maybe_pow(client, "create_thread")
            if pow_fields is None:
                pause()
                continue
            resp = client.request({"action": "create_thread", "title": title, "body": body, **pow_fields})
            show_result(resp)
            if resp.get("ok") and resp.get("data"):
                key_value("Thread", str(resp["data"].get("thread_id")), GREEN)
            pause()
        elif choice == "search":
            forum_search_menu(client)
        else:
            return


def invites_menu(client: RemoteClient) -> None:
    while True:
        clear()
        section("INVITES // VOUCH FOR NEW MEMBERS", "each invite ties a new account to you")
        resp = client.request({"action": "list_invites"})
        if not resp.get("ok"):
            show_result(resp)
            pause()
            return
        invites = resp["data"].get("invites", [])
        if not invites:
            print(c("you have no invites yet.", YELLOW))
        for inv in invites:
            print(c(f"  [#{inv['id']:04d}] ", MAGENTA) + c(inv["state"], WHITE) + c(f"  created {fmt_ts(inv.get('created_at'))}", DIM))
        print(line())
        print(c("commands: create, revoke, back", CYAN))
        choice = choose("invites@node> ", {"create": "create", "revoke": "revoke", "back": "back"})
        if choice == "create":
            resp = client.request({"action": "create_invite"})
            show_result(resp)
            if resp.get("ok") and resp.get("data", {}).get("invite_code"):
                print(c("[ INVITE CODE // SHOWN ONCE — STORE SECURELY ]", YELLOW + BOLD))
                print(c(str(resp["data"]["invite_code"]), MAGENTA + BOLD))
            pause()
        elif choice == "revoke":
            invite_id = ask_int("invite id to revoke> ")
            show_result(client.request({"action": "revoke_invite", "invite_id": invite_id}))
            pause()
        else:
            return


def admin_menu(client: RemoteClient) -> None:
    while True:
        clear()
        section("ADMIN CONSOLE // MODERATION GRID")
        resp = client.request({"action": "admin_get_settings"})
        if resp.get("ok"):
            s = resp["data"]
            key_value("Registration mode", str(s.get("registration_mode")), CYAN)
            key_value("Approval lock", "ON" if s.get("approval_required") else "off",
                      YELLOW if s.get("approval_required") else WHITE)
            key_value("Reg cap / hour", str(s.get("registration_max_per_hour")), DIM)
        print(line("·"))
        cmds = {
            "mode": "mode", "lock": "lock", "pending": "pending",
            "approve": "approve", "reject": "reject", "rep": "rep",
            "flags": "flags", "resolve flag": "resolve flag",
            "frozen": "frozen", "resolve rating": "resolve rating",
            "ban": "ban", "wipe": "wipe", "back": "back",
        }
        print(c("commands: mode, lock, pending, approve, reject, rep, flags, resolve flag, frozen, resolve rating, ban, wipe, back", CYAN))
        choice = choose("admin@node> ", cmds)
        if choice == "mode":
            mode = choose("registration mode [open/invite/closed]> ",
                          {"open": "open", "invite": "invite", "closed": "closed"})
            show_result(client.request({"action": "admin_set_registration_mode", "mode": mode}))
            pause()
        elif choice == "lock":
            enabled = yes_no("require manual admin approval for ALL new accounts? [yes/no]> ")
            show_result(client.request({"action": "admin_set_approval_lock", "enabled": enabled}))
            pause()
        elif choice == "pending":
            r = client.request({"action": "admin_list_pending"})
            if r.get("ok"):
                pend = r["data"].get("pending", [])
                if not pend:
                    print(c("no accounts awaiting approval.", YELLOW))
                for u in pend:
                    inviter = f"  invited by {u['invited_by']}" if u.get("invited_by") else ""
                    print(c(f"  {u['nickname']}", WHITE + BOLD) + c(f"  registered {fmt_ts(u.get('created_at'))}{inviter}", DIM))
            else:
                show_result(r)
            pause()
        elif choice == "approve":
            nickname = ask("nickname to approve> ")
            show_result(client.request({"action": "admin_approve_user", "nickname": nickname}))
            pause()
        elif choice == "reject":
            nickname = ask("nickname to reject> ")
            show_result(client.request({"action": "admin_reject_user", "nickname": nickname}))
            pause()
        elif choice == "rep":
            nickname = ask("nickname> ")
            raw = ask("reputation delta (e.g. 5 or -3.5)> ")
            try:
                delta = float(raw)
            except ValueError:
                print(c("invalid number.", RED))
                pause()
                continue
            show_result(client.request({"action": "admin_rep", "nickname": nickname, "delta": delta}))
            pause()
        elif choice == "flags":
            include = yes_no("include resolved flags? [yes/no]> ")
            r = client.request({"action": "admin_list_flags", "include_resolved": include})
            if r.get("ok"):
                flags = r["data"].get("flags", [])
                if not flags:
                    print(c("no moderation flags.", YELLOW))
                for f in flags:
                    tag = c("[resolved]", DIM) if f.get("resolved") else c("[open]", YELLOW)
                    who = f.get("nickname") or (f"user {f['user_id']}" if f.get("user_id") else "?")
                    print(c(f"  #{f['id']:04d} ", MAGENTA) + tag + c(f" {f['kind']} ", RED) + c(str(who), WHITE))
                    print(c("     " + str(f.get("detail") or ""), DIM))
            else:
                show_result(r)
            pause()
        elif choice == "resolve flag":
            flag_id = ask_int("flag id to resolve> ")
            show_result(client.request({"action": "admin_resolve_flag", "flag_id": flag_id}))
            pause()
        elif choice == "frozen":
            r = client.request({"action": "admin_list_frozen_ratings"})
            if r.get("ok"):
                frozen = r["data"].get("frozen_ratings", [])
                if not frozen:
                    print(c("no frozen ratings.", YELLOW))
                for fr in frozen:
                    print(c(f"  {fr['rater']} -> {fr['target']} ", WHITE)
                          + c(f"(job {fr['job_id']}, value {fr['rating_value']})", DIM)
                          + c(f"  rater_id={fr['rater_id']} target_id={fr['target_id']}", DIM))
            else:
                show_result(r)
            pause()
        elif choice == "resolve rating":
            rater_id = ask_int("rater_id> ")
            target_id = ask_int("target_id> ")
            job_id = ask_int("job_id> ")
            apply_it = yes_no("apply the rating? [yes = apply / no = discard]> ")
            show_result(client.request({
                "action": "admin_resolve_rating",
                "rater_id": rater_id, "target_id": target_id, "job_id": job_id, "apply": apply_it,
            }))
            pause()
        elif choice == "ban":
            ban_user_menu(client)
        elif choice == "wipe":
            wipe_user_menu(client)
        else:
            return


def main_menu(client: RemoteClient) -> None:
    choices = {
        "open jobs": "open jobs",
        "open": "open jobs",
        "done jobs": "done jobs",
        "done": "done jobs",
        "cancelled jobs": "cancelled jobs",
        "cancelled": "cancelled jobs",
        "create job": "create job",
        "create": "create job",
        "job details": "job details",
        "details": "job details",
        "my authored jobs": "my authored jobs",
        "my jobs": "my authored jobs",
        "my accepted": "my accepted",
        "accepted": "my accepted",
        "profile": "profile",
        "rate": "rate",
        "blocks": "blocks",
        "chats": "chats",
        "forum": "forum",
        "invites": "invites",
        "admin": "admin",
        "logout": "logout",
        "quit": "quit",
        "exit": "quit",
    }
    while True:
        clear()
        section("MAIN GRID // OPERATOR CONSOLE")
        operator_label = (client.nickname or "unknown") + (" [admin]" if client.is_admin else "")
        key_value("Operator", operator_label, GREEN)
        print(c("commands: open jobs, done jobs, cancelled jobs, create job, job details, my authored jobs, my accepted, profile, rate, blocks, chats, forum, invites" + (", admin" if client.is_admin else "") + ", logout, quit", CYAN))
        print(line("·"))
        choice = choose("afterlife@node> ", choices)
        if choice == "open jobs":
            list_jobs_menu(client, status="open")
        elif choice == "done jobs":
            list_jobs_menu(client, status="done", completed_mode=True)
        elif choice == "cancelled jobs":
            list_jobs_menu(client, status="cancelled", completed_mode=True)
        elif choice == "create job":
            create_job_menu(client)
        elif choice == "job details":
            job_details_menu(client)
        elif choice == "my authored jobs":
            my_jobs_menu(client)
        elif choice == "my accepted":
            my_accepts_menu(client)
        elif choice == "profile":
            view_profile(client)
        elif choice == "rate":
            rate_user_menu(client)
        elif choice == "blocks":
            blocks_menu(client)
        elif choice == "chats":
            chats_menu(client)
        elif choice == "forum":
            forum_menu(client)
        elif choice == "invites":
            invites_menu(client)
        elif choice == "admin":
            if client.is_admin:
                admin_menu(client)
            else:
                print(c("admin only option.", RED))
                pause()
        elif choice == "logout":
            show_result(client.request({"action": "logout"}))
            client.session_token = None
            client.nickname = None
            client.is_admin = False
            pause()
            return
        else:
            raise SystemExit(0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AFTERLIFE client – Tor hidden service terminal interface. Run with proxychains.")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Server host/IP (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Server port (default: {DEFAULT_PORT})")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    client = connect_prompt(args)
    while True:
        auth_menu(client)
        main_menu(client)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c("\n[ session interrupted ]", RED))
