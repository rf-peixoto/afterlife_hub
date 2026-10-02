#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
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
    for item in ["initializing terminal shell...", "establishing plaintext uplink..."]:
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
def format_rep(rep: int) -> str:
    if rep < 0:
        return c(str(rep), RED + BOLD)
    if rep > 0:
        return c(f"+{rep}", GREEN)
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
        print(c(f"Your reputation: ", DIM) + format_rep(int(data["viewer_reputation"])))
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


# =========================
# Menus
# =========================
def connect_prompt(args: argparse.Namespace) -> RemoteClient:
    clear()
    section("NODE LINK // PLAIN TCP", "no encryption – use in trusted networks only")
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
            response = client.request({"action": "login", "nickname": nickname, "password": password})
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
            response = client.request({"action": "register", "nickname": nickname, "password": password})
            show_result(response)
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
    print(c("Reputation       : ", DIM) + format_rep(int(data["reputation"])))
    key_value("Role", "admin" if data.get("is_admin") else "member", CYAN)
    key_value("Created", fmt_ts(data.get("created_at")))
    print(line())
    pause()


def list_jobs_menu(client: RemoteClient, status: Optional[str] = None, completed_mode: bool = False) -> None:
    clear()
    section(f"JOB BOARD // {(status or 'all').upper()} CONTRACTS")
    response = client.request({"action": "list_jobs", "status": status})
    if not response.get("ok"):
        show_result(response)
        pause()
        return
    print_jobs(response["data"]["jobs"], completed_mode=completed_mode)
    pause()


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
    response = client.request({
        "action": "create_job",
        "title": title,
        "description": description,
        "reward": reward,
        "min_reputation": min_reputation,
        "is_private": is_private,
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
    nickname = ask("nickname> ")
    rating = choose("rating [positive/negative]> ", {"positive": "positive", "negative": "negative"})
    show_result(client.request({"action": "rate_user", "nickname": nickname, "rating": rating}))
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
        print_chats(response["data"].get("chats", []))
        print(c("commands: open, view, read, send, back", CYAN))
        choice = choose("chat@node> ", {"open": "open", "view": "view", "read": "read", "send": "send", "back": "back"})
        if choice == "open":
            nickname = ask("chat <nickname> > ")
            resp = client.request({"action": "open_chat", "nickname": nickname})
            show_result(resp)
            if resp.get("ok") and resp.get("data"):
                key_value("Chat", str(resp["data"].get("chat_id")), GREEN)
            pause()
        elif choice == "view":
            chat_id = ask_int("chat id> ")
            resp = client.request({"action": "list_messages", "chat_id": chat_id})
            if resp.get("ok"):
                clear()
                section("PRIVATE MESSAGES // CHAT VIEW")
                print_messages(resp["data"])
            else:
                show_result(resp)
            pause()
        elif choice == "read":
            message_id = ask_int("message id> ")
            resp = client.request({"action": "read_message", "message_id": message_id})
            if resp.get("ok"):
                data = resp["data"]
                clear()
                section("PRIVATE MESSAGES // SINGLE MESSAGE")
                key_value("Message id", str(data["id"]))
                key_value("Chat", str(data["chat_id"]))
                key_value("From", str(data["sender_nickname"]))
                key_value("When", fmt_ts(data.get("created_at")))
                print(line("·"))
                print(wrap(str(data.get("body") or ""), indent="  "))
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
        "ban": "ban",
        "logout": "logout",
        "quit": "quit",
        "exit": "quit",
    }
    while True:
        clear()
        section("MAIN GRID // OPERATOR CONSOLE")
        operator_label = (client.nickname or "unknown") + (" [admin]" if client.is_admin else "")
        key_value("Operator", operator_label, GREEN)
        print(c("commands: open jobs, done jobs, cancelled jobs, create job, job details, my authored jobs, my accepted, profile, rate, blocks, chats" + (", ban" if client.is_admin else "") + ", logout, quit", CYAN))
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
        elif choice == "ban":
            if client.is_admin:
                ban_user_menu(client)
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
    parser = argparse.ArgumentParser(description="AFTERLIFE client – plain TCP terminal interface.")
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
