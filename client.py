#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
import socket
import ssl
import sys
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

# =========================
# Configuration
# =========================
DEFAULT_HOST = os.environ.get("AFTERLIFE_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("AFTERLIFE_PORT", "2077"))
SOCKET_TIMEOUT = 25
MAX_RESPONSE_BYTES = int(os.environ.get("AFTERLIFE_MAX_RESPONSE_BYTES", "1048576"))
WRAP_WIDTH = 78
BOOT_DELAY = 0.18

# ANSI colors
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
YELLOW = "\033[33m"
RED = "\033[31m"
WHITE = "\033[37m"

STATUS_COLORS = {
    "OPEN": GREEN,
    "DONE": CYAN,
    "CANCELLED": RED,
}


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
    if not text:
        return ""
    width = max(20, WRAP_WIDTH - len(indent))
    return "\n".join(indent + part for part in textwrap.wrap(text, width=width))


def banner() -> str:
    inner = WRAP_WIDTH - 2
    title = "A F T E R L I F E".center(inner)
    subtitle = "private freelancer terminal".center(inner)
    return "\n".join(
        [
            c("╔" + "═" * inner + "╗", CYAN),
            c("║", CYAN) + c(title, MAGENTA + BOLD) + c("║", CYAN),
            c("║", CYAN) + c(subtitle, DIM) + c("║", CYAN),
            c("╚" + "═" * inner + "╝", CYAN),
        ]
    )


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
    color = STATUS_COLORS.get(normalized, WHITE)
    return c(f"● {normalized}", color)


def key_value(label: str, value: str, value_color: str = WHITE) -> None:
    print(c(f"{label:<10}: ", DIM) + c(str(value), value_color))


def boot_sequence() -> None:
    steps = [
        "initializing terminal shell...",
        "loading trusted certificate store...",
        "preparing tls context...",
        "establishing encrypted uplink...",
    ]
    for item in steps:
        print(c(f"> {item}", DIM))
        time.sleep(BOOT_DELAY)


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def explain_ssl_error(exc: ssl.SSLError) -> str:
    text = str(exc)

    lowered = text.lower()
    if "hostname" in lowered or "doesn't match" in lowered or "does not match" in lowered:
        return (
            f"{exc}\n"
            "certificate hostname validation failed. "
            "the certificate SAN must match the server name used by the client."
        )
    if "self-signed certificate" in lowered:
        return (
            f"{exc}\n"
            "the server presented a self-signed certificate that is not trusted by this client. "
            "use --cert with the issuing CA or the pinned server certificate."
        )
    if "unable to get local issuer certificate" in lowered or "unknown ca" in lowered:
        return (
            f"{exc}\n"
            "the client does not trust the certificate chain presented by the server. "
            "provide the correct CA bundle with --cert."
        )
    if "certificate verify failed" in lowered:
        return (
            f"{exc}\n"
            "tls verification failed. confirm that the certificate chain is trusted and "
            "that the hostname/IP matches the certificate SAN."
        )
    return text


@dataclass
class RemoteClient:
    host: str
    port: int
    ssl_context: ssl.SSLContext
    server_hostname: str
    session_token: Optional[str] = None
    nickname: Optional[str] = None
    is_admin: bool = False

    def request(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.session_token:
            payload.setdefault("session_token", self.session_token)

        raw = json.dumps(payload).encode("utf-8") + b"\n"

        with socket.create_connection((self.host, self.port), timeout=SOCKET_TIMEOUT) as tcp_sock:
            tcp_sock.settimeout(SOCKET_TIMEOUT)

            with self.ssl_context.wrap_socket(tcp_sock, server_hostname=self.server_hostname) as sock:
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
        response = self.request({"action": "ping"})
        return bool(response.get("ok"))


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


def ask_int(prompt_text: str) -> int:
    while True:
        raw = input(prompt(prompt_text)).strip()
        try:
            return int(raw)
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
# Views
# =========================

def print_jobs(jobs: list[dict[str, Any]], include_author: bool = True, completed_mode: bool = False) -> None:
    if not jobs:
        print(c("no contracts found.", YELLOW))
        return

    for job in jobs:
        lock_mark = c("[PRIVATE] ", YELLOW) if job.get("is_private") else ""
        status = str(job.get("status", "open")).upper()
        print(c(f"[ CONTRACT #{int(job['id']):04d} ]", CYAN + BOLD))
        print(lock_mark + c(str(job["title"]), WHITE + BOLD))
        key_value("Reward", str(job["reward"]))
        key_value("Status", status_badge(status))
        if not completed_mode:
            key_value("Accepts", str(job.get("accept_count", 0)))
            if include_author and job.get("author_display"):
                author_text = str(job["author_display"])
                author_color = YELLOW if job.get("author_is_banned") else WHITE
                key_value("Author", author_text, author_color)
        print(line())


def print_job_details(data: dict[str, Any]) -> None:
    print(c(f"[ CONTRACT #{int(data['id']):04d} // SECURE VIEW ]", MAGENTA + BOLD))
    print(line("═", CYAN))
    print(c(str(data["title"]), WHITE + BOLD))
    print(line("·"))
    key_value("Reward", str(data["reward"]))
    key_value("Status", status_badge(str(data["status"])))
    author_value = str(data.get("author_display") or data["author_nickname"])
    author_color = YELLOW if data.get("author_is_banned") else WHITE
    key_value("Author", author_value, author_color)
    key_value("Private", "yes" if data["is_private"] else "no", YELLOW if data["is_private"] else WHITE)
    key_value("Accepts", str(data.get("accept_count", 0)))
    print()

    if data.get("description_visible"):
        print(c("[ DESCRIPTION // DECRYPTED ]", CYAN))
        print(wrap(data.get("description") or "", indent="  "))
    else:
        print(c("[ DESCRIPTION // LOCKED ]", YELLOW + BOLD))
        print(c("  use the private token to unlock this contract description.", DIM))

    print()
    workers = data.get("worker_pool")
    if workers is not None:
        print(c("[ WORKER POOL ]", CYAN))
        if workers:
            for worker in workers:
                marker = c("  << SELECTED >>", GREEN) if data.get("selected_worker_id") == worker["id"] else ""
                worker_name = f"[banned] {worker["nickname"]}" if worker.get("is_banned") else worker["nickname"]
                worker_color = YELLOW if worker.get("is_banned") else WHITE
                print(
                    c(f"  [{worker['id']}] ", MAGENTA)
                    + c(worker_name, worker_color)
                    + c(f"  rep={worker['reputation']}", DIM)
                    + marker
                )
                print(c("      contact: ", DIM) + c(str(worker.get("contact_info", "")), CYAN))
        else:
            print(c("  no workers assigned yet.", DIM))


def build_ssl_context(cert_path: str | None = None, insecure: bool = False) -> ssl.SSLContext:
    """
    Secure mode:
      - certificate verification required
      - hostname verification required

    Insecure mode:
      - certificate verification disabled
      - hostname verification disabled
      - testing only
    """
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True

    if cert_path:
        context.load_verify_locations(cafile=cert_path)

    return context


def validate_args(args: argparse.Namespace) -> None:
    if not args.insecure:
        if not args.cert:
            raise SystemExit("secure mode requires --cert pointing to a trusted PEM CA bundle or pinned server certificate")
        cert_file = Path(args.cert)
        if not cert_file.is_file():
            raise SystemExit(f"trusted PEM file not found: {args.cert}")

    if args.port < 1 or args.port > 65535:
        raise SystemExit("port must be between 1 and 65535")


def connect_prompt(args: argparse.Namespace) -> RemoteClient:
    clear()
    subtitle = "tls verification enabled" if not args.insecure else "WARNING: insecure testing mode"
    section("NODE LINK // TLS REQUIRED", subtitle)

    key_value("Trust PEM", args.cert if args.cert else "(system/default)", CYAN)
    if args.server_name:
        key_value("TLS Name", args.server_name, CYAN)
    print()

    if args.insecure:
        print(c("[ WARNING ] --insecure disables certificate and hostname verification. testing only.", YELLOW + BOLD))
        print(line("·"))

    boot_sequence()
    print(line("·"))

    host = ask(f"uplink host [{args.host}]> ", allow_blank=True) or args.host
    port_raw = ask(f"uplink port [{args.port}]> ", allow_blank=True) or str(args.port)

    try:
        port = int(port_raw)
    except ValueError:
        port = args.port

    server_name = args.server_name or host

    if not args.insecure and is_ip_address(host) and not args.server_name:
        print(c(
            "[ NOTICE ] you are connecting to a raw IP without --server-name.\n"
            "production certificates often validate against a DNS name. this only works if the certificate SAN includes that IP.",
            YELLOW,
        ))
        print(line("·"))

    client = RemoteClient(
        host=host,
        port=port,
        ssl_context=build_ssl_context(args.cert, insecure=args.insecure),
        server_hostname=server_name,
    )

    try:
        if client.ping():
            print(c("[ LINK UP ] encrypted session established.", GREEN))
            key_value("Remote", f"{host}:{port}", CYAN)
            key_value("TLS peer", server_name, CYAN)
        else:
            print(c("[ LINK ERROR ] server responded unexpectedly.", RED))
    except ssl.SSLCertVerificationError as exc:
        print(c("[ TLS FAILURE ] certificate verification error", RED + BOLD))
        print(c(wrap(explain_ssl_error(exc)), RED))
        sys.exit(1)
    except ssl.SSLError as exc:
        print(c("[ TLS FAILURE ] ssl error", RED + BOLD))
        print(c(wrap(explain_ssl_error(exc)), RED))
        sys.exit(1)
    except Exception as exc:
        print(c(f"[ CONNECTION FAILURE ] {exc}", RED))
        sys.exit(1)

    time.sleep(0.5)
    return client


def auth_menu(client: RemoteClient) -> None:
    choices = {
        "login": "login",
        "register": "register",
        "quit": "quit",
        "exit": "quit",
    }
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
                time.sleep(0.6)
            else:
                pause()
        elif choice == "register":
            nickname = ask("new nickname> ")
            password = ask_hidden("new password> ")
            contact_info = ask("contact info> ")
            response = client.request(
                {
                    "action": "register",
                    "nickname": nickname,
                    "password": password,
                    "contact_info": contact_info,
                }
            )
            show_result(response)
            pause()
        elif choice == "quit":
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
    nickname = data["nickname"]
    if data.get("is_banned"):
        nickname = f"[banned] {nickname}"
    key_value("Nickname", nickname, YELLOW if data.get("is_banned") else WHITE + BOLD)
    key_value("Contact", data.get("contact_info", ""), CYAN)
    key_value("Reputation", str(data["reputation"]), CYAN)
    key_value("Role", "admin" if data.get("is_admin") else "member", CYAN)
    print(line())
    pause()


def list_jobs_menu(client: RemoteClient, status: Optional[str] = None, completed_mode: bool = False) -> None:
    clear()
    status_title = status.upper() if status else "ALL"
    section(f"JOB BOARD // {status_title} CONTRACTS")
    response = client.request({"action": "list_jobs", "status": status})
    if not response.get("ok"):
        show_result(response)
        pause()
        return
    jobs = response["data"]["jobs"]
    print_jobs(jobs, completed_mode=completed_mode)
    pause()


def create_job_menu(client: RemoteClient) -> None:
    clear()
    section("CREATE CONTRACT // BROADCAST")
    print(c("forbidden characters in text fields: ' \" \\ / %", DIM))
    print(line("·"))
    title = ask("title> ")
    description = ask("description> ")
    reward = ask("reward> ")
    is_private = yes_no("private contract? [yes/no]> ")
    response = client.request(
        {
            "action": "create_job",
            "title": title,
            "description": description,
            "reward": reward,
            "is_private": is_private,
        }
    )
    show_result(response)
    if response.get("ok"):
        data = response.get("data", {})
        key_value("Contract", str(data.get("job_id")), GREEN)
        if data.get("private_token"):
            print(c("[ PRIVATE TOKEN // STORE SECURELY ]", YELLOW + BOLD))
            print(c(data["private_token"], MAGENTA))
    pause()


def job_details_menu(client: RemoteClient) -> None:
    clear()
    section("CONTRACT DETAILS // SECURE VIEW")
    job_id = ask_int("contract id> ")
    unlock_token = ask("unlock token [blank if none]> ", allow_blank=True)
    response = client.request(
        {
            "action": "job_details",
            "job_id": job_id,
            **({"unlock_token": unlock_token} if unlock_token else {}),
        }
    )
    if not response.get("ok"):
        show_result(response)
        pause()
        return

    data = response["data"]
    while True:
        clear()
        section("CONTRACT DETAILS // LIVE VIEW", "available actions depend on your role")
        print_job_details(data)
        print(line("═", CYAN))
        actions = {
            "accept": "accept",
            "withdraw": "withdraw",
            "back": "back",
        }
        visible_actions = ["accept", "withdraw", "back"]
        if data.get("is_author") or data.get("is_admin"):
            actions.update(
                {
                    "select worker": "select worker",
                    "done": "done",
                    "cancelled": "cancelled",
                    "reopen": "reopen",
                }
            )
            visible_actions = ["accept", "withdraw", "select worker", "done", "cancelled", "reopen", "back"]
        if data.get("is_admin"):
            actions.update({"delete": "delete"})
            visible_actions.insert(-1, "delete")
        print(c("commands: " + ", ".join(visible_actions), CYAN))
        choice = choose("contract@view> ", actions)
        if choice == "accept":
            resp = client.request({"action": "accept_job", "job_id": data["id"]})
            show_result(resp)
            pause()
        elif choice == "withdraw":
            resp = client.request({"action": "withdraw_job", "job_id": data["id"]})
            show_result(resp)
            pause()
        elif choice == "select worker" and (data.get("is_author") or data.get("is_admin")):
            worker_id = ask_int("worker id> ")
            resp = client.request({"action": "select_worker", "job_id": data["id"], "worker_id": worker_id})
            show_result(resp)
            pause()
        elif choice == "done" and (data.get("is_author") or data.get("is_admin")):
            resp = client.request({"action": "set_status", "job_id": data["id"], "status": "done"})
            show_result(resp)
            pause()
        elif choice == "cancelled" and (data.get("is_author") or data.get("is_admin")):
            resp = client.request({"action": "set_status", "job_id": data["id"], "status": "cancelled"})
            show_result(resp)
            pause()
        elif choice == "reopen" and (data.get("is_author") or data.get("is_admin")):
            resp = client.request({"action": "set_status", "job_id": data["id"], "status": "open"})
            show_result(resp)
            pause()
        elif choice == "delete" and data.get("is_admin"):
            if yes_no(f"delete contract #{data['id']} permanently? [yes/no]> "):
                resp = client.request({"action": "delete_job", "job_id": data["id"]})
                show_result(resp)
                pause()
                if resp.get("ok"):
                    return
            else:
                print(c("operation cancelled.", YELLOW))
                pause()
        elif choice == "back":
            return

        refresh = client.request(
            {
                "action": "job_details",
                "job_id": data["id"],
                **({"unlock_token": unlock_token} if unlock_token else {}),
            }
        )
        if not refresh.get("ok"):
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
    section("MY CONTRACTS // ACCEPTED + COMPLETED", "descriptions remain omitted here, including private contracts")
    response = client.request({"action": "my_accepts"})
    if not response.get("ok"):
        show_result(response)
        pause()
        return
    print_jobs(response["data"]["jobs"], completed_mode=True)
    pause()



def ban_user_menu(client: RemoteClient) -> None:
    clear()
    section("ADMIN BAN // PERMANENT ACTION")
    print(c("this permanently bans a member account. input must match the exact nickname.", YELLOW))
    print(line("·"))
    nickname = ask("nickname to ban> ")
    confirm = yes_no(f"ban {nickname} permanently? [yes/no]> ")
    if not confirm:
        print(c("operation cancelled.", YELLOW))
        pause()
        return
    response = client.request({"action": "ban_user", "nickname": nickname})
    show_result(response)
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
        commands = (
            "commands: open jobs, done jobs, cancelled jobs, create job, job details, "
            "my authored jobs, my accepted, profile"
        )
        if client.is_admin:
            commands += ", ban"
        commands += ", logout, quit"
        print(c(commands, CYAN))
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
        elif choice == "ban":
            if client.is_admin:
                ban_user_menu(client)
            else:
                print(c("admin only option.", RED))
                pause()
        elif choice == "logout":
            response = client.request({"action": "logout"})
            show_result(response)
            client.session_token = None
            client.nickname = None
            client.is_admin = False
            pause()
            return
        elif choice == "quit":
            raise SystemExit(0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "AFTERLIFE client terminal. TLS is mandatory for production. "
            "Use --cert to point to the trusted PEM CA bundle or pinned server certificate. "
            "--insecure disables certificate and hostname verification and must only be used for testing."
        )
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Default server host/IP (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Default server port (default: {DEFAULT_PORT})")
    parser.add_argument(
        "--cert",
        default=None,
        help=(
            "Path to the trusted PEM CA bundle or pinned server certificate. "
            "Required in secure mode."
        ),
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate and hostname verification (testing only).",
    )
    parser.add_argument(
        "--server-name",
        default=None,
        help=(
            "Optional TLS server name override for certificate matching/SNI. "
            "Useful when connecting to a raw IP but validating a DNS certificate."
        ),
    )
    args = parser.parse_args()
    validate_args(args)
    return args


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