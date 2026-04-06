#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import json
import os
import socket
import ssl
import sys
import textwrap
import time
from dataclasses import dataclass
from typing import Any, Optional

# =========================
# Configuration
# =========================
DEFAULT_HOST = os.environ.get("AFTERLIFE", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("AFTERLIFE", "5050"))
SOCKET_TIMEOUT = 25
WRAP_WIDTH = 78

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


def c(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"


def hr(char: str = "═") -> str:
    return char * WRAP_WIDTH


def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def pause() -> None:
    input(c("\nPress enter to continue... ", DIM))


def wrap(text: str) -> str:
    return "\n".join(textwrap.wrap(text, WRAP_WIDTH)) if text else ""


def banner() -> str:
    return (
        c(hr(), DIM)
        + "\n"
        + c("AFTERLIFE SPACE CLIENT", MAGENTA)
        + "\n"
        + c("Secure terminal uplink", DIM)
        + "\n"
        + c(hr(), DIM)
    )


@dataclass
class RemoteClient:
    host: str
    port: int
    ssl_context: ssl.SSLContext
    server_hostname: str
    session_token: Optional[str] = None
    nickname: Optional[str] = None

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
        if not chunks:
            raise RuntimeError("No response from server.")
        return json.loads(chunks.decode("utf-8").strip())

    def ping(self) -> bool:
        response = self.request({"action": "ping"})
        return bool(response.get("ok"))


# =========================
# Input helpers
# =========================

def ask(prompt: str, allow_blank: bool = False) -> str:
    while True:
        value = input(prompt).strip()
        if value or allow_blank:
            return value
        print(c("Value required.", RED))


def ask_hidden(prompt: str) -> str:
    while True:
        value = getpass.getpass(prompt).strip()
        if value:
            return value
        print(c("Value required.", RED))


def ask_int(prompt: str) -> int:
    while True:
        raw = input(prompt).strip()
        try:
            return int(raw)
        except ValueError:
            print(c("Enter a valid number.", RED))


def yes_no(prompt: str) -> bool:
    while True:
        value = input(prompt).strip().lower()
        if value in {"y", "yes"}:
            return True
        if value in {"n", "no"}:
            return False
        print(c("Answer with yes or no.", RED))


def normalize_choice(value: str) -> str:
    return value.strip().lower().replace("_", " ").replace("-", " ")


def choose(prompt: str, mapping: dict[str, str]) -> str:
    normalized = {normalize_choice(k): v for k, v in mapping.items()}
    while True:
        value = normalize_choice(input(prompt))
        if value in normalized:
            return normalized[value]
        print(c("Unknown option.", RED))


def show_result(response: dict[str, Any]) -> None:
    if response.get("ok"):
        print(c(response.get("message", "OK"), GREEN))
    else:
        message = response.get("message", "Request failed.")
        retry_after = response.get("retry_after")
        if retry_after:
            message = f"{message} Retry after {retry_after}s."
        print(c(message, RED))


# =========================
# Views
# =========================

def print_jobs(jobs: list[dict[str, Any]], include_author: bool = True, completed_mode: bool = False) -> None:
    if not jobs:
        print(c("No jobs found.", YELLOW))
        return
    print(c(hr("─"), DIM))
    for job in jobs:
        lock_mark = "[PRIVATE] " if job.get("is_private") else ""
        status = str(job.get("status", "open")).upper()
        print(c(f"#{job['id']} {lock_mark}{job['title']}", CYAN))
        if not completed_mode:
            print(f"  Reward : {job['reward']}")
            print(f"  Status : {status}")
            print(f"  Accepts: {job.get('accept_count', 0)}")
            if include_author and job.get("author_nickname"):
                print(f"  Author : {job['author_nickname']}")
        else:
            print(f"  Status : {status}")
        print(c(hr("─"), DIM))


def print_job_details(data: dict[str, Any]) -> None:
    print(c(hr(), DIM))
    print(c(f"JOB #{data['id']} // {data['title']}", MAGENTA))
    print(c(hr(), DIM))
    print(f"Reward : {data['reward']}")
    print(f"Status : {str(data['status']).upper()}")
    print(f"Author : {data['author_nickname']}")
    print(f"Private: {'yes' if data['is_private'] else 'no'}")
    print(f"Accepts: {data.get('accept_count', 0)}")
    print()
    if data.get("description_visible"):
        print(c("DESCRIPTION", CYAN))
        print(wrap(data.get("description") or ""))
    else:
        print(c("DESCRIPTION LOCKED", YELLOW))
        print("Use the private token to unlock this job description.")
    print()
    workers = data.get("worker_pool")
    if workers is not None:
        print(c("WORKER POOL", CYAN))
        if workers:
            for worker in workers:
                marker = " *selected" if data.get("selected_worker_id") == worker["id"] else ""
                print(f"  [{worker['id']}] {worker['nickname']} (rep {worker['reputation']}){marker}")
        else:
            print("  No workers yet.")


def build_ssl_context(cert_path: str) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=cert_path)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def connect_prompt(args: argparse.Namespace) -> RemoteClient:
    clear()
    print(banner())
    print(c(f"Trusted certificate: {args.cert}", DIM))
    host = ask(f"Server IP or hostname [{args.host}]: ", allow_blank=True) or args.host
    port_raw = ask(f"Server port [{args.port}]: ", allow_blank=True) or str(args.port)
    try:
        port = int(port_raw)
    except ValueError:
        port = args.port
    server_name = args.server_name or host
    client = RemoteClient(
        host=host,
        port=port,
        ssl_context=build_ssl_context(args.cert),
        server_hostname=server_name,
    )
    try:
        if client.ping():
            print(c("Secure connection established.", GREEN))
        else:
            print(c("Server responded unexpectedly.", RED))
    except ssl.SSLError as exc:
        print(c(f"TLS handshake failed: {exc}", RED))
        sys.exit(1)
    except Exception as exc:
        print(c(f"Connection failed: {exc}", RED))
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
        print(banner())
        print(c("Available actions: login, register, quit", CYAN))
        choice = choose("Action> ", choices)
        if choice == "login":
            nickname = ask("Nickname> ")
            password = ask_hidden("Password> ")
            response = client.request({"action": "login", "nickname": nickname, "password": password})
            show_result(response)
            if response.get("ok"):
                data = response.get("data", {})
                client.session_token = data.get("session_token")
                client.nickname = data.get("nickname")
                time.sleep(0.6)
            else:
                pause()
        elif choice == "register":
            nickname = ask("New nickname> ")
            password = ask_hidden("New password> ")
            response = client.request({"action": "register", "nickname": nickname, "password": password})
            show_result(response)
            pause()
        elif choice == "quit":
            raise SystemExit(0)


def view_profile(client: RemoteClient) -> None:
    clear()
    print(banner())
    response = client.request({"action": "profile"})
    if not response.get("ok"):
        show_result(response)
        pause()
        return
    data = response["data"]
    print(c("PROFILE", CYAN))
    print(c(hr("─"), DIM))
    print(f"Nickname  : {data['nickname']}")
    print(f"Reputation: {data['reputation']}")
    print(c(hr("─"), DIM))
    pause()


def list_jobs_menu(client: RemoteClient, status: Optional[str] = None, completed_mode: bool = False) -> None:
    clear()
    print(banner())
    print(c(f"JOB BOARD // {status.upper() if status else 'ALL'}", CYAN))
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
    print(banner())
    print(c("CREATE JOB", CYAN))
    print(c("Forbidden characters in text fields: ' \" \\ / %", DIM))
    title = ask("Title> ")
    description = ask("Description> ")
    reward = ask("Reward> ")
    is_private = yes_no("Private job? [yes/no]> ")
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
        print(c(f"Job id: {data.get('job_id')}", GREEN))
        if data.get("private_token"):
            print(c("Private token (save it carefully):", YELLOW))
            print(c(data["private_token"], MAGENTA))
    pause()


def job_details_menu(client: RemoteClient) -> None:
    clear()
    print(banner())
    job_id = ask_int("Job id> ")
    unlock_token = ask("Unlock token (blank if none)> ", allow_blank=True)
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
        print(banner())
        print_job_details(data)
        print(c(hr(), DIM))
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
        print(c("Available actions: " + ", ".join(visible_actions), CYAN))
        choice = choose("Action> ", actions)
        if choice == "accept":
            resp = client.request({"action": "accept_job", "job_id": data["id"]})
            show_result(resp)
            pause()
        elif choice == "withdraw":
            resp = client.request({"action": "withdraw_job", "job_id": data["id"]})
            show_result(resp)
            pause()
        elif choice == "select worker" and (data.get("is_author") or data.get("is_admin")):
            worker_id = ask_int("Worker id> ")
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
    print(banner())
    response = client.request({"action": "my_jobs"})
    if not response.get("ok"):
        show_result(response)
        pause()
        return
    print(c("MY AUTHORED JOBS", CYAN))
    print_jobs(response["data"]["jobs"], include_author=False)
    pause()


def my_accepts_menu(client: RemoteClient) -> None:
    clear()
    print(banner())
    response = client.request({"action": "my_accepts"})
    if not response.get("ok"):
        show_result(response)
        pause()
        return
    print(c("MY COMPLETED / ACCEPTED VIEW", CYAN))
    print(c("Descriptions are omitted here, including private jobs.", DIM))
    print_jobs(response["data"]["jobs"], completed_mode=True)
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
        "logout": "logout",
        "quit": "quit",
        "exit": "quit",
    }
    while True:
        clear()
        print(banner())
        print(c(f"Operator: {client.nickname}", GREEN))
        print(c("Commands: open jobs, done jobs, cancelled jobs, create job, job details, my authored jobs, my accepted, profile, logout, quit", CYAN))
        choice = choose("Command> ", choices)
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
        elif choice == "logout":
            response = client.request({"action": "logout"})
            show_result(response)
            client.session_token = None
            client.nickname = None
            pause()
            return
        elif choice == "quit":
            raise SystemExit(0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "AFTERLIFE Space client. TLS is mandatory. Use --cert to point to the PEM certificate "
            "or CA bundle used to validate the server certificate."
        )
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Default server host/IP (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Default server port (default: {DEFAULT_PORT})")
    parser.add_argument(
        "--cert",
        required=True,
        help=(
            "Path to the trusted PEM certificate or CA bundle. The client refuses plaintext and will abort "
            "if TLS verification fails."
        ),
    )
    parser.add_argument(
        "--server-name",
        default=None,
        help="Optional TLS server name override for certificate matching/SNI when the socket target is an IP.",
    )
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
        print(c("\nSession interrupted.", RED))
