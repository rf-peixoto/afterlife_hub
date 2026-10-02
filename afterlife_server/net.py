"""Asyncio network front-end.

* Thousands of idle sockets cost almost nothing, and every request must be
  complete within REQUEST_DEADLINE seconds in total (not per recv), so slowloris
  connections are dropped instead of pinning worker threads.
* With `HiddenServiceExportCircuitID haproxy`, tor prefixes every stream with a
  PROXY v1 line whose source address encodes the Tor circuit's global id. All
  per-client limits are keyed on that id.
* Blocking work (SQLite, scrypt, PBKDF2) runs in a bounded thread pool; when the
  admission queue is full new work is shed immediately instead of queueing.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import signal
import socket
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Optional

from . import config as C
from .db import Database
from .handlers import Ctx, err, handle_request
from .security import circuit_limiter
from .util import audit_log, log, parse_request_json

TOR_CIRCUIT_NET = ipaddress.IPv6Network("fc00:dead:beef:4dad::/64")


class ProxyHeaderError(Exception):
    pass


def parse_proxy_v1(line: bytes) -> str:
    """'PROXY TCP6 fc00:dead:beef:4dad::ffff:ffff ::1 65535 42\\r\\n' -> 'circ:<id>'."""
    if len(line) > 108 or not line.endswith(b"\r\n"):
        raise ProxyHeaderError("malformed PROXY header")
    parts = line[:-2].decode("ascii", "strict").split(" ")
    if len(parts) != 6 or parts[0] != "PROXY" or parts[1] != "TCP6":
        raise ProxyHeaderError("unexpected PROXY header")
    try:
        src = ipaddress.IPv6Address(parts[2])
    except ValueError:
        raise ProxyHeaderError("bad PROXY source")
    if src not in TOR_CIRCUIT_NET:
        raise ProxyHeaderError("PROXY source is not a tor circuit id")
    return f"circ:{int(src) & 0xFFFFFFFF}"


class Server:
    def __init__(self, db: Database) -> None:
        self.db = db
        self.executor = ThreadPoolExecutor(max_workers=C.MAX_WORKERS, thread_name_prefix="afterlife")
        self.active = 0
        self.per_circuit: dict[str, int] = defaultdict(int)
        self.queued = 0
        self.stopping = asyncio.Event()

    def _send(self, writer: asyncio.StreamWriter, payload: dict[str, Any]) -> None:
        try:
            writer.write(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")
        except (ConnectionError, RuntimeError):
            pass

    async def _close(self, writer: asyncio.StreamWriter) -> None:
        try:
            await asyncio.wait_for(writer.drain(), timeout=10)
        except Exception:
            pass
        try:
            writer.close()
        except Exception:
            pass

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self.active >= C.MAX_CONNECTIONS:
            self._send(writer, err("Server busy.", "server_busy", 5))
            await self._close(writer)
            return
        self.active += 1
        circuit = ""
        counted = False
        loop = asyncio.get_running_loop()
        deadline = loop.time() + C.REQUEST_DEADLINE_SECONDS
        try:
            try:
                # 1) circuit identity first (tor sends it immediately), so the
                #    per-circuit connection cap applies even to idle sockets.
                first = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=C.PROXY_HEADER_DEADLINE_SECONDS)
                if first.startswith(b"PROXY "):
                    circuit = parse_proxy_v1(first)
                    first = b""
                elif C.REQUIRE_PROXY_HEADER:
                    raise ProxyHeaderError("PROXY header required")
                if not circuit:
                    peer = writer.get_extra_info("peername")
                    circuit = f"local:{peer[0] if isinstance(peer, tuple) and peer else 'unix'}"
                if self.per_circuit[circuit] >= C.MAX_CONN_PER_CIRCUIT:
                    self._send(writer, err("Too many concurrent connections from this circuit.", "rate_limited", 2))
                    return
                self.per_circuit[circuit] += 1
                counted = True
                # 2) the request line, bounded by ONE deadline for the whole request.
                raw = first or await asyncio.wait_for(reader.readuntil(b"\n"), timeout=max(0.1, deadline - loop.time()))
            except ProxyHeaderError:
                audit_log("connection_rejected", status="blocked", details="bad or missing PROXY header", noisy=True)
                return
            except asyncio.TimeoutError:
                self._send(writer, err("Request timed out.", "timeout"))
                return
            except asyncio.LimitOverrunError:
                self._send(writer, err("Request too large.", "bad_request"))
                return
            except (asyncio.IncompleteReadError, ConnectionError, UnicodeDecodeError):
                return
            allowed, retry = circuit_limiter.allow(circuit)
            if not allowed:
                audit_log("circuit_rate_limited", status="blocked", noisy=True)
                self._send(writer, err("Too many requests from this connection. Slow down.", "rate_limited", retry))
                return
            try:
                request = parse_request_json(raw.strip())
            except (ValueError, UnicodeDecodeError, RecursionError):
                audit_log("request_rejected", action="invalid_json", status="fail", noisy=True)
                self._send(writer, err("Invalid JSON.", "bad_request"))
                return
            if self.queued >= C.MAX_QUEUED_JOBS:
                self._send(writer, err("Server is busy. Try again shortly.", "server_busy", 3))
                return
            self.queued += 1
            try:
                response = await loop.run_in_executor(self.executor, self._dispatch, request, circuit)
            finally:
                self.queued -= 1
            self._send(writer, response)
        finally:
            self.active -= 1
            if counted:
                self.per_circuit[circuit] -= 1
                if self.per_circuit[circuit] <= 0:
                    self.per_circuit.pop(circuit, None)
            await self._close(writer)

    def _dispatch(self, request: Any, circuit: str) -> dict[str, Any]:
        try:
            return handle_request(request, Ctx(circuit=circuit, db=self.db))
        except Exception as exc:  # never leak internals to the client
            audit_log("handler_error", status="error", details=f"{exc.__class__.__name__}: {exc}", noisy=True)
            return err("Internal server error.", "server_error")

    async def _maintenance(self) -> None:
        loop = asyncio.get_running_loop()
        while not self.stopping.is_set():
            try:
                await loop.run_in_executor(self.executor, self.db.maintenance)
            except Exception as exc:
                log(f"maintenance_error {exc.__class__.__name__}")
            try:
                await asyncio.wait_for(self.stopping.wait(), timeout=300)
            except asyncio.TimeoutError:
                pass

    async def serve(self) -> None:
        limit = C.MAX_REQUEST_LINE_BYTES
        if C.UNIX_SOCKET:
            path = C.UNIX_SOCKET
            if os.path.exists(path):
                os.unlink(path)
            server = await asyncio.start_unix_server(self.handle, path=path, limit=limit, backlog=512)
            os.chmod(path, 0o666)   # the socket's directory is only shared with the tor container
            where = f"unix:{path}"
        else:
            server = await asyncio.start_server(self.handle, host=C.HOST, port=C.PORT, limit=limit, backlog=512,
                                                reuse_address=True, family=socket.AF_INET)
            where = f"{C.HOST}:{C.PORT}"
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, self.stopping.set)
            except (NotImplementedError, RuntimeError):
                pass
        log(f"server_listening {where} pow=scrypt(n={C.POW_SCRYPT_N},r={C.POW_SCRYPT_R}) base_difficulty={C.POW_BASE_DIFFICULTY} "
            f"require_proxy_header={int(C.REQUIRE_PROXY_HEADER)}")
        maint = asyncio.create_task(self._maintenance())
        async with server:
            await self.stopping.wait()
        maint.cancel()
        log("server_stopped")
        self.executor.shutdown(wait=False, cancel_futures=True)
