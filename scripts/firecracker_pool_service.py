#!/usr/bin/env python3
"""Node-local Firecracker pool service prototype.

The service owns pool/session/process lifecycle and exposes Codex-style sandbox
operations through a small JSON HTTP API. It can run with the real LUMI
FirecrackerPool backend or with --mock for local API smoke tests.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import http.client
import http.server
import json
import os
import queue
import select
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any


def maybe_import_firecracker_pool() -> Any:
    try:
        import firecracker_lumi_phase6 as phase6  # type: ignore
    except ImportError:
        return None
    return phase6


class ServiceError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class MockSession:
    def __init__(self, pool: "MockPool", session_id: str):
        self.pool = pool
        self.session_id = session_id
        self.vm_id = "mock-vm"
        self.queue_wait_ms = 0.0
        self.workspace = Path(tempfile.mkdtemp(prefix="fc-service-mock-"))
        (self.workspace / "tests").mkdir()
        (self.workspace / "tests" / "test_sample.py").write_text("def test_ok():\n    assert 1 + 1 == 2\n", encoding="utf-8")
        self.handles: dict[str, subprocess.Popen[bytes]] = {}

    def run_ms(self, command: str, timeout_ms: int = 0, cwd: str = "/workspace", env: dict[str, str] | None = None, stdin: bytes = b"", stdout_limit: int = 16 * 1024 * 1024, stderr_limit: int = 16 * 1024 * 1024) -> dict[str, Any]:
        started = time.perf_counter()
        proc = subprocess.Popen(
            ["/bin/bash", "-lc", command],
            cwd=self.workspace,
            env={**os.environ, **(env or {})},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid,
        )
        timed_out = False
        kill_reason = None
        try:
            timeout_s = None if int(timeout_ms) <= 0 else timeout_ms / 1000.0
            stdout, stderr = proc.communicate(input=stdin, timeout=timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            kill_reason = "timeout"
            with contextlib.suppress(ProcessLookupError):
                os.killpg(os.getpgid(proc.pid), 9)
            stdout, stderr = proc.communicate()
        stdout = stdout or b""
        stderr = stderr or b""
        return {
            "ok": True,
            "exit_code": proc.returncode,
            "stdout_b64": b64(stdout[:stdout_limit]),
            "stderr_b64": b64(stderr[:stderr_limit]),
            "stdout_bytes_full": len(stdout),
            "stderr_bytes_full": len(stderr),
            "stdout_truncated": len(stdout) > stdout_limit,
            "stderr_truncated": len(stderr) > stderr_limit,
            "timeout": timed_out,
            "kill_reason": kill_reason,
            "command_roundtrip_ms": (time.perf_counter() - started) * 1000.0,
        }

    def start(self, command: str, cwd: str = "/workspace", env: dict[str, str] | None = None) -> dict[str, Any]:
        proc = subprocess.Popen(
            ["/bin/bash", "-lc", command],
            cwd=self.workspace,
            env={**os.environ, **(env or {})},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid,
        )
        handle = "p-" + uuid.uuid4().hex[:12]
        self.handles[handle] = proc
        return {"ok": True, "handle": handle, "pid": proc.pid}

    def read(self, handle: str, wait_ms: int = 0, stdout_limit: int = 16 * 1024 * 1024, stderr_limit: int = 16 * 1024 * 1024) -> dict[str, Any]:
        proc = self.handles[handle]
        stdout = b""
        stderr = b""
        streams = [stream for stream in (proc.stdout, proc.stderr) if stream is not None]
        if streams:
            select.select(streams, [], [], max(0, wait_ms) / 1000.0)
        for stream_name, stream, limit in (("stdout", proc.stdout, stdout_limit), ("stderr", proc.stderr, stderr_limit)):
            if stream is None:
                continue
            fd = stream.fileno()
            os.set_blocking(fd, False)
            try:
                chunk = os.read(fd, limit)
            except BlockingIOError:
                chunk = b""
            if stream_name == "stdout":
                stdout = chunk
            else:
                stderr = chunk
        return {
            "ok": True,
            "stdout_b64": b64(stdout),
            "stderr_b64": b64(stderr),
            "stdout_bytes_full": len(stdout),
            "stderr_bytes_full": len(stderr),
            "running": proc.poll() is None,
            "exit_code": proc.poll(),
        }

    def write(self, handle: str, data: bytes) -> dict[str, Any]:
        proc = self.handles[handle]
        if proc.stdin:
            proc.stdin.write(data)
            proc.stdin.flush()
        return {"ok": True, "bytes": len(data), "running": proc.poll() is None}

    def close_stdin(self, handle: str) -> dict[str, Any]:
        proc = self.handles[handle]
        if proc.stdin:
            proc.stdin.close()
        return {"ok": True, "running": proc.poll() is None}

    def process_status(self, handle: str) -> dict[str, Any]:
        proc = self.handles[handle]
        return {"ok": True, "running": proc.poll() is None, "exit_code": proc.poll(), "pid": proc.pid}

    def terminate(self, handle: str, signal_number: int = 15) -> dict[str, Any]:
        proc = self.handles[handle]
        with contextlib.suppress(ProcessLookupError):
            os.killpg(os.getpgid(proc.pid), signal_number)
        return {"ok": True, "running": proc.poll() is None, "exit_code": proc.poll()}

    def reset(self, validate: bool = True) -> dict[str, Any]:
        for handle, proc in list(self.handles.items()):
            if proc.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(os.getpgid(proc.pid), 9)
            self.handles.pop(handle, None)
        for child in list(self.workspace.iterdir()):
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
        (self.workspace / "tests").mkdir()
        (self.workspace / "tests" / "test_sample.py").write_text("def test_ok():\n    assert 1 + 1 == 2\n", encoding="utf-8")
        return {"ok": True, "reset_request_ms": 0.0, "post_reset_validation_ms": 0.0, "total_recycle_ready_ms": 0.0}

    def release(self, reset: bool = True) -> dict[str, Any] | None:
        if reset:
            self.reset(validate=True)
        shutil.rmtree(self.workspace, ignore_errors=True)
        self.pool.release(self)
        return {"ok": True}


class MockPool:
    def __init__(self, size: int, pool_id: str):
        self.size = size
        self.pool_id = pool_id
        self.available = queue.Queue()
        for _ in range(size):
            self.available.put(object())
        self.closed = False

    def create(self) -> dict[str, Any]:
        return self.status()

    def acquire(self, timeout: float = 30) -> MockSession:
        self.available.get(timeout=timeout)
        return MockSession(self, "s-" + uuid.uuid4().hex[:12])

    def release(self, _session: MockSession) -> None:
        if not self.closed:
            self.available.put(object())

    def status(self) -> dict[str, Any]:
        return {"pool_id": self.pool_id, "requested": self.size, "ready": self.size, "available": self.available.qsize()}

    def close(self) -> None:
        self.closed = True


class PoolRecord:
    def __init__(self, pool_id: str, pool: Any, backend: str):
        self.pool_id = pool_id
        self.pool = pool
        self.backend = backend
        self.created_at = time.time()
        self.draining = False
        self.metrics = collections_counter()
        self.operation_lock = threading.RLock()


class SessionRecord:
    def __init__(self, session_id: str, pool_id: str, session: Any, task_id: str | None):
        self.session_id = session_id
        self.pool_id = pool_id
        self.session = session
        self.task_id = task_id
        self.created_at = time.time()
        self.transcript: list[dict[str, Any]] = []
        self.metrics: list[dict[str, Any]] = []


def collections_counter() -> dict[str, int]:
    return {"acquire": 0, "run": 0, "start": 0, "reset": 0, "release": 0}


class PoolService:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.phase6 = maybe_import_firecracker_pool()
        self.pools: dict[str, PoolRecord] = {}
        self.sessions: dict[str, SessionRecord] = {}
        self.lock = threading.RLock()
        self.started_at = time.time()
        self.request_counts = collections_counter()

    def create_pool(self, payload: dict[str, Any]) -> dict[str, Any]:
        pool_id = str(payload.get("pool_id") or "pool-" + uuid.uuid4().hex[:8])
        size = int(payload.get("size") or self.args.pool_size)
        backend = str(payload.get("backend") or self.args.backend)
        with self.lock:
            if pool_id in self.pools:
                raise ServiceError(409, f"pool already exists: {pool_id}")
            if backend == "mock":
                pool = MockPool(size, pool_id)
            else:
                if self.phase6 is None:
                    raise ServiceError(500, "firecracker_lumi_phase6 is not importable")
                pool = self.phase6.FirecrackerPool(
                    size,
                    payload.get("profile") or "service",
                    self.args.firecracker,
                    self.args.kernel,
                    self.args.rootfs,
                    self.args.run_dir,
                    mem_mib=int(payload.get("mem_mib") or self.args.mem_mib),
                    vcpus=int(payload.get("vcpus") or self.args.vcpus),
                    pool_id=pool_id,
                )
            status = pool.create()
            self.pools[pool_id] = PoolRecord(pool_id, pool, backend)
            return {"pool_id": pool_id, "status": status}

    def pool_status(self, pool_id: str) -> dict[str, Any]:
        record = self.require_pool(pool_id)
        return {"pool_id": pool_id, "draining": record.draining, "backend": record.backend, "status": record.pool.status(), "metrics": record.metrics}

    def create_session(self, payload: dict[str, Any]) -> dict[str, Any]:
        pool_id = str(payload.get("pool_id") or "")
        record = self.require_pool(pool_id)
        if record.draining:
            raise ServiceError(503, f"pool is draining: {pool_id}")
        timeout_ms = int(payload.get("queue_timeout_ms") or 30000)
        started = time.perf_counter()
        session = record.pool.acquire(timeout=timeout_ms / 1000.0)
        session_id = str(payload.get("session_id") or "sess-" + uuid.uuid4().hex[:12])
        rec = SessionRecord(session_id, pool_id, session, payload.get("task_id"))
        with self.lock:
            self.sessions[session_id] = rec
            record.metrics["acquire"] += 1
            self.request_counts["acquire"] += 1
        return {
            "session_id": session_id,
            "pool_id": pool_id,
            "vm_id": getattr(session, "vm_id", None),
            "queue_wait_ms": getattr(session, "queue_wait_ms", (time.perf_counter() - started) * 1000.0),
        }

    def create_sandbox(self, payload: dict[str, Any]) -> dict[str, Any]:
        clean_payload = dict(payload)
        clean_payload.pop("session_id", None)
        resp = self.create_session(clean_payload)
        resp["sandbox_id"] = resp["session_id"]
        return resp

    def run(self, session_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        rec = self.require_session(session_id)
        started = time.perf_counter()
        timeout_ms = payload.get("timeout_ms")
        if timeout_ms is None:
            timeout_ms = self.args.default_timeout_ms
        resp = rec.session.run_ms(
            str(payload.get("command") or ""),
            timeout_ms=int(timeout_ms),
            cwd=payload.get("cwd") or "/workspace",
            env=payload.get("env") or {},
            stdin=b64decode(payload.get("stdin_b64")),
            stdout_limit=int(payload.get("stdout_limit") or 16 * 1024 * 1024),
            stderr_limit=int(payload.get("stderr_limit") or 16 * 1024 * 1024),
        )
        metric = {"op": "run", "elapsed_ms": (time.perf_counter() - started) * 1000.0, "exit_code": resp.get("exit_code")}
        rec.metrics.append(metric)
        rec.transcript.append({"op": "run", "command": payload.get("command"), "response": compact_response(resp)})
        self.pools[rec.pool_id].metrics["run"] += 1
        self.request_counts["run"] += 1
        return resp

    def start(self, session_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        rec = self.require_session(session_id)
        resp = rec.session.start(str(payload.get("command") or ""), cwd=payload.get("cwd") or "/workspace", env=payload.get("env") or {})
        if "handle" in resp and "process_id" not in resp:
            resp["process_id"] = resp["handle"]
        rec.transcript.append({"op": "start", "command": payload.get("command"), "response": resp})
        self.pools[rec.pool_id].metrics["start"] += 1
        self.request_counts["start"] += 1
        return resp

    def process_action(self, session_id: str, process_id: str, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        rec = self.require_session(session_id)
        if action == "read":
            return rec.session.read(process_id, wait_ms=int(payload.get("wait_ms") or 0), stdout_limit=int(payload.get("stdout_limit") or 16 * 1024 * 1024), stderr_limit=int(payload.get("stderr_limit") or 16 * 1024 * 1024))
        if action == "write":
            return rec.session.write(process_id, b64decode(payload.get("stdin_b64") or payload.get("data_b64")))
        if action == "close_stdin":
            return rec.session.close_stdin(process_id)
        if action == "interrupt":
            return rec.session.terminate(process_id, signal_number=2)
        if action == "terminate":
            return rec.session.terminate(process_id, signal_number=int(payload.get("signal") or 15))
        if action == "cancel":
            return rec.session.terminate(process_id, signal_number=int(payload.get("signal") or 15))
        if action == "status":
            return rec.session.process_status(process_id)
        raise ServiceError(404, f"unknown process action: {action}")

    def reset_session(self, session_id: str) -> dict[str, Any]:
        rec = self.require_session(session_id)
        pool_record = self.require_pool(rec.pool_id)
        with pool_record.operation_lock:
            resp = rec.session.reset(validate=True)
        rec.metrics.append({"op": "reset", "ok": resp.get("ok"), "total_recycle_ready_ms": resp.get("total_recycle_ready_ms")})
        pool_record.metrics["reset"] += 1
        self.request_counts["reset"] += 1
        return resp

    def close_session(self, session_id: str, strategy: str = "auto") -> dict[str, Any]:
        if strategy not in {"auto", "hard"}:
            raise ServiceError(400, "release strategy must be auto or hard")
        with self.lock:
            rec = self.sessions.pop(session_id, None)
        if rec is None:
            return {"ok": True, "already_closed": True}
        pool_record = self.require_pool(rec.pool_id)
        with pool_record.operation_lock:
            resp = rec.session.release(reset=True)
        pool_record.metrics["release"] += 1
        self.request_counts["release"] += 1
        return {"ok": True, "sandbox_id": session_id, "release": resp, "requested_strategy": strategy}

    def release_sandbox(self, sandbox_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.close_session(sandbox_id, strategy=str(payload.get("strategy") or "auto"))

    def close_pool(self, pool_id: str) -> dict[str, Any]:
        record = self.require_pool(pool_id)
        record.draining = True
        with record.operation_lock:
            for session_id, rec in list(self.sessions.items()):
                if rec.pool_id == pool_id:
                    self.close_session(session_id)
            record.pool.close()
            with self.lock:
                self.pools.pop(pool_id, None)
        return {"ok": True, "pool_id": pool_id}

    def transcript(self, session_id: str) -> dict[str, Any]:
        rec = self.require_session(session_id)
        return {"session_id": session_id, "transcript": rec.transcript}

    def metrics(self, session_id: str) -> dict[str, Any]:
        rec = self.require_session(session_id)
        return {"session_id": session_id, "metrics": rec.metrics}

    def healthz(self) -> dict[str, Any]:
        return {"ok": True, "uptime_s": time.time() - self.started_at}

    def readyz(self) -> dict[str, Any]:
        pool_statuses = []
        ready = True
        with self.lock:
            records = list(self.pools.values())
        for record in records:
            status = record.pool.status()
            pool_statuses.append({"pool_id": record.pool_id, "backend": record.backend, "status": status})
            ready = ready and not record.draining
        return {"ok": ready, "pool_count": len(pool_statuses), "pools": pool_statuses}

    def varz(self) -> dict[str, Any]:
        with self.lock:
            pools = {
                pool_id: {
                    "backend": record.backend,
                    "created_at": record.created_at,
                    "draining": record.draining,
                    "status": record.pool.status(),
                    "metrics": record.metrics,
                }
                for pool_id, record in self.pools.items()
            }
            sessions = {
                session_id: {
                    "pool_id": record.pool_id,
                    "task_id": record.task_id,
                    "created_at": record.created_at,
                    "vm_id": getattr(record.session, "vm_id", None),
                }
                for session_id, record in self.sessions.items()
            }
        return {
            "service": "firecracker-rl-sandbox",
            "uptime_s": time.time() - self.started_at,
            "backend_default": self.args.backend,
            "pools": pools,
            "sandboxes": sessions,
            "request_counts": self.request_counts,
        }

    def prometheus_metrics(self) -> str:
        varz = self.varz()
        lines = [
            "# HELP firecracker_rl_sandbox_uptime_seconds Service uptime.",
            "# TYPE firecracker_rl_sandbox_uptime_seconds gauge",
            f"firecracker_rl_sandbox_uptime_seconds {varz['uptime_s']:.6f}",
            "# HELP firecracker_rl_sandbox_pools Number of configured pools.",
            "# TYPE firecracker_rl_sandbox_pools gauge",
            f"firecracker_rl_sandbox_pools {len(varz['pools'])}",
            "# HELP firecracker_rl_sandbox_leased_sandboxes Number of leased sandboxes.",
            "# TYPE firecracker_rl_sandbox_leased_sandboxes gauge",
            f"firecracker_rl_sandbox_leased_sandboxes {len(varz['sandboxes'])}",
            "# HELP firecracker_rl_sandbox_requests_total Service operation counts.",
            "# TYPE firecracker_rl_sandbox_requests_total counter",
        ]
        for op, count in sorted(self.request_counts.items()):
            lines.append(f'firecracker_rl_sandbox_requests_total{{op="{op}"}} {count}')
        for pool_id, pool in sorted(varz["pools"].items()):
            status = pool["status"]
            for key in ("ready", "available", "requested"):
                if key in status:
                    lines.append(f'firecracker_rl_sandbox_pool_{key}{{pool_id="{pool_id}"}} {status[key]}')
        return "\n".join(lines) + "\n"

    def require_pool(self, pool_id: str) -> PoolRecord:
        with self.lock:
            record = self.pools.get(pool_id)
        if record is None:
            raise ServiceError(404, f"unknown pool: {pool_id}")
        return record

    def require_session(self, session_id: str) -> SessionRecord:
        with self.lock:
            record = self.sessions.get(session_id)
        if record is None:
            raise ServiceError(404, f"unknown session: {session_id}")
        return record


class Handler(http.server.BaseHTTPRequestHandler):
    server: "JsonServer"

    def do_GET(self) -> None:
        self.handle_request("GET")

    def do_POST(self) -> None:
        self.handle_request("POST")

    def do_DELETE(self) -> None:
        self.handle_request("DELETE")

    def handle_request(self, method: str) -> None:
        try:
            self.check_auth()
            payload = self.read_payload()
            result = route(self.server.service, method, self.path, payload)
            if "__text__" in result:
                self.send_text(200, result["__text__"], result.get("__content_type__", "text/plain; charset=utf-8"))
            else:
                self.send_json(200, result)
        except ServiceError as exc:
            self.send_json(exc.status, {"ok": False, "error": exc.message})
        except Exception as exc:
            self.send_json(500, {"ok": False, "error": repr(exc)})

    def check_auth(self) -> None:
        token = self.server.auth_token
        if not token:
            return
        got = self.headers.get("authorization", "")
        if got != "Bearer " + token:
            raise ServiceError(401, "missing or invalid bearer token")

    def read_payload(self) -> dict[str, Any]:
        size = int(self.headers.get("content-length") or 0)
        if not size:
            return {}
        data = json.loads(self.rfile.read(size).decode("utf-8"))
        if not isinstance(data, dict):
            raise ServiceError(400, "request body must be a JSON object")
        return data

    def send_json(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_text(self, status: int, text: str, content_type: str) -> None:
        data = text.encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args: Any) -> None:
        if self.server.quiet:
            return
        super().log_message(fmt, *args)


class JsonServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 1024

    def __init__(self, address: tuple[str, int], handler: type[Handler], service: PoolService, auth_token: str | None, quiet: bool):
        super().__init__(address, handler)
        self.service = service
        self.auth_token = auth_token
        self.quiet = quiet


def route(service: PoolService, method: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    parts = [part for part in urllib.parse.urlsplit(path).path.split("/") if part]
    if parts == ["healthz"] and method == "GET":
        return service.healthz()
    if parts == ["readyz"] and method == "GET":
        return service.readyz()
    if parts == ["varz"] and method == "GET":
        return service.varz()
    if parts == ["metrics"] and method == "GET":
        return {
            "__text__": service.prometheus_metrics(),
            "__content_type__": "text/plain; version=0.0.4; charset=utf-8",
        }
    if parts == ["v1", "pools"] and method == "POST":
        return service.create_pool(payload)
    if len(parts) == 3 and parts[:2] == ["v1", "pools"] and method == "GET":
        return service.pool_status(parts[2])
    if len(parts) == 3 and parts[:2] == ["v1", "pools"] and method == "DELETE":
        return service.close_pool(parts[2])
    if parts == ["v1", "sandboxes"] and method == "POST":
        return service.create_sandbox(payload)
    if len(parts) == 4 and parts[:2] == ["v1", "sandboxes"] and parts[3] == "run" and method == "POST":
        return service.run(parts[2], payload)
    if len(parts) == 4 and parts[:2] == ["v1", "sandboxes"] and parts[3] == "processes" and method == "POST":
        return service.start(parts[2], payload)
    if len(parts) == 6 and parts[:2] == ["v1", "sandboxes"] and parts[3] == "processes":
        action = parts[5]
        if method in {"GET", "POST"}:
            return service.process_action(parts[2], parts[4], action, payload)
    if len(parts) == 4 and parts[:2] == ["v1", "sandboxes"] and parts[3] in {"release", "reset"} and method == "POST":
        if parts[3] == "reset":
            return service.reset_session(parts[2])
        return service.release_sandbox(parts[2], payload)
    if len(parts) == 4 and parts[:2] == ["v1", "sandboxes"] and parts[3] == "transcript" and method == "GET":
        return service.transcript(parts[2])
    if len(parts) == 4 and parts[:2] == ["v1", "sandboxes"] and parts[3] == "metrics" and method == "GET":
        return service.metrics(parts[2])
    if len(parts) == 3 and parts[:2] == ["v1", "sandboxes"] and method == "DELETE":
        return service.release_sandbox(parts[2], payload)
    if parts == ["v1", "sessions"] and method == "POST":
        return service.create_session(payload)
    if len(parts) == 4 and parts[:2] == ["v1", "sessions"] and parts[3] == "run" and method == "POST":
        return service.run(parts[2], payload)
    if len(parts) == 4 and parts[:2] == ["v1", "sessions"] and parts[3] == "processes" and method == "POST":
        return service.start(parts[2], payload)
    if len(parts) == 6 and parts[:2] == ["v1", "sessions"] and parts[3] == "processes":
        action = parts[5]
        if method in {"GET", "POST"}:
            return service.process_action(parts[2], parts[4], action, payload)
    if len(parts) == 4 and parts[:2] == ["v1", "sessions"] and parts[3] == "reset" and method == "POST":
        return service.reset_session(parts[2])
    if len(parts) == 4 and parts[:2] == ["v1", "sessions"] and parts[3] == "transcript" and method == "GET":
        return service.transcript(parts[2])
    if len(parts) == 4 and parts[:2] == ["v1", "sessions"] and parts[3] == "metrics" and method == "GET":
        return service.metrics(parts[2])
    if len(parts) == 3 and parts[:2] == ["v1", "sessions"] and method == "DELETE":
        return service.close_session(parts[2])
    raise ServiceError(404, f"no route for {method} {path}")


def run_self_test(args: argparse.Namespace) -> int:
    args.backend = "mock"
    service = PoolService(args)
    server = JsonServer(("127.0.0.1", 0), Handler, service, auth_token=None, quiet=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        pool = http_json(host, port, "POST", "/v1/pools", {"pool_id": "selftest", "size": 2, "backend": "mock"})
        session = http_json(host, port, "POST", "/v1/sessions", {"pool_id": "selftest", "task_id": "smoke"})
        sid = session["session_id"]
        healthz = http_json(host, port, "GET", "/healthz", {})
        readyz = http_json(host, port, "GET", "/readyz", {})
        sandbox = http_json(host, port, "POST", "/v1/sandboxes", {"pool_id": "selftest", "task_id": "smoke"})
        sbx = sandbox["sandbox_id"]
        run = http_json(host, port, "POST", f"/v1/sandboxes/{sbx}/run", {"command": "echo service-ready"})
        proc = http_json(host, port, "POST", f"/v1/sandboxes/{sbx}/processes", {"command": "python3 -u -c 'print(1, flush=True); import time; time.sleep(5)'"})
        read = http_json(host, port, "POST", f"/v1/sandboxes/{sbx}/processes/{proc['process_id']}/read", {"wait_ms": 1000})
        term = http_json(host, port, "POST", f"/v1/sandboxes/{sbx}/processes/{proc['process_id']}/cancel", {})
        reset = http_json(host, port, "POST", f"/v1/sandboxes/{sbx}/reset", {})
        close_session = http_json(host, port, "DELETE", f"/v1/sandboxes/{sbx}", {})
        close_pool = http_json(host, port, "DELETE", "/v1/pools/selftest", {})
    finally:
        server.shutdown()
        thread.join(timeout=5)
    ok = (
        pool["status"]["ready"] == 2
        and healthz["ok"]
        and readyz["ok"]
        and sandbox["pool_id"] == "selftest"
        and run["exit_code"] == 0
        and b64decode(read.get("stdout_b64")) == b"1\n"
        and term.get("ok")
        and reset.get("ok")
        and close_session.get("ok")
        and close_pool.get("ok")
    )
    result = {"assessment": "pass" if ok else "fail", "pool": pool, "sandbox": sandbox, "run": compact_response(run), "read": compact_response(read), "reset": reset}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if ok else 2


def http_json(host: str, port: int, method: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    conn = http.client.HTTPConnection(host, port, timeout=10)
    body = json.dumps(payload).encode("utf-8") if method != "GET" or payload else b""
    conn.request(method, path, body=body, headers={"content-type": "application/json"})
    resp = conn.getresponse()
    data = json.loads(resp.read().decode("utf-8"))
    if resp.status >= 400:
        raise RuntimeError(data)
    return data


def compact_response(resp: dict[str, Any]) -> dict[str, Any]:
    out = dict(resp)
    for key in ("stdout_b64", "stderr_b64"):
        if key in out and len(str(out[key])) > 120:
            out[key] = str(out[key])[:120] + "...<truncated>"
    return out


def b64(data: bytes) -> str:
    return base64.b64encode(data or b"").decode("ascii")


def b64decode(value: Any) -> bytes:
    if not value:
        return b""
    return base64.b64decode(str(value).encode("ascii"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a node-local Firecracker pool service.")
    parser.add_argument("--listen", default="127.0.0.1:8765")
    parser.add_argument("--backend", choices=("firecracker", "mock"), default="firecracker")
    parser.add_argument("--pool-size", type=int, default=64)
    parser.add_argument("--firecracker")
    parser.add_argument("--kernel")
    parser.add_argument("--rootfs")
    parser.add_argument("--run-dir", default="/tmp/firecracker-pool-service")
    parser.add_argument("--mem-mib", type=int, default=768)
    parser.add_argument("--vcpus", type=int, default=1)
    parser.add_argument("--default-timeout-ms", type=int, default=0)
    parser.add_argument("--auth-token", default=os.environ.get("FIRECRACKER_POOL_TOKEN"))
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        return run_self_test(args)
    host, raw_port = args.listen.rsplit(":", 1)
    service = PoolService(args)
    server = JsonServer((host, int(raw_port)), Handler, service, args.auth_token, args.quiet)
    print(json.dumps({"event": "listening", "listen": args.listen, "backend": args.backend, "auth": bool(args.auth_token)}, sort_keys=True), flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
