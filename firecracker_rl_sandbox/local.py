from __future__ import annotations

import contextlib
import os
import queue
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from .client import CommandResult


class LocalPool:
    """Subprocess-backed API compatibility helper.

    This is useful for quick starts and client tests. It is not a sandbox and
    must not be used as a security boundary.
    """

    def __init__(self, *, profile: str = "local-subprocess", size: int = 1):
        self.profile = profile
        self.size = size
        self._tokens: queue.Queue[object] = queue.Queue()
        for _ in range(size):
            self._tokens.put(object())

    def allocate(self, *, task_id: str | None = None, queue_timeout_ms: int = 30000) -> "LocalSandbox":
        token = self._tokens.get(timeout=queue_timeout_ms / 1000.0)
        return LocalSandbox(self, token, profile=self.profile, task_id=task_id)

    def _release_token(self, token: object) -> None:
        self._tokens.put(token)


class LocalSandbox:
    def __init__(self, pool: LocalPool, token: object, *, profile: str, task_id: str | None):
        self.pool = pool
        self.token = token
        self.profile = profile
        self.task_id = task_id
        self.sandbox_id = "local-" + uuid.uuid4().hex[:12]
        self.workspace = Path(tempfile.mkdtemp(prefix="firecracker-rl-sandbox-local-"))
        self._processes: dict[str, LocalProcess] = {}
        self._released = False

    def __enter__(self) -> "LocalSandbox":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.release()

    def run(
        self,
        command: str,
        *,
        cwd: str = "/workspace",
        env: dict[str, str] | None = None,
        stdin: bytes | str | None = None,
        timeout_ms: int = 0,
        stdout_limit: int | None = None,
        stderr_limit: int | None = None,
    ) -> CommandResult:
        started = time.perf_counter()
        proc = subprocess.Popen(
            ["/bin/bash", "-lc", command],
            cwd=self._cwd(cwd),
            env={**os.environ, **(env or {})},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid,
        )
        timeout_s = None if timeout_ms <= 0 else timeout_ms / 1000.0
        timed_out = False
        try:
            stdout, stderr = proc.communicate(input=_to_bytes(stdin), timeout=timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_process_group(proc.pid, signal.SIGKILL)
            stdout, stderr = proc.communicate()
        stdout = stdout or b""
        stderr = stderr or b""
        stdout_view = stdout[: stdout_limit or len(stdout)]
        stderr_view = stderr[: stderr_limit or len(stderr)]
        return CommandResult(
            exit_code=proc.returncode,
            stdout=stdout_view,
            stderr=stderr_view,
            timeout=timed_out,
            stdout_truncated=len(stdout_view) < len(stdout),
            stderr_truncated=len(stderr_view) < len(stderr),
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            raw={
                "sandbox_id": self.sandbox_id,
                "stdout_bytes_full": len(stdout),
                "stderr_bytes_full": len(stderr),
            },
        )

    def start_process(
        self,
        command: str,
        *,
        cwd: str = "/workspace",
        env: dict[str, str] | None = None,
        interactive: bool = False,
    ) -> "LocalProcess":
        stdin = subprocess.PIPE if interactive else subprocess.DEVNULL
        proc = subprocess.Popen(
            ["/bin/bash", "-lc", command],
            cwd=self._cwd(cwd),
            env={**os.environ, **(env or {})},
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid,
        )
        process = LocalProcess("local-proc-" + uuid.uuid4().hex[:12], proc, interactive=interactive)
        self._processes[process.process_id] = process
        return process

    def release(self, *, strategy: str = "auto") -> dict[str, Any]:
        if self._released:
            return {"ok": True, "already_released": True}
        for process in list(self._processes.values()):
            if process.status()["running"]:
                process.cancel(signal_number=signal.SIGKILL)
        shutil.rmtree(self.workspace, ignore_errors=True)
        self.pool._release_token(self.token)
        self._released = True
        return {"ok": True, "sandbox_id": self.sandbox_id, "requested_strategy": strategy}

    def _cwd(self, cwd: str) -> str:
        if cwd == "/workspace":
            return str(self.workspace)
        if cwd.startswith("/workspace/"):
            return str(self.workspace / cwd.removeprefix("/workspace/"))
        return cwd


class LocalProcess:
    def __init__(self, process_id: str, proc: subprocess.Popen[bytes], *, interactive: bool):
        self.process_id = process_id
        self.proc = proc
        self.interactive = interactive

    def status(self) -> dict[str, Any]:
        return {"process_id": self.process_id, "running": self.proc.poll() is None, "exit_code": self.proc.poll()}

    def read(self, *, wait_ms: int = 0, stdout_limit: int | None = None, stderr_limit: int | None = None) -> CommandResult:
        deadline = time.monotonic() + max(0, wait_ms) / 1000.0
        while self.proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        stdout, stderr = self.proc.communicate(timeout=0) if self.proc.poll() is not None else (b"", b"")
        stdout = stdout or b""
        stderr = stderr or b""
        stdout_view = stdout[: stdout_limit or len(stdout)]
        stderr_view = stderr[: stderr_limit or len(stderr)]
        return CommandResult(
            exit_code=self.proc.poll(),
            stdout=stdout_view,
            stderr=stderr_view,
            stdout_truncated=len(stdout_view) < len(stdout),
            stderr_truncated=len(stderr_view) < len(stderr),
            raw=self.status(),
        )

    def close_stdin(self) -> dict[str, Any]:
        if self.proc.stdin is None:
            return {"ok": False, "error": "stdin_closed"}
        self.proc.stdin.close()
        return {"ok": True}

    def cancel(self, *, signal_number: int = signal.SIGTERM) -> dict[str, Any]:
        _kill_process_group(self.proc.pid, signal_number)
        try:
            self.proc.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            _kill_process_group(self.proc.pid, signal.SIGKILL)
            with contextlib.suppress(subprocess.TimeoutExpired):
                self.proc.wait(timeout=0.5)
        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            if stream is not None:
                with contextlib.suppress(OSError):
                    stream.close()
        return self.status()


def _to_bytes(value: bytes | str | None) -> bytes | None:
    if value is None:
        return None
    return value if isinstance(value, bytes) else value.encode("utf-8")


def _kill_process_group(pid: int, sig: int) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(os.getpgid(pid), sig)
