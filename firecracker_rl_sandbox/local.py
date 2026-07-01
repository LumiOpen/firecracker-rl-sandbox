from __future__ import annotations

import contextlib
import os
import queue
import shutil
import signal
import select
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from .client import CommandResult


class LocalPool:
    """In-process Firecracker-backed sandbox pool.

    Local means "no standalone service process", not "mock". This class still
    launches real Firecracker microVMs and provides the same sandbox API shape
    as the service client.
    """

    def __init__(
        self,
        *,
        profile: str = "python-coding",
        size: int = 1,
        firecracker_bin: str | os.PathLike[str] | None = None,
        kernel: str | os.PathLike[str] | None = None,
        rootfs: str | os.PathLike[str] | None = None,
        run_dir: str | os.PathLike[str] | None = None,
        mem_mib: int = 768,
        vcpus: int = 1,
        network: str = "none",
        pool_id: str | None = None,
        create: bool = True,
    ):
        if network not in {"none", "egress"}:
            raise ValueError("network must be 'none' or 'egress'")
        if network == "egress":
            raise NotImplementedError("LocalPool network egress is not wired into the production gateway path yet")
        self.profile = profile
        self.size = size
        self.firecracker_bin = _required_path(firecracker_bin, "FIRECRACKER_BIN", "firecracker_bin")
        self.kernel = _required_path(kernel, "FIRECRACKER_KERNEL", "kernel")
        self.rootfs = _required_path(rootfs, "FIRECRACKER_ROOTFS", "rootfs")
        self.run_dir = Path(run_dir or os.environ.get("FIRECRACKER_RUN_DIR") or tempfile.mkdtemp(prefix="firecracker-rl-sandbox-"))
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.mem_mib = mem_mib
        self.vcpus = vcpus
        self.pool_id = pool_id or "local-" + uuid.uuid4().hex[:8]
        phase6 = _import_phase6()
        self._pool = phase6.FirecrackerPool(
            size,
            profile,
            str(self.firecracker_bin),
            str(self.kernel),
            str(self.rootfs),
            str(self.run_dir),
            mem_mib=mem_mib,
            vcpus=vcpus,
            pool_id=self.pool_id,
        )
        self._created = False
        if create:
            self.create()

    def create(self) -> dict[str, Any]:
        status = self._pool.create()
        self._created = True
        return status

    def status(self) -> dict[str, Any]:
        return self._pool.status()

    def allocate(self, *, task_id: str | None = None, queue_timeout_ms: int = 30000) -> "LocalSandbox":
        if not self._created:
            self.create()
        session = self._pool.acquire(timeout=queue_timeout_ms / 1000.0)
        return LocalSandbox(self, session, task_id=task_id)

    def close(self) -> None:
        self._pool.close()


class LocalSandbox:
    def __init__(self, pool: LocalPool, session: Any, *, task_id: str | None):
        self.pool = pool
        self.session = session
        self.task_id = task_id
        self.sandbox_id = "sbx_" + uuid.uuid4().hex[:16]
        self.released = False

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
        response = self.session.run_ms(
            command,
            timeout_ms=timeout_ms,
            cwd=cwd,
            env=env or {},
            stdin=_to_bytes(stdin) or b"",
            stdout_limit=stdout_limit or 16 * 1024 * 1024,
            stderr_limit=stderr_limit or 16 * 1024 * 1024,
        )
        return CommandResult.from_response(response)

    def start_process(
        self,
        command: str,
        *,
        cwd: str = "/workspace",
        env: dict[str, str] | None = None,
        interactive: bool = False,
    ) -> "LocalProcess":
        response = self.session.start(command, cwd=cwd, env=env or {})
        process_id = response.get("process_id") or response.get("handle")
        if not process_id:
            raise RuntimeError({"missing_process_id": response})
        return LocalProcess(self, str(process_id))

    def release(self, *, strategy: str = "auto") -> dict[str, Any]:
        if self.released:
            return {"ok": True, "already_released": True}
        reset = strategy != "none"
        response = self.session.release(reset=reset)
        self.released = True
        return {"ok": True, "sandbox_id": self.sandbox_id, "requested_strategy": strategy, "release": response}


class LocalProcess:
    def __init__(self, sandbox: LocalSandbox, process_id: str):
        self.sandbox = sandbox
        self.process_id = process_id

    def status(self) -> dict[str, Any]:
        return self.sandbox.session.process_status(self.process_id)

    def read(self, *, wait_ms: int = 0, stdout_limit: int | None = None, stderr_limit: int | None = None) -> CommandResult:
        response = self.sandbox.session.read(
            self.process_id,
            wait_ms=wait_ms,
            stdout_limit=stdout_limit or 16 * 1024 * 1024,
            stderr_limit=stderr_limit or 16 * 1024 * 1024,
        )
        return CommandResult.from_response(response)

    def write(self, data: bytes | str) -> dict[str, Any]:
        return self.sandbox.session.write(self.process_id, _to_bytes(data) or b"")

    def close_stdin(self) -> dict[str, Any]:
        return self.sandbox.session.close_stdin(self.process_id)

    def cancel(self, *, signal_number: int = signal.SIGTERM) -> dict[str, Any]:
        return self.sandbox.session.terminate(self.process_id, signal_number=signal_number)


class SubprocessPool:
    """Non-isolating subprocess backend for tests and API demos only."""

    def __init__(self, *, profile: str = "subprocess-mock", size: int = 1):
        self.profile = profile
        self.size = size
        self._tokens: queue.Queue[object] = queue.Queue()
        for _ in range(size):
            self._tokens.put(object())

    def allocate(self, *, task_id: str | None = None, queue_timeout_ms: int = 30000) -> "SubprocessSandbox":
        token = self._tokens.get(timeout=queue_timeout_ms / 1000.0)
        return SubprocessSandbox(self, token, profile=self.profile, task_id=task_id)

    def _release_token(self, token: object) -> None:
        self._tokens.put(token)


class SubprocessSandbox:
    def __init__(self, pool: SubprocessPool, token: object, *, profile: str, task_id: str | None):
        self.pool = pool
        self.token = token
        self.profile = profile
        self.task_id = task_id
        self.sandbox_id = "subprocess-" + uuid.uuid4().hex[:12]
        self.workspace = Path(tempfile.mkdtemp(prefix="firecracker-rl-sandbox-subprocess-"))
        self._processes: dict[str, SubprocessProcess] = {}
        self._released = False

    def __enter__(self) -> "SubprocessSandbox":
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
    ) -> "SubprocessProcess":
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
        process = SubprocessProcess("subprocess-proc-" + uuid.uuid4().hex[:12], proc, interactive=interactive)
        self._processes[process.process_id] = process
        return process

    def release(self, *, strategy: str = "auto") -> dict[str, Any]:
        if self._released:
            return {"ok": True, "already_released": True}
        for process in list(self._processes.values()):
            if process.status()["running"]:
                process.cancel(signal_number=signal.SIGKILL)
            process.close_streams()
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


class SubprocessProcess:
    def __init__(self, process_id: str, proc: subprocess.Popen[bytes], *, interactive: bool):
        self.process_id = process_id
        self.proc = proc
        self.interactive = interactive
        for stream in (self.proc.stdout, self.proc.stderr):
            if stream is not None:
                os.set_blocking(stream.fileno(), False)

    def status(self) -> dict[str, Any]:
        return {"process_id": self.process_id, "running": self.proc.poll() is None, "exit_code": self.proc.poll()}

    def read(self, *, wait_ms: int = 0, stdout_limit: int | None = None, stderr_limit: int | None = None) -> CommandResult:
        if self.proc.poll() is None and wait_ms > 0:
            deadline = time.monotonic() + wait_ms / 1000.0
            while time.monotonic() < deadline and not self._any_ready():
                if self.proc.poll() is not None:
                    break
                time.sleep(0.01)
        stdout = self._drain(self.proc.stdout, stdout_limit or 16 * 1024 * 1024)
        stderr = self._drain(self.proc.stderr, stderr_limit or 16 * 1024 * 1024)
        return CommandResult(
            exit_code=self.proc.poll(),
            stdout=stdout,
            stderr=stderr,
            stdout_truncated=False,
            stderr_truncated=False,
            raw=self.status(),
        )

    def write(self, data: bytes | str) -> dict[str, Any]:
        if self.proc.stdin is None or self.proc.stdin.closed:
            return {"ok": False, "error": "stdin_closed"}
        raw = _to_bytes(data) or b""
        self.proc.stdin.write(raw)
        self.proc.stdin.flush()
        return {"ok": True, "bytes": len(raw), "running": self.proc.poll() is None}

    def close_stdin(self) -> dict[str, Any]:
        if self.proc.stdin is None or self.proc.stdin.closed:
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
        self.close_streams()
        return self.status()

    def close_streams(self) -> None:
        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            if stream is not None:
                with contextlib.suppress(OSError):
                    stream.close()

    def _any_ready(self) -> bool:
        for stream in (self.proc.stdout, self.proc.stderr):
            if stream is None or stream.closed:
                continue
            try:
                readable, _, _ = select.select([stream], [], [], 0)
            except (OSError, ValueError):
                continue
            if readable:
                return True
        return False

    def _drain(self, stream: Any, limit: int) -> bytes:
        if stream is None or stream.closed or limit <= 0:
            return b""
        chunks: list[bytes] = []
        remaining = limit
        while remaining > 0:
            try:
                chunk = os.read(stream.fileno(), min(65536, remaining))
            except BlockingIOError:
                break
            except OSError:
                break
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)


def _import_phase6() -> Any:
    try:
        import firecracker_lumi_phase6 as phase6  # type: ignore
    except ImportError:
        repo_root = Path(__file__).resolve().parents[1]
        scripts = repo_root / "scripts"
        if str(scripts) not in sys.path:
            sys.path.insert(0, str(scripts))
        try:
            import firecracker_lumi_phase6 as phase6  # type: ignore
        except ImportError as exc:
            raise RuntimeError("LocalPool requires the Firecracker backend scripts to be importable") from exc
    return phase6


def _required_path(value: str | os.PathLike[str] | None, env_name: str, label: str) -> Path:
    raw = value or os.environ.get(env_name)
    if not raw:
        raise ValueError(
            f"LocalPool requires {label}. Pass {label}=... or set {env_name}. "
            "Run `python3 scripts/firecracker_prepare_artifacts.py --env-output .firecracker-env` "
            "to fetch/build the default artifacts."
        )
    path = Path(raw).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"{label} does not exist: {path}")
    return path


def _to_bytes(value: bytes | str | None) -> bytes | None:
    if value is None:
        return None
    return value if isinstance(value, bytes) else value.encode("utf-8")


def _kill_process_group(pid: int, sig: int) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(os.getpgid(pid), sig)
