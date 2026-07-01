from __future__ import annotations

import base64
import http.client
import json
import urllib.parse
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CommandResult:
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timeout: bool = False
    stdout_blocked: bool = False
    stderr_blocked: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    elapsed_ms: float | None = None
    raw: dict[str, Any] | None = None

    @property
    def stdout_text(self) -> str:
        return self.stdout.decode("utf-8", "replace")

    @property
    def stderr_text(self) -> str:
        return self.stderr.decode("utf-8", "replace")

    @classmethod
    def from_response(cls, response: dict[str, Any]) -> "CommandResult":
        return cls(
            exit_code=response.get("exit_code"),
            stdout=_b64decode(response.get("stdout_b64")),
            stderr=_b64decode(response.get("stderr_b64")),
            timeout=bool(response.get("timeout")),
            stdout_blocked=bool(response.get("stdout_blocked")),
            stderr_blocked=bool(response.get("stderr_blocked")),
            stdout_truncated=bool(response.get("stdout_truncated")),
            stderr_truncated=bool(response.get("stderr_truncated")),
            elapsed_ms=response.get("command_roundtrip_ms") or response.get("elapsed_ms"),
            raw=response,
        )


class ServiceClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8765", *, token: str | None = None, timeout_s: float = 30.0):
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in {"http", ""}:
            raise ValueError("only http service URLs are supported by the prototype client")
        self.host = parsed.hostname or "127.0.0.1"
        self.port = parsed.port or 8765
        self.token = token
        self.timeout_s = timeout_s

    def create_pool(
        self,
        *,
        pool_id: str = "default",
        profile: str = "python-coding",
        size: int = 1,
        backend: str | None = None,
        mem_mib: int | None = None,
        vcpus: int | None = None,
        network: str | None = None,
    ) -> "ServicePool":
        payload: dict[str, Any] = {"pool_id": pool_id, "profile": profile, "size": size}
        if backend is not None:
            payload["backend"] = backend
        if mem_mib is not None:
            payload["mem_mib"] = mem_mib
        if vcpus is not None:
            payload["vcpus"] = vcpus
        if network is not None:
            payload["network"] = network
        self.request("POST", "/v1/pools", payload)
        return ServicePool(self, pool_id=pool_id, profile=profile)

    def pool(self, pool_id: str = "default", *, profile: str = "python-coding") -> "ServicePool":
        return ServicePool(self, pool_id=pool_id, profile=profile)

    def healthz(self) -> dict[str, Any]:
        return self.request("GET", "/healthz")

    def readyz(self) -> dict[str, Any]:
        return self.request("GET", "/readyz")

    def varz(self) -> dict[str, Any]:
        return self.request("GET", "/varz")

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        body = json.dumps(payload or {}).encode("utf-8") if method != "GET" or payload else b""
        headers = {"content-type": "application/json"}
        if self.token:
            headers["authorization"] = "Bearer " + self.token
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout_s)
        try:
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            data = response.read()
        finally:
            conn.close()
        try:
            decoded = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError:
            decoded = {"raw": data.decode("utf-8", "replace")}
        if response.status >= 400:
            raise RuntimeError({"status": response.status, "response": decoded})
        if not isinstance(decoded, dict):
            raise RuntimeError({"status": response.status, "response": decoded})
        return decoded


class ServicePool:
    def __init__(self, client: ServiceClient, *, pool_id: str, profile: str):
        self.client = client
        self.pool_id = pool_id
        self.profile = profile

    def allocate(self, *, task_id: str | None = None, queue_timeout_ms: int = 30000) -> "Sandbox":
        payload: dict[str, Any] = {"pool_id": self.pool_id, "profile": self.profile, "queue_timeout_ms": queue_timeout_ms}
        if task_id is not None:
            payload["task_id"] = task_id
        response = self.client.request(
            "POST",
            "/v1/sandboxes",
            payload,
        )
        return Sandbox(self.client, response["sandbox_id"], pool_id=self.pool_id, profile=self.profile)


class Sandbox:
    def __init__(self, client: ServiceClient, sandbox_id: str, *, pool_id: str, profile: str):
        self.client = client
        self.sandbox_id = sandbox_id
        self.pool_id = pool_id
        self.profile = profile
        self.released = False

    def __enter__(self) -> "Sandbox":
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
        payload: dict[str, Any] = {
            "command": command,
            "cwd": cwd,
            "env": env or {},
            "timeout_ms": timeout_ms,
        }
        if stdin is not None:
            payload["stdin_b64"] = _b64encode(_to_bytes(stdin))
        if stdout_limit is not None:
            payload["stdout_limit"] = stdout_limit
        if stderr_limit is not None:
            payload["stderr_limit"] = stderr_limit
        response = self.client.request("POST", f"/v1/sandboxes/{self.sandbox_id}/run", payload)
        return CommandResult.from_response(response)

    def start_process(
        self,
        command: str,
        *,
        cwd: str = "/workspace",
        env: dict[str, str] | None = None,
        interactive: bool = False,
    ) -> "ProcessHandle":
        response = self.client.request(
            "POST",
            f"/v1/sandboxes/{self.sandbox_id}/processes",
            {"command": command, "cwd": cwd, "env": env or {}, "interactive": interactive},
        )
        process_id = response.get("process_id") or response.get("handle")
        if not process_id:
            raise RuntimeError({"missing_process_id": response})
        return ProcessHandle(self, str(process_id))

    def release(self, *, strategy: str = "auto") -> dict[str, Any]:
        if self.released:
            return {"ok": True, "already_released": True}
        response = self.client.request("POST", f"/v1/sandboxes/{self.sandbox_id}/release", {"strategy": strategy})
        self.released = True
        return response


class ProcessHandle:
    def __init__(self, sandbox: Sandbox, process_id: str):
        self.sandbox = sandbox
        self.process_id = process_id

    def status(self) -> dict[str, Any]:
        return self.sandbox.client.request(
            "POST",
            f"/v1/sandboxes/{self.sandbox.sandbox_id}/processes/{self.process_id}/status",
            {},
        )

    def read(self, *, wait_ms: int = 0, stdout_limit: int | None = None, stderr_limit: int | None = None) -> CommandResult:
        payload: dict[str, Any] = {"wait_ms": wait_ms}
        if stdout_limit is not None:
            payload["stdout_limit"] = stdout_limit
        if stderr_limit is not None:
            payload["stderr_limit"] = stderr_limit
        response = self.sandbox.client.request(
            "POST",
            f"/v1/sandboxes/{self.sandbox.sandbox_id}/processes/{self.process_id}/read",
            payload,
        )
        return CommandResult.from_response(response)

    def write(self, data: bytes | str) -> dict[str, Any]:
        return self.sandbox.client.request(
            "POST",
            f"/v1/sandboxes/{self.sandbox.sandbox_id}/processes/{self.process_id}/write",
            {"stdin_b64": _b64encode(_to_bytes(data))},
        )

    def close_stdin(self) -> dict[str, Any]:
        return self.sandbox.client.request(
            "POST",
            f"/v1/sandboxes/{self.sandbox.sandbox_id}/processes/{self.process_id}/close_stdin",
            {},
        )

    def cancel(self, *, signal_number: int = 15) -> dict[str, Any]:
        return self.sandbox.client.request(
            "POST",
            f"/v1/sandboxes/{self.sandbox.sandbox_id}/processes/{self.process_id}/cancel",
            {"signal": signal_number},
        )


def _to_bytes(value: bytes | str) -> bytes:
    return value if isinstance(value, bytes) else value.encode("utf-8")


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: Any) -> bytes:
    if not value:
        return b""
    return base64.b64decode(str(value).encode("ascii"))
