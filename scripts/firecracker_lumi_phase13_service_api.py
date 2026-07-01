#!/usr/bin/env python3
"""Phase 13 real-service API smoke for the LUMI Firecracker backend."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from firecracker_rl_sandbox import ServiceClient


def main() -> int:
    args = parse_args()
    return_dir = Path(args.return_dir)
    return_dir.mkdir(parents=True, exist_ok=True)
    raw_path = return_dir / "firecracker-service-api-smoke.jsonl"
    json_path = return_dir / "firecracker-service-api-smoke.json"
    md_path = return_dir / "firecracker-service-api-smoke.md"
    service_log = return_dir / "firecracker-service.log"
    if raw_path.exists():
        raw_path.unlink()

    run_dir = Path(args.run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    proc: subprocess.Popen[str] | None = None
    assessment = "fail"
    failure_reason = None

    try:
        proc = start_service(args, service_log)
        client = ServiceClient(f"http://127.0.0.1:{args.port}", timeout_s=args.http_timeout_s)
        wait_for_service(client, args.service_ready_timeout_s)

        record(rows, raw_path, "service.healthz", "pass", response=client.healthz())

        pool_id = args.pool_id
        started = time.perf_counter()
        pool = client.create_pool(
            pool_id=pool_id,
            profile=args.profile,
            size=args.pool_size,
            backend="firecracker",
            mem_mib=args.mem_mib,
            vcpus=args.vcpus,
        )
        pool_create_ms = elapsed_ms(started)
        pool_status = client.request("GET", f"/v1/pools/{pool_id}")
        pool_ok = (
            pool_status.get("status", {}).get("ready") == args.pool_size
            and not pool_status.get("status", {}).get("boot_errors")
        )
        record(
            rows,
            raw_path,
            "pool.create",
            "pass" if pool_ok else "fail",
            elapsed_ms=pool_create_ms,
            response=pool_status,
        )
        record(rows, raw_path, "service.readyz", "pass", response=client.readyz())

        with pool.allocate(task_id="phase13-basic") as sandbox:
            run_and_record(rows, raw_path, sandbox, "command.echo", "echo service-ready")
            run_and_record(rows, raw_path, sandbox, "command.python", "python3 -c 'print(1 + 1)'")
            run_and_record(rows, raw_path, sandbox, "command.pytest", "python3 -m pytest -q tests", timeout_ms=60000)
            run_and_record(rows, raw_path, sandbox, "workspace.mutate", "echo dirty > phase13-marker && test -f phase13-marker")
            release_resp = sandbox.release(strategy="auto")
            record(rows, raw_path, "sandbox.release.auto", "pass" if release_resp.get("ok") else "fail", response=release_resp)

        with pool.allocate(task_id="phase13-cleanliness") as sandbox:
            result = sandbox.run("test ! -e phase13-marker && test -f tests/test_sample.py && echo clean", timeout_ms=10000)
            record_result(rows, raw_path, "workspace.clean_after_release", result)
            release_resp = sandbox.release(strategy="auto")
            record(rows, raw_path, "sandbox.release.cleanliness", "pass" if release_resp.get("ok") else "fail", response=release_resp)

        with pool.allocate(task_id="phase13-process") as sandbox:
            process_started = time.perf_counter()
            proc_handle = sandbox.start_process("python3 -u -c 'print(123, flush=True); import time; time.sleep(30)'")
            start_ms = elapsed_ms(process_started)
            read_result = proc_handle.read(wait_ms=1000)
            read_ok = read_result.stdout.strip() == b"123"
            record_result(rows, raw_path, "process.read_stdout", read_result, classification="pass" if read_ok else "fail", elapsed_ms=start_ms)
            cancel_resp = proc_handle.cancel()
            record(rows, raw_path, "process.cancel", "pass" if cancel_resp.get("ok", True) else "fail", response=cancel_resp)
            release_resp = sandbox.release(strategy="hard")
            record(rows, raw_path, "sandbox.release.hard", "pass" if release_resp.get("ok") else "fail", response=release_resp)

        metrics_text = client.request("GET", "/varz")
        record(rows, raw_path, "service.varz", "pass", response=metrics_text)
        pool_close = client.request("DELETE", f"/v1/pools/{pool_id}", {})
        record(rows, raw_path, "pool.close", "pass" if pool_close.get("ok") else "fail", response=pool_close)

        failures = [row for row in rows if row.get("classification") != "pass"]
        assessment = "pass" if not failures else "fail"
        failure_reason = None if not failures else f"{len(failures)} failing rows"
    except Exception as exc:
        failure_reason = repr(exc)
        record(rows, raw_path, "phase13.exception", "fail", error=repr(exc))
    finally:
        if proc is not None:
            terminate_service(proc)
        runtime_before_cleanup = count_runtime_dirs(run_dir)
        cleanup_ok = True
        if args.cleanup_run_dir:
            try:
                shutil.rmtree(run_dir, ignore_errors=True)
            except Exception:
                cleanup_ok = False
        runtime_after_cleanup = count_runtime_dirs(run_dir)

        summary = {
            "assessment": assessment,
            "failure_reason": failure_reason,
            "job": safe_slurm_snapshot(),
            "host": socket.gethostname(),
            "parameters": {
                "pool_id": args.pool_id,
                "pool_size": args.pool_size,
                "profile": args.profile,
                "mem_mib": args.mem_mib,
                "vcpus": args.vcpus,
                "port": args.port,
                "cleanup_run_dir": args.cleanup_run_dir,
            },
            "artifacts": {
                "raw_jsonl": str(raw_path),
                "service_log": str(service_log),
            },
            "runtime_dirs_before_cleanup": runtime_before_cleanup,
            "runtime_dirs_after_cleanup": runtime_after_cleanup,
            "cleanup_ok": cleanup_ok,
            "row_count": len(rows),
            "failures": [row for row in rows if row.get("classification") != "pass"],
        }
        json_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        md_path.write_text(render_markdown(summary, rows), encoding="utf-8")

    return 0 if assessment == "pass" else 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Phase 13 real Firecracker service API smoke.")
    parser.add_argument("--firecracker", required=True)
    parser.add_argument("--kernel", required=True)
    parser.add_argument("--rootfs", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--return-dir", required=True)
    parser.add_argument("--port", type=int, default=18765)
    parser.add_argument("--pool-id", default="phase13")
    parser.add_argument("--profile", default="python-coding")
    parser.add_argument("--pool-size", type=int, default=2)
    parser.add_argument("--mem-mib", type=int, default=768)
    parser.add_argument("--vcpus", type=int, default=1)
    parser.add_argument("--http-timeout-s", type=float, default=300.0)
    parser.add_argument("--service-ready-timeout-s", type=float, default=60.0)
    parser.add_argument("--cleanup-run-dir", action=argparse.BooleanOptionalAction, default=True)
    return parser.parse_args()


def start_service(args: argparse.Namespace, log_path: Path) -> subprocess.Popen[str]:
    env = dict(os.environ)
    root = Path.cwd()
    env["PYTHONPATH"] = f"{root}:{root / 'scripts'}:{env.get('PYTHONPATH', '')}"
    cmd = [
        sys.executable,
        "scripts/firecracker_pool_service.py",
        "--backend",
        "firecracker",
        "--listen",
        f"127.0.0.1:{args.port}",
        "--pool-size",
        str(args.pool_size),
        "--firecracker",
        args.firecracker,
        "--kernel",
        args.kernel,
        "--rootfs",
        args.rootfs,
        "--run-dir",
        args.run_dir,
        "--mem-mib",
        str(args.mem_mib),
        "--vcpus",
        str(args.vcpus),
        "--quiet",
    ]
    handle = log_path.open("w", encoding="utf-8")
    proc = subprocess.Popen(cmd, stdout=handle, stderr=subprocess.STDOUT, text=True, env=env, start_new_session=True)
    # The child owns the file descriptor now; closing the parent copy prevents
    # leaked handles without interrupting child logging.
    handle.close()
    return proc


def wait_for_service(client: ServiceClient, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            if client.healthz().get("ok"):
                return
        except Exception as exc:
            last_error = exc
        time.sleep(0.25)
    raise TimeoutError(f"service did not become healthy: {last_error!r}")


def terminate_service(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=10)
    except Exception:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass


def run_and_record(rows: list[dict[str, Any]], raw_path: Path, sandbox: Any, test_id: str, command: str, timeout_ms: int = 10000) -> None:
    result = sandbox.run(command, timeout_ms=timeout_ms)
    record_result(rows, raw_path, test_id, result, command=command)


def record_result(
    rows: list[dict[str, Any]],
    raw_path: Path,
    test_id: str,
    result: Any,
    *,
    command: str | None = None,
    classification: str | None = None,
    elapsed_ms: float | None = None,
) -> None:
    raw = result.raw or {}
    row = {
        "test_id": test_id,
        "classification": classification or ("pass" if result.exit_code == 0 and not result.timeout else "fail"),
        "command": command,
        "exit_code": result.exit_code,
        "stdout_text": result.stdout_text[:2000],
        "stderr_text": result.stderr_text[:2000],
        "stdout_bytes": len(result.stdout),
        "stderr_bytes": len(result.stderr),
        "stdout_blocked": result.stdout_blocked,
        "stderr_blocked": result.stderr_blocked,
        "stdout_truncated": result.stdout_truncated,
        "stderr_truncated": result.stderr_truncated,
        "timeout": result.timeout,
        "elapsed_ms": elapsed_ms if elapsed_ms is not None else result.elapsed_ms,
        "raw": compact(raw),
    }
    record(rows, raw_path, **row)


def record(rows: list[dict[str, Any]], raw_path: Path, test_id: str, classification: str, **fields: Any) -> None:
    row = {
        "test_id": test_id,
        "classification": classification,
        "ts": time.time(),
        **fields,
    }
    rows.append(row)
    with raw_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def compact(value: Any) -> Any:
    text = json.dumps(value, sort_keys=True, default=str)
    if len(text) <= 4000:
        return value
    return {"compact_json_prefix": text[:4000], "truncated": True}


def elapsed_ms(started: float) -> float:
    return (time.perf_counter() - started) * 1000.0


def count_runtime_dirs(run_dir: Path) -> int:
    if not run_dir.exists():
        return 0
    return sum(1 for path in run_dir.glob("vm-*") if path.exists())


def safe_slurm_snapshot() -> dict[str, str]:
    keys = [
        "SLURM_JOB_ID",
        "SLURM_JOB_NAME",
        "SLURM_JOB_NODELIST",
        "SLURM_JOB_NUM_NODES",
        "SLURM_CPUS_ON_NODE",
        "SLURM_CPUS_PER_TASK",
        "SLURM_MEM_PER_NODE",
        "SLURM_PARTITION",
        "SLURM_ACCOUNT",
    ]
    return {key: os.environ[key] for key in keys if key in os.environ}


def render_markdown(summary: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    lines = [
        "# Firecracker LUMI Phase 13 Service API Smoke",
        "",
        f"assessment: `{summary['assessment']}`",
        "",
        "## Parameters",
        "",
        "| field | value |",
        "| --- | --- |",
    ]
    for key, value in summary["parameters"].items():
        lines.append(f"| `{key}` | `{value}` |")
    lines.extend(
        [
            "",
            "## Runtime Cleanup",
            "",
            f"- runtime dirs before cleanup: `{summary['runtime_dirs_before_cleanup']}`",
            f"- runtime dirs after cleanup: `{summary['runtime_dirs_after_cleanup']}`",
            f"- cleanup ok: `{summary['cleanup_ok']}`",
            "",
            "## Checks",
            "",
            "| test | result | exit | elapsed ms | notes |",
            "| --- | --- | ---: | ---: | --- |",
        ]
    )
    for row in rows:
        notes = ""
        if row.get("error"):
            notes = str(row["error"])
        elif row.get("stdout_text"):
            notes = str(row["stdout_text"]).replace("\n", "\\n")[:120]
        lines.append(
            "| `{}` | `{}` | `{}` | `{}` | {} |".format(
                row.get("test_id"),
                row.get("classification"),
                row.get("exit_code", ""),
                fmt(row.get("elapsed_ms")),
                notes,
            )
        )
    if summary.get("failures"):
        lines.extend(["", "## Failures", ""])
        for failure in summary["failures"]:
            lines.append(f"- `{failure.get('test_id')}`: `{failure.get('classification')}`")
    return "\n".join(lines) + "\n"


def fmt(value: Any) -> str:
    if isinstance(value, (int, float)):
        return f"{value:.3f}"
    return ""


if __name__ == "__main__":
    raise SystemExit(main())
