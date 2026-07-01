#!/usr/bin/env python3
"""Benchmark 100 Firecracker sandboxes through the service API on LUMI."""

from __future__ import annotations

import argparse
import concurrent.futures
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
    out_dir = Path(args.return_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = out_dir / "firecracker-100-sandbox-benchmark.jsonl"
    json_path = out_dir / "firecracker-100-sandbox-benchmark.json"
    md_path = out_dir / "firecracker-100-sandbox-benchmark.md"
    service_log = out_dir / "firecracker-service.log"
    raw_path.unlink(missing_ok=True)

    rows: list[dict[str, Any]] = []
    proc: subprocess.Popen[str] | None = None
    assessment = "fail"
    failure_reason = None
    run_dir = Path(args.run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    lifecycle_start = time.perf_counter()

    try:
        proc = start_service(args, service_log)
        client = ServiceClient(f"http://127.0.0.1:{args.port}", timeout_s=args.http_timeout_s)
        wait_for_service(client, args.service_ready_timeout_s)

        pool_start = time.perf_counter()
        pool = client.create_pool(
            pool_id=args.pool_id,
            profile=args.profile,
            size=args.count,
            backend="firecracker",
            mem_mib=args.mem_mib,
            vcpus=args.vcpus,
        )
        pool_create_ms = elapsed_ms(pool_start)
        pool_status = client.request("GET", f"/v1/pools/{args.pool_id}")
        status = pool_status.get("status") or {}
        pool_ok = status.get("ready") == args.count and status.get("available") == args.count
        record(rows, raw_path, "pool_create", "pass" if pool_ok else "fail", elapsed_ms=pool_create_ms, response=pool_status)

        alloc_start = time.perf_counter()
        sandboxes = parallel(args.count, args.workers, lambda i: timed(lambda: pool.allocate()))
        allocate_wall_ms = elapsed_ms(alloc_start)
        alloc_rows = [{"index": i, **entry} for i, entry in enumerate(sandboxes)]
        for row in alloc_rows:
            record(rows, raw_path, "allocate_sandbox", "pass" if row.get("ok") else "fail", **without_obj(row))

        command = "python3 -c 'print(1)'"
        command_start = time.perf_counter()

        def run_command(entry: dict[str, Any]) -> dict[str, Any]:
            sandbox = entry["value"]
            return timed(lambda: sandbox.run(command, timeout_ms=args.command_timeout_ms))

        command_results = parallel_items(sandboxes, args.workers, run_command)
        command_wall_ms = elapsed_ms(command_start)
        for idx, row in enumerate(command_results):
            result = row.get("value")
            ok = bool(row.get("ok")) and result and result.exit_code == 0 and result.stdout.strip() == b"1"
            record(
                rows,
                raw_path,
                "python_command",
                "pass" if ok else "fail",
                index=idx,
                elapsed_ms=row.get("elapsed_ms"),
                exit_code=getattr(result, "exit_code", None),
                stdout_text=getattr(result, "stdout_text", "")[:200],
                error=row.get("error"),
            )

        release_start = time.perf_counter()

        def release_sandbox(entry: dict[str, Any]) -> dict[str, Any]:
            sandbox = entry["value"]
            return timed(lambda: sandbox.release(strategy="auto"))

        release_results = parallel_items(sandboxes, args.workers, release_sandbox)
        release_wall_ms = elapsed_ms(release_start)
        for idx, row in enumerate(release_results):
            record(
                rows,
                raw_path,
                "release_sandbox",
                "pass" if row.get("ok") else "fail",
                index=idx,
                elapsed_ms=row.get("elapsed_ms"),
                error=row.get("error"),
            )

        close_start = time.perf_counter()
        close_response = client.request("DELETE", f"/v1/pools/{args.pool_id}", {})
        close_ms = elapsed_ms(close_start)
        record(rows, raw_path, "pool_close", "pass" if close_response.get("ok") else "fail", elapsed_ms=close_ms, response=close_response)

        failures = [row for row in rows if row.get("classification") != "pass"]
        assessment = "pass" if not failures else "fail"
        failure_reason = None if not failures else f"{len(failures)} failed rows"

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
            "host": socket.gethostname(),
            "job": safe_slurm_snapshot(),
            "parameters": vars(args),
            "pool_create_wall_ms": pool_create_ms,
            "allocate_wall_ms": allocate_wall_ms,
            "python_command_wall_ms": command_wall_ms,
            "release_wall_ms": release_wall_ms,
            "pool_close_wall_ms": close_ms,
            "total_lifecycle_wall_ms": elapsed_ms(lifecycle_start),
            "allocate_latency_ms": summarize([row.get("elapsed_ms") for row in alloc_rows]),
            "python_command_latency_ms": summarize([row.get("elapsed_ms") for row in command_results]),
            "release_latency_ms": summarize([row.get("elapsed_ms") for row in release_results]),
            "runtime_dirs_before_cleanup": runtime_before_cleanup,
            "runtime_dirs_after_cleanup": runtime_after_cleanup,
            "cleanup_ok": cleanup_ok,
            "row_count": len(rows),
            "failure_count": len(failures),
            "artifacts": {
                "raw_jsonl": str(raw_path),
                "service_log": str(service_log),
            },
        }
    except Exception as exc:
        failure_reason = repr(exc)
        record(rows, raw_path, "benchmark_exception", "fail", error=repr(exc))
        summary = {
            "assessment": "fail",
            "failure_reason": failure_reason,
            "host": socket.gethostname(),
            "job": safe_slurm_snapshot(),
            "parameters": vars(args),
            "row_count": len(rows),
            "failure_count": 1,
        }
    finally:
        if proc is not None:
            terminate_service(proc)

    json_path.write_text(json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(summary), encoding="utf-8")
    return 0 if summary.get("assessment") == "pass" else 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a 100-sandbox Firecracker benchmark.")
    parser.add_argument("--firecracker", required=True)
    parser.add_argument("--kernel", required=True)
    parser.add_argument("--rootfs", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--return-dir", required=True)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--workers", type=int, default=100)
    parser.add_argument("--port", type=int, default=18766)
    parser.add_argument("--pool-id", default="benchmark100")
    parser.add_argument("--profile", default="python-coding")
    parser.add_argument("--mem-mib", type=int, default=768)
    parser.add_argument("--vcpus", type=int, default=1)
    parser.add_argument("--command-timeout-ms", type=int, default=10000)
    parser.add_argument("--http-timeout-s", type=float, default=600.0)
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
        str(args.count),
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
        proc.wait(timeout=20)
    except Exception:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            pass
        try:
            proc.wait(timeout=10)
        except Exception:
            pass


def parallel(count: int, workers: int, fn: Any) -> list[dict[str, Any]]:
    return parallel_items(list(range(count)), workers, fn)


def parallel_items(items: list[Any], workers: int, fn: Any) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = [None] * len(items)  # type: ignore[list-item]
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_idx = {executor.submit(fn, item): idx for idx, item in enumerate(items)}
        for future in concurrent.futures.as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception as exc:
                results[idx] = {"ok": False, "elapsed_ms": None, "error": repr(exc), "value": None}
    return results


def timed(fn: Any) -> dict[str, Any]:
    start = time.perf_counter()
    try:
        value = fn()
        return {"ok": True, "elapsed_ms": elapsed_ms(start), "value": value}
    except Exception as exc:
        return {"ok": False, "elapsed_ms": elapsed_ms(start), "error": repr(exc), "value": None}


def without_obj(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    out.pop("value", None)
    return out


def elapsed_ms(started: float) -> float:
    return (time.perf_counter() - started) * 1000.0


def percentile(values: list[float], p: float) -> float | None:
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    idx = min(len(vals) - 1, int(round((len(vals) - 1) * p)))
    return vals[idx]


def summarize(values: list[Any]) -> dict[str, Any]:
    vals = [float(v) for v in values if v is not None]
    if not vals:
        return {"n": 0, "p50_ms": None, "p90_ms": None, "p99_ms": None, "mean_ms": None, "max_ms": None}
    return {
        "n": len(vals),
        "p50_ms": percentile(vals, 0.50),
        "p90_ms": percentile(vals, 0.90),
        "p99_ms": percentile(vals, 0.99),
        "mean_ms": sum(vals) / len(vals),
        "max_ms": max(vals),
    }


def record(rows: list[dict[str, Any]], raw_path: Path, test_id: str, classification: str, **fields: Any) -> None:
    row = {"test_id": test_id, "classification": classification, "ts": time.time(), **fields}
    rows.append(row)
    with raw_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True, default=str) + "\n")


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


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Firecracker 100-Sandbox Benchmark",
        "",
        f"assessment: `{summary.get('assessment')}`",
        "",
        "## Wall Times",
        "",
        "| phase | ms |",
        "| --- | ---: |",
    ]
    for key in (
        "pool_create_wall_ms",
        "allocate_wall_ms",
        "python_command_wall_ms",
        "release_wall_ms",
        "pool_close_wall_ms",
        "total_lifecycle_wall_ms",
    ):
        lines.append(f"| `{key}` | `{fmt(summary.get(key))}` |")
    lines.extend(["", "## Latency Summaries", ""])
    for key in ("allocate_latency_ms", "python_command_latency_ms", "release_latency_ms"):
        lines.extend([
            f"### `{key}`",
            "",
            "```json",
            json.dumps(summary.get(key), indent=2, sort_keys=True),
            "```",
            "",
        ])
    lines.extend([
        "## Cleanup",
        "",
        f"- runtime dirs before cleanup: `{summary.get('runtime_dirs_before_cleanup')}`",
        f"- runtime dirs after cleanup: `{summary.get('runtime_dirs_after_cleanup')}`",
        f"- cleanup ok: `{summary.get('cleanup_ok')}`",
        f"- failure count: `{summary.get('failure_count')}`",
        "",
    ])
    return "\n".join(lines)


def fmt(value: Any) -> str:
    if isinstance(value, (float, int)):
        return f"{value:.3f}"
    return ""


if __name__ == "__main__":
    raise SystemExit(main())
