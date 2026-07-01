#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import threading
import time
from pathlib import Path

import firecracker_lumi_phase5 as phase5
from firecracker_lumi_bench import download_firecracker, host_snapshot, mkdir
from firecracker_lumi_phase4 import log
from firecracker_lumi_phase6 import redact_file, safe_slurm_snapshot
from firecracker_pool_service import Handler, JsonServer, PoolService, b64decode, http_json


def write_json(path, payload):
    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--kernel-path", required=True)
    ap.add_argument("--artifact-cache-dir", required=True)
    ap.add_argument("--rootfs-cache-dir", required=True)
    ap.add_argument("--phase6-mvp-dir", required=True)
    ap.add_argument("--return-dir", required=True)
    ap.add_argument("--mem-mib", type=int, default=768)
    ap.add_argument("--vcpus", type=int, default=1)
    ap.add_argument("--pool-size", type=int, default=2)
    args = ap.parse_args()

    job_id = os.environ.get("SLURM_JOB_ID", "local")
    reports_dir = Path("reports")
    mkdir(reports_dir)
    mkdir(args.run_dir)
    return_dir = Path(args.return_dir)
    mkdir(return_dir)
    result = {
        "phase": 10,
        "assessment": "fail",
        "host": host_snapshot(),
        "slurm": safe_slurm_snapshot(),
        "args": vars(args),
        "steps": [],
        "errors": [],
    }
    server = None
    thread = None
    try:
        log("phase10 preparing artifacts")
        fc = download_firecracker(Path(args.artifact_cache_dir) / "firecracker")
        workspace_template = Path(args.phase6_mvp_dir) / "workspaces" / "fixtures" / "mvp"
        rootfs = phase5.prepare_rootfs(args.rootfs_cache_dir, args.artifact_cache_dir, {}, workspace_template)
        result["artifacts"] = {
            "firecracker": fc,
            "kernel": {"path": args.kernel_path, "bytes": Path(args.kernel_path).stat().st_size},
            "rootfs": rootfs,
        }

        service_args = argparse.Namespace(
            backend="firecracker",
            pool_size=args.pool_size,
            firecracker=fc["path"],
            kernel=args.kernel_path,
            rootfs=rootfs["path"],
            run_dir=args.run_dir,
            mem_mib=args.mem_mib,
            vcpus=args.vcpus,
        )
        service = PoolService(service_args)
        server = JsonServer(("127.0.0.1", 0), Handler, service, auth_token=None, quiet=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address
        result["service"] = {"listen": "{}:{}".format(host, port), "backend": "firecracker"}

        def call(label, method, path, payload):
            started = time.perf_counter()
            resp = http_json(host, port, method, path, payload)
            row = {
                "label": label,
                "method": method,
                "path": path,
                "elapsed_ms": (time.perf_counter() - started) * 1000.0,
                "response": resp,
                "classification": "pass",
            }
            result["steps"].append(row)
            return resp

        pool = call("create_pool", "POST", "/v1/pools", {"pool_id": "phase10", "size": args.pool_size, "backend": "firecracker", "profile": "python-coding"})
        session = call("create_session", "POST", "/v1/sessions", {"pool_id": "phase10", "task_id": "phase10-smoke", "queue_timeout_ms": 30000})
        sid = session["session_id"]
        echo = call("run_echo", "POST", "/v1/sessions/{}/run".format(sid), {"command": "bash -lc 'echo service-ready'", "timeout_ms": 10000})
        pytest = call("run_pytest", "POST", "/v1/sessions/{}/run".format(sid), {"command": "bash -lc 'python3 -m pytest tests'", "timeout_ms": 60000})
        proc = call("process_start", "POST", "/v1/sessions/{}/processes".format(sid), {"command": "python3 -u -c 'print(\"proc-ready\", flush=True); import time; time.sleep(30)'"})
        handle = proc["handle"]
        read = call("process_read", "POST", "/v1/sessions/{}/processes/{}/read".format(sid, handle), {"wait_ms": 1000})
        term = call("process_terminate", "POST", "/v1/sessions/{}/processes/{}/terminate".format(sid, handle), {})
        reset = call("reset", "POST", "/v1/sessions/{}/reset".format(sid), {})
        close_session = call("close_session", "DELETE", "/v1/sessions/{}".format(sid), {})
        close_pool = call("close_pool", "DELETE", "/v1/pools/phase10", {})

        checks = {
            "pool_ready": pool.get("status", {}).get("ready") == args.pool_size,
            "echo": echo.get("exit_code") == 0 and b"service-ready" in b64decode(echo.get("stdout_b64")),
            "pytest": pytest.get("exit_code") == 0,
            "process_read": b"proc-ready" in b64decode(read.get("stdout_b64")),
            "process_terminate": bool(term.get("ok")),
            "reset": bool(reset.get("ok")),
            "close_session": bool(close_session.get("ok")),
            "close_pool": bool(close_pool.get("ok")),
        }
        result["checks"] = checks
        result["assessment"] = "pass" if all(checks.values()) else "fail"
    except Exception as exc:
        result["errors"].append(repr(exc))
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=10)
        run_dir = Path(args.run_dir)
        for path in run_dir.glob("vm-*"):
            shutil.rmtree(str(path), ignore_errors=True)
        result["runtime_dirs_remaining_after_cleanup"] = len(list(run_dir.glob("vm-*"))) if run_dir.exists() else 0
        result["host_after"] = host_snapshot()

        json_path = reports_dir / "firecracker-lumi-phase10-{}-service-smoke.json".format(job_id)
        md_path = reports_dir / "firecracker-lumi-phase10-{}-service-smoke.md".format(job_id)
        write_json(json_path, result)
        md = [
            "# Firecracker LUMI Phase 10 Service Smoke",
            "",
            "- Job: `{}`".format(job_id),
            "- Assessment: `{}`".format(result["assessment"]),
            "- Runtime dirs remaining after cleanup: `{}`".format(result.get("runtime_dirs_remaining_after_cleanup")),
            "",
            "## Checks",
            "",
            "| check | pass |",
            "| --- | --- |",
        ]
        for key, value in sorted((result.get("checks") or {}).items()):
            md.append("| `{}` | `{}` |".format(key, value))
        md.extend([
            "",
            "## Next Work",
            "",
            "The service smoke validates the API path against real Firecracker VMs. Remaining production work is unhealthy-slot replacement, admission control, periodic health checks, Unix-socket listener support, and RL/eval integration.",
        ])
        md_path.write_text("\n".join(md) + "\n", encoding="utf-8")
        for src in [json_path, md_path, Path("scripts/firecracker_pool_service.py"), Path(__file__), Path(__file__).with_suffix(".sbatch"), Path("docs/firecracker-pool-service.md")]:
            if src.exists():
                dest = return_dir / src.name
                shutil.copy2(str(src), str(dest))
                redact_file(dest)
        (return_dir / "README.md").write_text(
            "\n".join([
                "# Firecracker LUMI Phase 10 Service Hardening Status",
                "",
                "Date: 2026-07-01",
                "",
                "assessment: `{}`".format(result["assessment"]),
                "",
                "This handoff contains the node-local pool service prototype and a real LUMI Firecracker service smoke run.",
                "",
                "Next phase work for the other agent:",
                "",
                "- Build RL/eval framework integration against the service API.",
                "- Add unhealthy VM replacement for guest-agent death, especially stdout/stderr flood cases found in Phase 8.",
                "- Add admission control and periodic health checks.",
                "- Add Unix-socket listener support and allocation-local auth policy.",
            ]) + "\n",
            encoding="utf-8",
        )
        print(json.dumps({"assessment": result["assessment"], "return_dir": str(return_dir), "errors": result["errors"]}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
