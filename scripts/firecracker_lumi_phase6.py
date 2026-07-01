#!/usr/bin/env python3
import argparse
import base64
import collections
import contextlib
import fnmatch
import hashlib
import json
import os
import queue
import re
import shutil
import stat
import threading
import time
from pathlib import Path, PurePosixPath

import firecracker_lumi_phase5 as phase5
from firecracker_lumi_bench import (
    download_firecracker,
    host_snapshot,
    mkdir,
    ms_since,
    now_ns,
    proc_rss_kb,
    read_text,
)
from firecracker_lumi_phase4 import Phase4VM, log


TRACE_NAME = "agenttrove-strict-safe-100"
PHASE6_PROFILE = "firecracker-phase6"
PHASE6_RUNNER = "firecracker"
DEFAULT_STDIO_LIMIT = 16 * 1024 * 1024
SECRET_KEY_RE = re.compile(
    r"(api[_-]?key|token|secret|password|passwd|credential|authorization|bearer|private[_-]?key)",
    re.IGNORECASE,
)
SECRET_VALUE_RE = re.compile(
    r"(?i)(sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{16,}|"
    r"xox[baprs]-[A-Za-z0-9-]{16,}|AKIA[0-9A-Z]{16}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
NATIVE_WORKSPACE_RE = re.compile(
    r"/tmp/wasm-terminal-trace-(?:baseline|candidate)-[^/\s]+/workspace"
)


def b64(data):
    return base64.b64encode(data or b"").decode("ascii")


def unb64(text):
    return base64.b64decode(text.encode("ascii")) if text else b""


def sha256_bytes(data):
    return hashlib.sha256(data or b"").hexdigest()


def decode_text(data):
    if isinstance(data, str):
        return data
    return (data or b"").decode("utf-8", "replace")


def compact_text(data, limit=2000):
    return decode_text(data)[:limit]


def read_jsonl(path):
    rows = []
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def write_jsonl(path, row):
    with Path(path).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def percentile(values, p):
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    idx = min(len(vals) - 1, int(round((len(vals) - 1) * p)))
    return vals[idx]


def summarize(values):
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return {"n": 0, "p50_ms": None, "p90_ms": None, "p99_ms": None, "mean_ms": None, "max_ms": None}
    return {
        "n": len(vals),
        "p50_ms": percentile(vals, 0.5),
        "p90_ms": percentile(vals, 0.9),
        "p99_ms": percentile(vals, 0.99),
        "mean_ms": sum(vals) / len(vals),
        "max_ms": vals[-1],
    }


def safe_slurm_snapshot():
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
        "SLURM_SUBMIT_DIR",
    ]
    return {key: os.environ.get(key) for key in keys if os.environ.get(key) is not None}


def redact_value(value, key=""):
    if SECRET_KEY_RE.search(str(key)):
        if value not in (None, "", [], {}):
            return "<redacted>"
        return value
    if isinstance(value, dict):
        return {k: redact_value(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(item, key) for item in value]
    if isinstance(value, str):
        return SECRET_VALUE_RE.sub("<redacted>", value)
    return value


def redact_file(path):
    path = Path(path)
    if not path.exists():
        return
    if path.suffix in (".json", ".jsonl"):
        lines = []
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    lines.append(json.dumps(redact_value(json.loads(line)), sort_keys=True))
                except json.JSONDecodeError:
                    lines.append(SECRET_VALUE_RE.sub("<redacted>", line.rstrip("\n")))
        if path.suffix == ".json":
            try:
                obj = json.loads(path.read_text(encoding="utf-8"))
                path.write_text(json.dumps(redact_value(obj), indent=2, sort_keys=True) + "\n", encoding="utf-8")
                return
            except json.JSONDecodeError:
                pass
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    path.write_text(SECRET_VALUE_RE.sub("<redacted>", text), encoding="utf-8")


def cgroup_memory_current():
    text = read_text("/sys/fs/cgroup/memory.current").strip()
    try:
        return int(text)
    except Exception:
        return None


def current_fd_count():
    try:
        return len(os.listdir("/proc/self/fd"))
    except Exception:
        return None


def current_pids_count():
    try:
        return len([name for name in os.listdir("/proc") if name.isdigit()])
    except Exception:
        return None


def resp_stdio(resp):
    stdout_bytes = unb64(resp.get("stdout_b64", ""))
    stderr_bytes = unb64(resp.get("stderr_b64", ""))
    return stdout_bytes, stderr_bytes


def benchmark_row(test_id, category, command=None, resp=None, **extra):
    resp = resp or {}
    stdout, stderr = resp_stdio(resp)
    stdout_full = resp.get("stdout_bytes_full", len(stdout))
    stderr_full = resp.get("stderr_bytes_full", len(stderr))
    row = {
        "test_id": test_id,
        "category": category,
        "backend": "firecracker",
        "transport": "vsock-jsonl",
        "profile": extra.pop("profile", PHASE6_PROFILE),
        "pool_id": extra.pop("pool_id", None),
        "session_id": extra.pop("session_id", None),
        "vm_id": extra.pop("vm_id", None),
        "command": command,
        "exit_code": resp.get("exit_code"),
        "expected_exit_code": extra.pop("expected_exit_code", None),
        "classification": extra.pop(
            "classification",
            "pass" if resp.get("ok", False) and resp.get("exit_code", 0) == 0 and not resp.get("timeout") else "fail",
        ),
        "elapsed_ms": resp.get("command_roundtrip_ms"),
        "guest_process_ms": resp.get("guest_process_ms"),
        "queue_wait_ms": extra.pop("queue_wait_ms", None),
        "session_acquire_ms": extra.pop("session_acquire_ms", None),
        "reset_mode": extra.pop("reset_mode", None),
        "reset_request_ms": extra.pop("reset_request_ms", None),
        "post_reset_validation_ms": extra.pop("post_reset_validation_ms", None),
        "total_recycle_ready_ms": extra.pop("total_recycle_ready_ms", None),
        "stdout_bytes": stdout_full,
        "stderr_bytes": stderr_full,
        "stdout_excerpt": compact_text(stdout, 2000),
        "stderr_excerpt": compact_text(stderr, 2000),
        "stdout_truncated": resp.get("stdout_truncated", False),
        "stderr_truncated": resp.get("stderr_truncated", False),
        "timeout": resp.get("timeout", False),
        "kill_reason": resp.get("kill_reason"),
        "guest_memory_mb": extra.pop("guest_memory_mb", None),
        "host_rss_kb": extra.pop("host_rss_kb", None),
        "cgroup_memory_current": extra.pop("cgroup_memory_current", None),
        "pids_current": extra.pop("pids_current", None),
        "fd_count": extra.pop("fd_count", None),
        "agent_survived": extra.pop("agent_survived", None),
        "vm_survived": extra.pop("vm_survived", None),
        "notes": extra.pop("notes", ""),
    }
    row.update(extra)
    return row


class Session:
    def __init__(self, pool, slot, session_id, queue_wait_ms):
        self.pool = pool
        self.slot = slot
        self.session_id = session_id
        self.queue_wait_ms = queue_wait_ms
        self.released = False

    @property
    def vm(self):
        return self.slot["vm"]

    @property
    def vm_id(self):
        return self.slot["vm"].vm_id

    def run(self, command, timeout=10, cwd="/workspace", env=None, stdin=b"", stdout_limit=DEFAULT_STDIO_LIMIT, stderr_limit=DEFAULT_STDIO_LIMIT):
        timeout_ms = int(timeout * 1000) if isinstance(timeout, float) else int(timeout) * 1000
        return self.vm.agent.request(
            "run",
            command=command,
            timeout_ms=timeout_ms,
            cwd=cwd,
            env=env or {},
            stdin_b64=b64(stdin),
            stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
        )

    def run_ms(self, command, timeout_ms=10000, cwd="/workspace", env=None, stdin=b"", stdout_limit=DEFAULT_STDIO_LIMIT, stderr_limit=DEFAULT_STDIO_LIMIT):
        return self.vm.agent.request(
            "run",
            command=command,
            timeout_ms=int(timeout_ms),
            cwd=cwd,
            env=env or {},
            stdin_b64=b64(stdin),
            stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
        )

    def start(self, command, cwd="/workspace", env=None):
        return self.vm.agent.request("process/start", command=command, cwd=cwd, env=env or {})

    def read(self, handle, wait_ms=0, stdout_limit=DEFAULT_STDIO_LIMIT, stderr_limit=DEFAULT_STDIO_LIMIT):
        return self.vm.agent.request(
            "process/read",
            handle=handle,
            wait_ms=int(wait_ms),
            stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
        )

    def write(self, handle, data):
        return self.vm.agent.request("process/write", handle=handle, stdin_b64=b64(data))

    def close_stdin(self, handle):
        return self.vm.agent.request("process/close_stdin", handle=handle)

    def process_status(self, handle):
        return self.vm.agent.request("process/status", handle=handle)

    def terminate(self, handle, signal_number=15):
        return self.vm.agent.request("process/terminate", handle=handle, signal=signal_number)

    def health(self):
        return self.vm.agent.request("health")

    def reset(self, validate=True):
        return self.pool.reset_session(self, validate=validate)

    def release(self, reset=True):
        if self.released:
            return None
        self.released = True
        return self.pool.release(self, reset=reset)


class FirecrackerPool:
    def __init__(self, size, profile, fc_path, kernel_path, rootfs_path, run_dir, mem_mib=768, vcpus=1, pool_id=None):
        self.size = int(size)
        self.profile = profile
        self.fc_path = fc_path
        self.kernel_path = kernel_path
        self.rootfs_path = rootfs_path
        self.run_dir = Path(run_dir)
        self.mem_mib = mem_mib
        self.vcpus = vcpus
        self.pool_id = pool_id or "pool-{}".format(hashlib.sha1(str(time.time()).encode()).hexdigest()[:8])
        self.available = queue.Queue()
        self.slots = []
        self.lock = threading.Lock()
        self.boot_records = []
        self.boot_errors = []
        self.closed = False
        self.created_ms = None

    def _new_vm(self, index):
        return Phase4VM(
            "{}-{}".format(self.pool_id, index),
            self.fc_path,
            self.kernel_path,
            self.rootfs_path,
            self.run_dir,
            mem_mib=self.mem_mib,
            vcpus=self.vcpus,
        )

    def _boot_slot(self, index):
        vm = self._new_vm(index)
        boot = vm.boot()
        return {"index": index, "vm": vm, "boot": boot, "uses": 0, "replacements": 0}

    def create(self):
        t0 = now_ns()
        results = [None] * self.size
        errors = [None] * self.size

        def worker(index):
            vm = self._new_vm(index)
            try:
                boot = vm.boot()
                slot = {"index": index, "vm": vm, "boot": boot, "uses": 0, "replacements": 0}
                results[index] = slot
                self.available.put(slot)
            except Exception as exc:
                errors[index] = repr(exc)
                try:
                    vm.stop()
                except Exception:
                    pass

        threads = [threading.Thread(target=worker, args=(idx,), daemon=True) for idx in range(self.size)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.created_ms = ms_since(t0)
        self.slots = [slot for slot in results if slot]
        self.boot_records = [slot["boot"] for slot in self.slots]
        self.boot_errors = [error for error in errors if error]
        return self.status()

    def acquire(self, timeout=30):
        start = now_ns()
        try:
            slot = self.available.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError("timeout acquiring Firecracker session from {}".format(self.pool_id))
        wait_ms = ms_since(start)
        with self.lock:
            slot["uses"] += 1
        session_id = "{}-s{}".format(self.pool_id, hashlib.sha1("{}-{}".format(time.time(), slot["index"]).encode()).hexdigest()[:10])
        return Session(self, slot, session_id, wait_ms)

    def reset_session(self, session, validate=True):
        t0 = now_ns()
        reset_resp = None
        validation = None
        validation_ms = None
        try:
            reset_resp = session.vm.agent.request("environment/reset")
            reset_ms = ms_since(t0)
            if validate:
                val_t0 = now_ns()
                validation = session.run_ms(
                    "bash -lc 'test -f file.txt && test -f tests/test_sample.py && ! pgrep -x sleep >/dev/null && pwd'",
                    timeout_ms=10000,
                )
                validation_ms = ms_since(val_t0)
            ok = bool(reset_resp.get("ok")) and (not validate or (validation and validation.get("exit_code") == 0))
            if ok:
                return {
                    "ok": True,
                    "reset_response": reset_resp,
                    "validation_response": validation,
                    "reset_request_ms": reset_ms,
                    "post_reset_validation_ms": validation_ms,
                    "total_recycle_ready_ms": reset_ms + (validation_ms or 0),
                    "slot_replaced": False,
                    "actual_strategy": "environment_reset",
                    "escalated": False,
                }
            reason = "post_reset_validation_failed"
        except Exception as exc:
            reset_ms = ms_since(t0)
            reason = "reset_exception: {}".format(repr(exc))
        replacement = self.replace_slot(session.slot, reason=reason)
        session.slot = replacement["slot"]
        return {
            "ok": replacement["ok"],
            "reset_response": reset_resp,
            "validation_response": validation,
            "reset_request_ms": reset_ms,
            "post_reset_validation_ms": validation_ms,
            "total_recycle_ready_ms": reset_ms + replacement.get("replacement_ready_ms", 0.0),
            "slot_replaced": True,
            "actual_strategy": "hard_recycle",
            "escalated": True,
            "escalation_reason": reason,
            "replacement_ready_ms": replacement.get("replacement_ready_ms"),
            "runtime_dirs_remaining": replacement.get("runtime_dirs_remaining"),
        }

    def replace_slot(self, slot, reason):
        index = slot["index"]
        old_vm = slot.get("vm")
        t0 = now_ns()
        if old_vm is not None:
            try:
                old_vm.stop()
            except Exception:
                pass
            shutil.rmtree(str(old_vm.dir), ignore_errors=True)
        new_slot = self._boot_slot(index)
        new_slot["uses"] = slot.get("uses", 0)
        new_slot["replacements"] = slot.get("replacements", 0) + 1
        slot.clear()
        slot.update(new_slot)
        ready_ms = ms_since(t0)
        remaining = len(list(self.run_dir.glob("vm-{}-{}*".format(self.pool_id, index))))
        self.boot_records.append(slot["boot"])
        return {
            "ok": True,
            "slot": slot,
            "reason": reason,
            "replacement_ready_ms": ready_ms,
            "runtime_dirs_remaining": remaining,
        }

    @contextlib.contextmanager
    def session(self, timeout=30):
        session = self.acquire(timeout=timeout)
        try:
            yield session
        finally:
            session.release(reset=True)

    def release(self, session, reset=True):
        reset_result = None
        if reset:
            reset_result = session.reset(validate=True)
        if self.closed:
            try:
                session.vm.stop()
            except Exception:
                pass
        else:
            self.available.put(session.slot)
        return reset_result

    def status(self):
        rss_values = [proc_rss_kb(slot["vm"].proc.pid) for slot in self.slots if slot.get("vm") and slot["vm"].proc]
        return {
            "pool_id": self.pool_id,
            "profile": self.profile,
            "requested": self.size,
            "ready": len(self.slots),
            "available": self.available.qsize(),
            "boot_errors": list(self.boot_errors),
            "pool_ready_wall_ms": self.created_ms,
            "boot_ready_ms": summarize([record.get("ready_ms") for record in self.boot_records]),
            "rss_sum_kb": sum(v or 0 for v in rss_values),
            "rss_per_vm_kb": summarize(rss_values),
            "guest_memory_total_mb": len(self.slots) * self.mem_mib,
            "cgroup_memory_current": cgroup_memory_current(),
            "pids_current": current_pids_count(),
            "fd_count": current_fd_count(),
        }

    def close(self):
        self.closed = True
        for slot in list(self.slots):
            try:
                slot["vm"].stop()
            except Exception:
                pass


def run_rootfs_profile(session, raw_path):
    tests = [
        ("rootfs.bash", "bash -lc 'echo hello'"),
        ("rootfs.python", "python3 -c 'print(1)'"),
        ("rootfs.pytest", "python3 -m pytest tests"),
        ("rootfs.git", "git --version && git init repo && cd repo && git status --short"),
        ("rootfs.grep_find_sed_awk", "bash -lc 'grep needle needle.txt; find . -maxdepth 2 -type f | sort | head; sed -n \"1p\" file.txt; awk \"{print \\$1}\" table.txt | head -1'"),
        ("rootfs.coreutils", "bash -lc 'printf \"b\\na\\n\" | sort | uniq | wc -l; head -1 file.txt; tail -1 file.txt; diff -u before.txt after.txt || true'"),
        ("rootfs.patch_tar_gzip", "bash -lc 'cp before.txt patchme.txt; diff -u patchme.txt after.txt > change.patch || true; patch patchme.txt change.patch; tar -czf out.tgz patchme.txt; gzip -t out.tgz'"),
        ("rootfs.curl_binary", "curl --version | head -1"),
        ("rootfs.gcc_hello", "cat > hello.c <<'C'\n#include <stdio.h>\nint main(){puts(\"hello-c\");return 0;}\nC\ngcc hello.c -o hello && ./hello"),
        ("rootfs.sqlite3_stdlib", "python3 -c 'import sqlite3; print(sqlite3.sqlite_version)'"),
    ]
    rows = []
    for test_id, command in tests:
        resp = session.run_ms(command, timeout_ms=60000)
        health = session.health()
        row = benchmark_row(
            test_id,
            "rootfs_profile",
            command,
            resp,
            pool_id=session.pool.pool_id,
            session_id=session.session_id,
            vm_id=session.vm_id,
            host_rss_kb=proc_rss_kb(session.vm.proc.pid),
            guest_memory_mb=session.vm.mem_mib,
            agent_survived=health.get("ok"),
            vm_survived=session.vm.proc.poll() is None,
            classification="pass" if resp.get("ok") and resp.get("exit_code") == 0 else "fail",
        )
        rows.append(row)
        write_jsonl(raw_path, row)
    return rows


def run_pool_session_smoke(pool, raw_path, smoke_path):
    rows = []
    smoke = []
    session = pool.acquire()
    try:
        smoke.append({"event": "session/acquire", "pool_id": pool.pool_id, "session_id": session.session_id, "vm_id": session.vm_id, "queue_wait_ms": session.queue_wait_ms})
        for test_id, command, expect in [
            ("pool.run_true", "bash -lc 'true'", 0),
            ("pool.run_echo", "bash -lc 'echo hello'", 0),
            ("pool.workspace_persists_1", "bash -lc 'mkdir -p persist && echo value > persist/value.txt && cat persist/value.txt'", 0),
            ("pool.workspace_persists_2", "bash -lc 'cat persist/value.txt'", 0),
            ("pool.cwd_env_nonpersistent_1", "bash -lc 'cd /tmp && export PHASE6_STICKY=1'", 0),
            ("pool.cwd_env_nonpersistent_2", "bash -lc 'pwd; echo ${PHASE6_STICKY:-unset}'", 0),
            ("pool.pytest", "python3 -m pytest tests", 0),
        ]:
            resp = session.run_ms(command, timeout_ms=60000)
            stdout, _stderr = resp_stdio(resp)
            ok = resp.get("ok") and resp.get("exit_code") == expect
            if test_id == "pool.cwd_env_nonpersistent_2":
                ok = ok and b"/workspace" in stdout and b"unset" in stdout
            row = benchmark_row(
                test_id,
                "pool_session_smoke",
                command,
                resp,
                pool_id=pool.pool_id,
                session_id=session.session_id,
                vm_id=session.vm_id,
                queue_wait_ms=session.queue_wait_ms,
                session_acquire_ms=session.queue_wait_ms,
                classification="pass" if ok else "fail",
            )
            rows.append(row)
            smoke.append(row)
            write_jsonl(raw_path, row)
            write_jsonl(smoke_path, row)

        start = session.start("python3 -u -c 'import pathlib,time; pathlib.Path(\"bg-marker.txt\").write_text(\"alive\"); print(\"ready\", flush=True); time.sleep(60)'")
        read1 = session.read(start.get("handle"), wait_ms=1000)
        status1 = session.process_status(start.get("handle"))
        proc_ok = start.get("ok") and read1.get("ok") and status1.get("running")
        combined = {
            "ok": proc_ok,
            "exit_code": 0 if proc_ok else 1,
            "stdout_b64": read1.get("stdout_b64", ""),
            "stderr_b64": read1.get("stderr_b64", ""),
            "command_roundtrip_ms": (start.get("command_roundtrip_ms") or 0) + (read1.get("command_roundtrip_ms") or 0),
        }
        row = benchmark_row(
            "pool.background_process_persists",
            "pool_session_smoke",
            "process/start/read/status",
            combined,
            pool_id=pool.pool_id,
            session_id=session.session_id,
            vm_id=session.vm_id,
            classification="pass" if proc_ok else "fail",
            notes="Background process remained running inside the session before release.",
        )
        rows.append(row)
        smoke.append(row)
        write_jsonl(raw_path, row)
        write_jsonl(smoke_path, row)

        start2 = session.start("python3 -u -c 'import sys; print(sys.stdin.readline().strip().upper(), flush=True)'")
        session.write(start2.get("handle"), b"abc\n")
        session.close_stdin(start2.get("handle"))
        read2 = session.read(start2.get("handle"), wait_ms=1000)
        stdout2, _ = resp_stdio(read2)
        proc2_ok = start2.get("ok") and read2.get("ok") and b"ABC" in stdout2
        row = benchmark_row(
            "pool.process_stdin_transform",
            "pool_session_smoke",
            "process/start/write/close_stdin/read",
            {"ok": proc2_ok, "exit_code": 0 if proc2_ok else 1, "stdout_b64": read2.get("stdout_b64", ""), "stderr_b64": read2.get("stderr_b64", ""), "command_roundtrip_ms": read2.get("command_roundtrip_ms")},
            pool_id=pool.pool_id,
            session_id=session.session_id,
            vm_id=session.vm_id,
            classification="pass" if proc2_ok else "fail",
        )
        rows.append(row)
        smoke.append(row)
        write_jsonl(raw_path, row)
        write_jsonl(smoke_path, row)

        try:
            session.vm.agent.writer.write(b"{bad json\n")
            session.vm.agent.writer.flush()
            bad = json.loads(session.vm.agent.reader.readline().decode("utf-8"))
            health = session.health()
            malformed_ok = bool(bad.get("ok") is False and health.get("ok"))
        except Exception:
            malformed_ok = False
            health = {}
        row = benchmark_row(
            "pool.malformed_frame_survival",
            "pool_session_smoke",
            "malformed JSONL frame",
            {"ok": malformed_ok, "exit_code": 0 if malformed_ok else 1, "stdout_b64": "", "stderr_b64": "", "command_roundtrip_ms": 0},
            pool_id=pool.pool_id,
            session_id=session.session_id,
            vm_id=session.vm_id,
            agent_survived=health.get("ok"),
            vm_survived=session.vm.proc.poll() is None,
            classification="pass" if malformed_ok else "fail",
        )
        rows.append(row)
        smoke.append(row)
        write_jsonl(raw_path, row)
        write_jsonl(smoke_path, row)

        release_result = session.release(reset=True)
        row = {
            "test_id": "pool.session_release_reset",
            "category": "pool_session_smoke",
            "classification": "pass" if release_result and release_result.get("ok") else "fail",
            "pool_id": pool.pool_id,
            "session_id": session.session_id,
            "vm_id": session.vm_id,
            "reset_mode": "read_only_root_plus_tmpfs_workspace",
            "reset_request_ms": (release_result or {}).get("reset_request_ms"),
            "post_reset_validation_ms": (release_result or {}).get("post_reset_validation_ms"),
            "total_recycle_ready_ms": (release_result or {}).get("total_recycle_ready_ms"),
            "notes": "Release kills process handles and all other guest processes, clears tmpfs workspace, reseeds fixture, and returns slot to pool.",
        }
        rows.append(row)
        smoke.append(row)
        write_jsonl(raw_path, row)
        write_jsonl(smoke_path, row)
    finally:
        if not session.released:
            session.release(reset=True)

    with pool.session() as reused:
        resp = reused.run_ms("bash -lc '! test -e persist/value.txt && ! test -e bg-marker.txt && test -f file.txt && ! pgrep -x sleep >/dev/null && echo clean'", timeout_ms=10000)
        ok = resp.get("ok") and resp.get("exit_code") == 0 and b"clean" in resp_stdio(resp)[0]
        row = benchmark_row(
            "pool.slot_reuse_after_release",
            "pool_session_smoke",
            "validate clean reusable slot",
            resp,
            pool_id=pool.pool_id,
            session_id=reused.session_id,
            vm_id=reused.vm_id,
            queue_wait_ms=reused.queue_wait_ms,
            session_acquire_ms=reused.queue_wait_ms,
            classification="pass" if ok else "fail",
        )
        rows.append(row)
        smoke.append(row)
        write_jsonl(raw_path, row)
        write_jsonl(smoke_path, row)
    return rows, smoke


def run_reset_tests(pool, raw_path):
    rows = []
    session = pool.acquire()
    try:
        for count in (10, 1000, 10000):
            mutate = "bash -lc 'rm -rf /workspace/*; mkdir -p /workspace/dir; for i in $(seq 1 {}); do echo needle-$i > /workspace/dir/file-$i.txt; done; (cd /workspace/dir && sleep 60 &) ; echo mutated'".format(count)
            session.run_ms(mutate, timeout_ms=max(20000, count * 5))
            reset = session.reset(validate=True)
            resp = reset.get("validation_response") or {}
            row = benchmark_row(
                "reset.tmpfs_workspace_{}".format(count),
                "reset",
                "environment/reset after {} created files and background process".format(count),
                resp,
                pool_id=pool.pool_id,
                session_id=session.session_id,
                vm_id=session.vm_id,
                reset_mode="read_only_root_plus_tmpfs_workspace",
                reset_request_ms=reset.get("reset_request_ms"),
                post_reset_validation_ms=reset.get("post_reset_validation_ms"),
                total_recycle_ready_ms=reset.get("total_recycle_ready_ms"),
                workspace_file_count=count,
                classification="pass" if reset.get("ok") else "fail",
                notes="Reset is separate from post-reset validation latency.",
            )
            rows.append(row)
            write_jsonl(raw_path, row)
    finally:
        session.release(reset=True)
    return rows


def run_security_smoke(pool, raw_path):
    rows = []
    tests = [
        ("security.passwd_guest_local", "cat /etc/passwd", "exit_zero"),
        ("security.home_guest_local", "ls -la /home", "exit_zero"),
        ("security.guest_env_allowlisted", "env | sort", "env_allowlist"),
        ("security.no_host_paths", "for p in /scratch /pfs /Users /mnt /host; do if [ -e \"$p\" ]; then echo EXISTS:$p; else echo ABSENT:$p; fi; done", "no_exists"),
        ("security.network_default_denied_curl", "timeout 5 curl -fsS http://example.com/ >/tmp/net.out", "exit_nonzero"),
        ("security.network_default_denied_python", "python3 - <<'PY'\nimport socket\nsocket.create_connection(('example.com', 80), timeout=2)\nPY", "exit_nonzero"),
        ("security.memory_pressure_survival", "timeout 3 python3 - <<'PY'\nx=[]\nwhile True:\n    x.append(b'x'*1000000)\nPY", "exit_nonzero"),
        ("security.disk_fill_workspace", "python3 - <<'PY'\nopen('/workspace/big', 'wb').write(b'x' * 200000000)\nPY", "exit_zero"),
    ]
    with pool.session() as session:
        for test_id, command, expectation in tests:
            resp = session.run_ms("bash -lc '{}'".format(command.replace("'", "'\"'\"'")), timeout_ms=15000)
            health = session.health()
            stdout, _stderr = resp_stdio(resp)
            ok = bool(health.get("ok"))
            if expectation == "exit_zero":
                ok = ok and resp.get("exit_code") == 0
            elif expectation == "exit_nonzero":
                ok = ok and resp.get("exit_code") != 0
            elif expectation == "no_exists":
                ok = ok and b"EXISTS:" not in stdout
            elif expectation == "env_allowlist":
                env_text = decode_text(stdout)
                denied = [name for name in ("TOKEN", "KEY", "SECRET", "PASSWORD", "SLURM", "AWS", "HF_") if name in env_text]
                ok = ok and not denied
            row = benchmark_row(
                test_id,
                "security",
                command,
                resp,
                pool_id=pool.pool_id,
                session_id=session.session_id,
                vm_id=session.vm_id,
                agent_survived=health.get("ok"),
                vm_survived=session.vm.proc.poll() is None,
                classification="pass" if ok else "fail",
                notes="Network allowlist/proxy ACL remains deferred; this checks no network device/default egress path.",
            )
            rows.append(row)
            write_jsonl(raw_path, row)
    return rows


SNAPSHOT_SCRIPT_TEMPLATE = r'''python3 - <<'PY'
import fnmatch
import hashlib
import json
import os
import stat
import time
from pathlib import PurePosixPath

WORKSPACE = "/workspace"
IGNORE = {ignore_patterns_json}

def ignored(rel):
    candidate = PurePosixPath(rel)
    for pattern in IGNORE:
        if pattern in candidate.parts:
            return True
        if candidate.match(pattern) or fnmatch.fnmatchcase(rel, pattern):
            return True
    return False

def file_hash(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()

def snap_dir(directory, rel_prefix, snapshot):
    try:
        entries = list(os.scandir(directory))
    except FileNotFoundError:
        return
    for entry in sorted(entries, key=lambda item: item.name):
        rel = (rel_prefix + "/" + entry.name) if rel_prefix else entry.name
        if ignored(rel):
            continue
        try:
            st = entry.stat(follow_symlinks=False)
        except FileNotFoundError:
            continue
        mode = st.st_mode
        if stat.S_ISLNK(mode):
            snapshot[rel] = {{"type": "symlink", "target": os.readlink(entry.path), "mode": mode}}
        elif stat.S_ISREG(mode):
            snapshot[rel] = {{"type": "file", "size": st.st_size, "mode": mode, "sha256": file_hash(entry.path)}}
        elif stat.S_ISDIR(mode):
            snapshot[rel] = {{"type": "dir", "mode": mode}}
            snap_dir(entry.path, rel, snapshot)
        else:
            snapshot[rel] = {{"type": "other", "mode": mode}}

started = time.perf_counter()
snapshot = {{}}
snap_dir(WORKSPACE, "", snapshot)
payload = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
print(json.dumps({{
    "final_fs_hash": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
    "snapshot_entries": len(snapshot),
    "snapshot_ms": (time.perf_counter() - started) * 1000.0,
}}, sort_keys=True))
PY'''


def workspace_snapshot(session, ignore_patterns):
    command = SNAPSHOT_SCRIPT_TEMPLATE.format(ignore_patterns_json=json.dumps(ignore_patterns or []))
    resp = session.run_ms(command, timeout_ms=120000, stdout_limit=2 * 1024 * 1024, stderr_limit=2 * 1024 * 1024)
    stdout, stderr = resp_stdio(resp)
    if resp.get("exit_code") != 0:
        return {
            "ok": False,
            "error": decode_text(stderr),
            "response": resp,
            "snapshot_ms": resp.get("command_roundtrip_ms"),
        }
    try:
        data = json.loads(decode_text(stdout))
        data["ok"] = True
        data["response"] = resp
        return data
    except Exception as exc:
        return {"ok": False, "error": repr(exc), "stdout": decode_text(stdout), "response": resp}


def normalize_output(text):
    text = NATIVE_WORKSPACE_RE.sub("<workspace>", text or "")
    return text.replace("/workspace", "<workspace>")


def parse_ls_la_listing(text):
    listing = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("total "):
            continue
        fields = line.split(maxsplit=8)
        if len(fields) != 9:
            return None
        mode, _links, _owner, _group, size_text, *_rest, name = fields
        if len(mode) < 10:
            return None
        if name in {".", ".."}:
            continue
        if " -> " in name:
            name = name.split(" -> ", 1)[0]
        try:
            size = int(size_text)
        except ValueError:
            return None
        listing[name] = size
    return listing


def compare_step(expected, candidate):
    if expected.get("classification") != "pass":
        return "inconclusive", "expected native reference is not pass: {}".format(expected.get("notes") or expected.get("classification"))
    if expected.get("timeout"):
        return "inconclusive", "baseline timed out"
    if candidate.get("timeout"):
        return "fail", "candidate timed out"
    if expected.get("exit_code") != candidate.get("exit_code"):
        return "fail", "exit code differs: baseline={} candidate={}".format(expected.get("exit_code"), candidate.get("exit_code"))
    expected_stdout = normalize_output(expected.get("stdout") or "")
    candidate_stdout = normalize_output(candidate.get("stdout") or "")
    if expected_stdout != candidate_stdout:
        if (expected.get("command") or "").strip() == "ls -la":
            if parse_ls_la_listing(expected_stdout) == parse_ls_la_listing(candidate_stdout):
                return "pass", "ls -la structural listing matches; metadata differs"
        return "major_mismatch", "stdout differs after workspace normalization"
    expected_stderr = normalize_output(expected.get("stderr") or "")
    candidate_stderr = normalize_output(candidate.get("stderr") or "")
    if expected_stderr != candidate_stderr:
        return "major_mismatch", "stderr differs after workspace normalization"
    return "pass", "normalized stdout/stderr/exit match"


def run_trace_replay(pool, handoff_dir, trace_out_path, raw_path):
    commands = read_jsonl(Path(handoff_dir) / "traces" / "agenttrove-strict-safe-100-commands.jsonl")
    expected_rows = read_jsonl(Path(handoff_dir) / "traces" / "native-expected-replay.jsonl")
    expected_by_key = {(row["trace_id"], row["step_id"]): row for row in expected_rows}
    by_trace = collections.OrderedDict()
    for row in commands:
        by_trace.setdefault(row["trace_id"], []).append(row)

    output_rows = []
    counts = collections.Counter()
    failure_patterns = collections.Counter()
    reset_times = []
    command_times = []
    final_fs_times = []
    failing_traces = collections.defaultdict(int)

    session = pool.acquire()
    try:
        for trace_id, rows in by_trace.items():
            reset = session.reset(validate=True)
            reset_times.append(reset.get("total_recycle_ready_ms"))
            for index, row in enumerate(rows):
                resp = session.run_ms(
                    row["command"],
                    timeout_ms=int(row.get("timeout_ms") or 5000),
                    cwd="/workspace",
                    stdout_limit=DEFAULT_STDIO_LIMIT,
                    stderr_limit=DEFAULT_STDIO_LIMIT,
                )
                stdout_b, stderr_b = resp_stdio(resp)
                candidate = {
                    "test_id": "trace_replay.{}.{}".format(trace_id, row["step_id"]),
                    "trace_id": trace_id,
                    "step_id": row["step_id"],
                    "step_index": row.get("step_index", index),
                    "profile": PHASE6_PROFILE,
                    "profile_hash": "",
                    "runner": "trace-replay-{}".format(PHASE6_RUNNER),
                    "command": row["command"],
                    "exit_code": resp.get("exit_code"),
                    "stdout": decode_text(stdout_b),
                    "stderr": decode_text(stderr_b),
                    "stdout_bytes": resp.get("stdout_bytes_full", len(stdout_b)),
                    "stderr_bytes": resp.get("stderr_bytes_full", len(stderr_b)),
                    "stdout_truncated": resp.get("stdout_truncated", False),
                    "stderr_truncated": resp.get("stderr_truncated", False),
                    "stdout_excerpt": compact_text(stdout_b, 1000),
                    "stderr_excerpt": compact_text(stderr_b, 1000),
                    "timeout": resp.get("timeout", False),
                    "kill_reason": resp.get("kill_reason"),
                    "elapsed_ms": resp.get("command_roundtrip_ms"),
                    "guest_process_ms": resp.get("guest_process_ms"),
                    "reset_ms": reset.get("total_recycle_ready_ms") if index == 0 else None,
                    "timing": {
                        "command_wall_ms": resp.get("command_roundtrip_ms"),
                        "guest_process_ms": resp.get("guest_process_ms"),
                        "trace_step_index": float(index),
                    },
                    "resources": {
                        "max_rss_kb": proc_rss_kb(session.vm.proc.pid),
                        "stdout_bytes": resp.get("stdout_bytes_full", len(stdout_b)),
                        "stderr_bytes": resp.get("stderr_bytes_full", len(stderr_b)),
                    },
                    "lifecycle": {
                        "trace_corpus": TRACE_NAME,
                        "trace_workspace_template": row.get("workspace_template"),
                        "trace_ignore_path_patterns": ",".join(row.get("ignore_path_patterns") or []),
                        "trace_step_comparison": row.get("comparison"),
                        "candidate_runner": PHASE6_RUNNER,
                        "candidate_profile": PHASE6_PROFILE,
                        "candidate_guest_workspace": "/workspace",
                    },
                }
                expected = expected_by_key.get((trace_id, row["step_id"]))
                if expected is None:
                    classification, notes = "fail", "missing native expected row"
                else:
                    classification, notes = compare_step(expected, candidate)
                    candidate["expected_exit_code"] = expected.get("exit_code")
                candidate["classification"] = classification
                candidate["notes"] = notes
                counts[classification] += 1
                if classification != "pass":
                    failure_patterns[notes] += 1
                    failing_traces[trace_id] += 1
                command_times.append(resp.get("command_roundtrip_ms"))
                output_rows.append(candidate)
                write_jsonl(trace_out_path, candidate)
                write_jsonl(raw_path, benchmark_row(
                    "trace.{}.{}".format(trace_id, row["step_id"]),
                    "trace_equivalence_candidate",
                    row["command"],
                    resp,
                    pool_id=pool.pool_id,
                    session_id=session.session_id,
                    vm_id=session.vm_id,
                    classification=classification,
                    expected_exit_code=candidate.get("expected_exit_code"),
                    notes=notes,
                ))
            snap = workspace_snapshot(session, rows[-1].get("ignore_path_patterns") or [])
            final_hash = snap.get("final_fs_hash")
            expected_final = expected_by_key.get((trace_id, "__final_fs__"))
            expected_hash = None
            if expected_final:
                lifecycle = expected_final.get("lifecycle") or {}
                expected_hash = lifecycle.get("candidate_final_fs_hash") or lifecycle.get("baseline_final_fs_hash")
            if not snap.get("ok"):
                classification = "fail"
                notes = "candidate final filesystem snapshot failed: {}".format(snap.get("error"))
            elif expected_final and expected_final.get("classification") != "pass":
                classification = "inconclusive"
                notes = "expected final filesystem row is not pass"
            elif final_hash == expected_hash:
                classification = "pass"
                notes = "final filesystem hash matches"
            else:
                classification = "major_mismatch"
                notes = "final filesystem hash differs: baseline={} candidate={}".format(expected_hash, final_hash)
            final_row = {
                "test_id": "trace_replay.{}.__final_fs__".format(trace_id),
                "trace_id": trace_id,
                "step_id": "__final_fs__",
                "profile": PHASE6_PROFILE,
                "profile_hash": "",
                "runner": "trace-replay-{}".format(PHASE6_RUNNER),
                "command": "<final filesystem state>",
                "exit_code": 0 if snap.get("ok") else 1,
                "stdout": "",
                "stderr": "",
                "stdout_bytes": 0,
                "stderr_bytes": 0,
                "timeout": False,
                "kill_reason": None,
                "elapsed_ms": snap.get("snapshot_ms"),
                "classification": classification,
                "notes": notes,
                "timing": {
                    "command_wall_ms": None,
                    "candidate_final_fs_snapshot_ms": snap.get("snapshot_ms"),
                },
                "resources": {
                    "max_rss_kb": proc_rss_kb(session.vm.proc.pid),
                    "snapshot_entries": snap.get("snapshot_entries"),
                },
                "lifecycle": {
                    "trace_corpus": TRACE_NAME,
                    "trace_workspace_template": rows[-1].get("workspace_template"),
                    "trace_ignore_path_patterns": ",".join(rows[-1].get("ignore_path_patterns") or []),
                    "candidate_runner": PHASE6_RUNNER,
                    "candidate_profile": PHASE6_PROFILE,
                    "candidate_final_fs_hash": final_hash,
                    "baseline_final_fs_hash": expected_hash,
                },
            }
            output_rows.append(final_row)
            write_jsonl(trace_out_path, final_row)
            counts[classification] += 1
            if classification != "pass":
                failure_patterns[notes] += 1
                failing_traces[trace_id] += 1
            final_fs_times.append(snap.get("snapshot_ms"))
    finally:
        session.release(reset=True)

    total = len(output_rows)
    non_pass = sum(count for cls, count in counts.items() if cls != "pass")
    summary = {
        "trace_count": len(by_trace),
        "command_count": len(commands),
        "rows": total,
        "distinct_command_count": len({row["command"] for row in commands}),
        "classification_counts": dict(counts),
        "pass_count": counts.get("pass", 0),
        "minor_mismatch_count": counts.get("minor_mismatch", 0),
        "major_mismatch_count": counts.get("major_mismatch", 0),
        "fail_count": counts.get("fail", 0),
        "timeout_count": sum(1 for row in output_rows if row.get("timeout")),
        "non_pass_rate": non_pass / total if total else None,
        "failing_trace_count": len(failing_traces),
        "top_failure_patterns": failure_patterns.most_common(20),
        "worst_traces": [
            {"trace_id": trace_id, "failures": count, "failure_rate": count / (len(by_trace.get(trace_id, [])) + 1)}
            for trace_id, count in sorted(failing_traces.items(), key=lambda item: (-item[1], item[0]))[:20]
        ],
        "reset_recycle_ready_ms": summarize(reset_times),
        "command_wall_ms": summarize(command_times),
        "final_fs_snapshot_ms": summarize(final_fs_times),
        "candidate_rows_path": str(trace_out_path),
        "notes": "Candidate rows include full stdout/stderr fields; official external comparator should be run against native expected rows after handoff copy.",
    }
    return output_rows, summary


def run_density_tier(level, fc_path, kernel_path, rootfs_path, run_dir, mem_mib, vcpus, raw_path):
    pool = FirecrackerPool(
        size=level,
        profile=PHASE6_PROFILE,
        fc_path=fc_path,
        kernel_path=kernel_path,
        rootfs_path=rootfs_path,
        run_dir=run_dir,
        mem_mib=mem_mib,
        vcpus=vcpus,
        pool_id="density-{}".format(level),
    )
    pool.create()
    worker_count = pool.status()["ready"]
    results = [None] * worker_count

    def worker(index):
        session = pool.acquire(timeout=60)
        try:
            out = {"session_id": session.session_id, "vm_id": session.vm_id, "queue_wait_ms": session.queue_wait_ms, "commands": {}, "reset": None, "failure": None}
            commands = [
                ("true", "bash -lc 'true'", 10000),
                ("python", "python3 -c 'print(1)'", 30000),
                ("pytest", "python3 -m pytest tests", 60000),
                ("stdout_1m", "python3 -c 'import sys; sys.stdout.buffer.write(b\"x\" * 1048576)'", 60000),
            ]
            for label, command, timeout_ms in commands:
                resp = session.run_ms(command, timeout_ms=timeout_ms)
                out["commands"][label] = {
                    "ok": bool(resp.get("ok")) and resp.get("exit_code") == 0,
                    "exit_code": resp.get("exit_code"),
                    "elapsed_ms": resp.get("command_roundtrip_ms"),
                    "guest_process_ms": resp.get("guest_process_ms"),
                    "stdout_bytes": resp.get("stdout_bytes_full", len(unb64(resp.get("stdout_b64", "")))),
                    "stderr_bytes": resp.get("stderr_bytes_full", len(unb64(resp.get("stderr_b64", "")))),
                }
            out["reset"] = session.reset(validate=True)
            results[index] = out
        except Exception as exc:
            results[index] = {"failure": repr(exc)}
        finally:
            try:
                session.release(reset=False)
            except Exception:
                pass

    started = now_ns()
    threads = [threading.Thread(target=worker, args=(idx,), daemon=True) for idx in range(worker_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    active_wall_ms = ms_since(started)
    status = pool.status()
    pool.close()

    failures = []
    queue_waits = []
    reset_total = []
    per_command = collections.defaultdict(list)
    for item in results:
        if not item or item.get("failure"):
            failures.append((item or {}).get("failure", "missing result"))
            continue
        queue_waits.append(item.get("queue_wait_ms"))
        if item.get("reset"):
            reset_total.append(item["reset"].get("total_recycle_ready_ms"))
            if not item["reset"].get("ok"):
                failures.append("reset failed for {}".format(item.get("session_id")))
        for label, data in item.get("commands", {}).items():
            per_command[label].append(data.get("elapsed_ms"))
            if not data.get("ok"):
                failures.append("{} failed for {}".format(label, item.get("session_id")))
    summary = {
        **status,
        "active_workload_wall_ms": active_wall_ms,
        "session_acquire_ms": summarize(queue_waits),
        "queue_wait_ms": summarize(queue_waits),
        "warm_true_ms": summarize(per_command["true"]),
        "warm_python_ms": summarize(per_command["python"]),
        "small_pytest_ms": summarize(per_command["pytest"]),
        "stdout_1m_ms": summarize(per_command["stdout_1m"]),
        "reset_ms": summarize(reset_total),
        "failure_count": len(failures),
        "failure_rate": len(failures) / max(1, worker_count),
        "failures": failures[:20],
    }
    row = {
        "test_id": "density.active_pool_{}".format(level),
        "category": "density",
        "classification": "pass" if not failures and status["ready"] == level else "partial" if status["ready"] else "fail",
        "pool_id": "density-{}".format(level),
        "profile": PHASE6_PROFILE,
        "requested_vms": level,
        "booted_vms": status["ready"],
        "pool_ready_wall_ms": status["pool_ready_wall_ms"],
        "active_workload_wall_ms": active_wall_ms,
        "session_acquire_ms": summary["session_acquire_ms"],
        "queue_wait_ms": summary["queue_wait_ms"],
        "warm_true_ms": summary["warm_true_ms"],
        "warm_python_ms": summary["warm_python_ms"],
        "small_pytest_ms": summary["small_pytest_ms"],
        "stdout_1m_ms": summary["stdout_1m_ms"],
        "reset_ms": summary["reset_ms"],
        "rss_sum_kb": status["rss_sum_kb"],
        "rss_per_vm_kb": status["rss_per_vm_kb"],
        "guest_memory_total_mb": status["guest_memory_total_mb"],
        "cgroup_memory_current": status["cgroup_memory_current"],
        "pids_current": status["pids_current"],
        "fd_count": status["fd_count"],
        "failure_rate": summary["failure_rate"],
        "notes": "All commands submitted concurrently through pool/session API for this tier.",
    }
    write_jsonl(raw_path, row)
    return summary, row


def run_density_tests(levels, fc_path, kernel_path, rootfs_path, run_dir, mem_mib, vcpus, raw_path):
    summaries = []
    rows = []
    for level in levels:
        log("phase6 density tier {}".format(level))
        summary, row = run_density_tier(level, fc_path, kernel_path, rootfs_path, run_dir, mem_mib, vcpus, raw_path)
        summaries.append(summary)
        rows.append(row)
        if summary.get("failure_count", 0) and summary.get("ready", 0) < level:
            break
    return rows, summaries


def run_vm_recycle_smoke(fc_path, kernel_path, rootfs_path, run_dir, mem_mib, vcpus, raw_path):
    vm = None
    try:
        vm = Phase4VM("reset-reboot-a", fc_path, kernel_path, rootfs_path, run_dir, mem_mib=mem_mib, vcpus=vcpus)
        boot_a = vm.boot()
        vm.agent.run("bash -lc 'echo dirty > dirty.txt; sleep 60 &'", timeout_ms=10000)
        vm.stop()
        vm = Phase4VM("reset-reboot-b", fc_path, kernel_path, rootfs_path, run_dir, mem_mib=mem_mib, vcpus=vcpus)
        t0 = now_ns()
        boot_b = vm.boot()
        resp = vm.agent.run("bash -lc '! test -e dirty.txt && test -f file.txt && echo clean'", timeout_ms=10000)
        total_ms = ms_since(t0)
        ok = resp.get("ok") and resp.get("exit_code") == 0
        row = benchmark_row(
            "reset.vm_recycle_reboot",
            "reset",
            "kill VM + boot clean VM",
            resp,
            reset_mode="kill_vm_reboot_tmpfs_seed",
            reset_request_ms=boot_b.get("ready_ms"),
            post_reset_validation_ms=resp.get("command_roundtrip_ms"),
            total_recycle_ready_ms=total_ms,
            classification="pass" if ok else "fail",
            notes="Alternative reset/recycle mode; slower than in-guest tmpfs reset but proves clean boot path.",
            boot_a_ready_ms=boot_a.get("ready_ms"),
            boot_b_ready_ms=boot_b.get("ready_ms"),
        )
        write_jsonl(raw_path, row)
        return row
    finally:
        if vm:
            try:
                vm.stop()
            except Exception:
                pass


def profile_report(rootfs, kernel_path):
    rootfs_path = Path(rootfs["path"])
    sparse_bytes = None
    try:
        sparse_bytes = rootfs_path.stat().st_blocks * 512
    except Exception:
        pass
    implemented = {
        "profile_name": "python-coding+c-cpp-gcc+network-denied",
        "status": "implemented",
        "phase6_profile_alias": PHASE6_PROFILE,
        "rootfs_profile": rootfs.get("profile"),
        "profile_version_string": rootfs.get("profile_hash"),
        "rootfs_path": rootfs.get("path"),
        "rootfs_logical_size_bytes": rootfs.get("logical_size_bytes"),
        "rootfs_sparse_disk_usage_bytes": sparse_bytes,
        "kernel_path": str(kernel_path),
        "package_tool_inventory": rootfs.get("package_inventory_paths"),
        "package_composition": {
            "requested_roots": (rootfs.get("package_composition") or {}).get("requested_roots"),
            "resolved_count": (rootfs.get("package_composition") or {}).get("resolved_count"),
            "missing": (rootfs.get("package_composition") or {}).get("missing"),
            "error_count": len((rootfs.get("package_composition") or {}).get("errors") or []),
        },
        "build_stage_method": rootfs.get("build_method"),
        "offline_reuse_across_jobs": rootfs.get("can_be_reused_across_jobs"),
        "job_startup_network_requirement": rootfs.get("job_startup_requires_network"),
        "network_policy": "no network device attached; allowlist/proxy ACL deferred",
    }
    return [
        {"profile_name": "base-shell", "status": "concept", "notes": "Subset of implemented rootfs; would omit Python/GCC packages in a profile-aware builder."},
        {"profile_name": "python-coding", "status": "implemented_as_part_of_combined_profile", "notes": "Python 3, pip, pytest, git, shell/coreutils available in combined rootfs."},
        {"profile_name": "c-cpp-gcc", "status": "implemented_as_part_of_combined_profile", "notes": "gcc/g++/make available in combined rootfs."},
        {"profile_name": "network-denied", "status": "implemented", "notes": "Firecracker VMs are launched without a network device in this phase."},
        {"profile_name": "network-allowlist", "status": "deferred", "notes": "Design deferred by user instruction; low-risk but needs gateway/proxy tradeoff decision."},
        implemented,
    ]


def classify_gates(rows, trace_summary, density_summaries):
    counts = collections.Counter(row.get("classification") for row in rows)
    category_failures = collections.defaultdict(list)
    for row in rows:
        if row.get("classification") not in ("pass", "deferred", "inconclusive"):
            category_failures[row.get("category")].append(row.get("test_id"))
    max_density = max([item.get("ready", 0) for item in density_summaries] or [0])
    trace_rate = trace_summary.get("non_pass_rate")
    return {
        "summary": "Firecracker remains the practical LUMI backend candidate; Phase 6 exercises a trainer-facing pool/session shape with network allowlist ACL still deferred.",
        "classification_counts": dict(counts),
        "gates": {
            "gate_a_usable_pool_api": {
                "status": "pass" if not category_failures.get("pool_session_smoke") else "partial",
                "notes": "create/status/acquire/run/start/read/write/close_stdin/status/terminate/reset/release/close exercised in-process.",
            },
            "gate_b_process_semantics": {
                "status": "pass" if not category_failures.get("pool_session_smoke") else "partial",
                "notes": "Vsock JSONL uses request ids, structured errors, base64 stdout/stderr/stdin, output bounds, timeouts, handles, draining reads, and malformed-frame survival.",
            },
            "gate_c_exact_trace_equivalence": {
                "status": "pass" if trace_rate is not None and trace_rate <= 0.05 else "partial",
                "notes": "Candidate precheck non-pass rate {:.3f}; official comparator is also expected in return handoff.".format(trace_rate if trace_rate is not None else -1),
            },
            "gate_d_security_policy": {
                "status": "partial",
                "notes": "Default no-network profile and artifact redaction are tested. Network allowlist/proxy ACL is intentionally deferred and considered low risk pending design choice.",
            },
            "gate_e_profile_composition": {
                "status": "partial",
                "notes": "Combined reusable profile is pinned/described; finer-grained image/component composition remains future work.",
            },
            "gate_f_reset_recycling": {
                "status": "pass" if not category_failures.get("reset") else "partial",
                "notes": "Session release and explicit reset kill processes, reseed tmpfs workspace, and validate recycle-ready separately.",
            },
            "gate_g_density_performance": {
                "status": "pass" if max_density >= 64 else "partial",
                "notes": "Active pool density reached {} ready VMs in this run.".format(max_density),
            },
        },
    }


def write_pool_example(path):
    Path(path).write_text(
        '''#!/usr/bin/env python3
from firecracker_lumi_phase6 import FirecrackerPool

pool = FirecrackerPool(
    size=64,
    profile="python-coding",
    fc_path="/path/to/firecracker",
    kernel_path="/path/to/vmlinux",
    rootfs_path="/path/to/rootfs.ext4",
    run_dir="/path/to/runtime-dir",
    mem_mib=768,
    vcpus=1,
)
pool.create()
try:
    with pool.session() as env:
        r1 = env.run("python3 -m pytest tests", timeout=10)
        proc = env.start("python3 -u server.py")
        status = env.run("curl http://127.0.0.1:8000/health", timeout=5)
        env.terminate(proc["handle"])
finally:
    pool.close()
''',
        encoding="utf-8",
    )


def write_reports(result, rows, trace_summary, reports_dir, job_id, smoke_rows):
    mkdir(reports_dir)
    stem = Path(reports_dir) / "firecracker-lumi-phase6-{}".format(job_id)
    json_path = stem.with_suffix(".json")
    md_path = stem.with_suffix(".md")
    analysis_path = Path(reports_dir) / "firecracker-lumi-phase6-{}-analysis.md".format(job_id)
    trace_analysis_json = Path(reports_dir) / "trace-replay-firecracker-agenttrove-strict-safe-100-analysis.json"
    trace_analysis_md = Path(reports_dir) / "trace-replay-firecracker-agenttrove-strict-safe-100-analysis.md"
    trace_summary_md = Path(reports_dir) / "trace-replay-firecracker-agenttrove-strict-safe-100-summary.md"
    smoke_md = Path(reports_dir) / "firecracker-pool-session-smoke.md"
    example_path = Path(reports_dir) / "firecracker_pool_api_example.py"

    result["benchmarks"] = rows
    result["latency_summary"] = {
        category: summarize([row.get("elapsed_ms") for row in rows if row.get("category") == category])
        for category in sorted({row.get("category") for row in rows})
    }
    json_path.write_text(json.dumps(redact_value(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    trace_analysis_json.write_text(json.dumps(redact_value(trace_summary), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    counts = collections.Counter(row.get("classification") for row in rows)
    lines = [
        "# Firecracker LUMI Phase 6",
        "",
        "- Job: `{}`".format(job_id),
        "- Node: `{}`".format(result.get("host", {}).get("hostname")),
        "- Profile: `{}`".format(PHASE6_PROFILE),
        "- Kernel: `{}`".format(result.get("artifacts", {}).get("kernel", {}).get("path")),
        "- Rootfs: `{}`".format(result.get("artifacts", {}).get("rootfs", {}).get("path")),
        "- Classifications: `{}`".format(json.dumps(dict(counts), sort_keys=True)),
        "- Redaction: host environment was not copied wholesale; returned JSON/JSONL/Markdown receive a secret-shaped value redaction pass.",
        "",
        "## Decision Gates",
        "",
    ]
    for gate, data in result.get("recommendation", {}).get("gates", {}).items():
        lines.append("- `{}`: `{}` - {}".format(gate, data.get("status"), data.get("notes")))
    lines.extend([
        "",
        "## Trace Candidate Precheck",
        "",
        "- Rows: `{}`".format(trace_summary.get("rows")),
        "- Commands: `{}`".format(trace_summary.get("command_count")),
        "- Traces: `{}`".format(trace_summary.get("trace_count")),
        "- Non-pass rate: `{:.3f}`".format(trace_summary.get("non_pass_rate") or 0),
        "- Counts: `{}`".format(json.dumps(trace_summary.get("classification_counts", {}), sort_keys=True)),
        "",
        "## Density",
        "",
        "```json",
        json.dumps(result.get("density", []), indent=2, sort_keys=True),
        "```",
    ])
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    analysis = [
        "# Firecracker LUMI Phase 6 Analysis",
        "",
        "## Bottom Line",
        "",
        result.get("recommendation", {}).get("summary", ""),
        "",
        "Network allowlist/proxy ACL remains deliberately deferred. The run treats this as a design choice rather than a blocker: default no-network operation is tested, while transparent allowlist egress still needs a gateway/proxy decision.",
        "",
        "## API Surface Exercised",
        "",
        "- `pool/create`, `pool/status`, `session/acquire`, `session/run`, `session/start`, `process/read`, `process/write`, `process/close_stdin`, `process/status`, `process/terminate`, `session/reset`, `session/release`, and `pool/close` are implemented in the local Python prototype.",
        "- Workspace state persists across commands within a session and is reset on release.",
        "- One-shot command `cwd` and `env` do not persist unless explicitly supplied on that command.",
        "- Background processes persist within a session and are killed by reset/release.",
        "",
        "## Profile And Image Notes",
        "",
        "- Phase 6 still uses a combined reusable rootfs; it is reported as an implemented `python-coding+c-cpp-gcc+network-denied` profile.",
        "- Long term, the profile/image story should move toward component composition instead of one growing image.",
        "- Runtime directories are per-run scratch owned by the lifecycle manager; durable cache/artifact locations are separate and environment defaults are honored rather than forced.",
        "",
        "## Trace Summary",
        "",
        "```json",
        json.dumps({k: trace_summary.get(k) for k in ("trace_count", "command_count", "rows", "classification_counts", "non_pass_rate", "top_failure_patterns", "command_wall_ms", "reset_recycle_ready_ms")}, indent=2, sort_keys=True),
        "```",
        "",
        "## Remaining Work Before Trainer Integration",
        "",
        "- Decide the transparent network gateway/proxy design and policy rule location.",
        "- Replace the single combined image with a profile/component builder.",
        "- Promote the in-process pool prototype into the trainer runtime boundary chosen by the integration.",
        "- Add production lifecycle cleanup and debug-retention controls around per-VM runtime directories.",
    ]
    analysis_path.write_text("\n".join(analysis) + "\n", encoding="utf-8")

    trace_lines = [
        "# Firecracker Trace Replay Candidate Summary",
        "",
        "- Corpus: `{}`".format(TRACE_NAME),
        "- Traces: `{}`".format(trace_summary.get("trace_count")),
        "- Commands: `{}`".format(trace_summary.get("command_count")),
        "- Rows including final filesystem: `{}`".format(trace_summary.get("rows")),
        "- Non-pass rate: `{:.3f}`".format(trace_summary.get("non_pass_rate") or 0),
        "- Classification counts: `{}`".format(json.dumps(trace_summary.get("classification_counts", {}), sort_keys=True)),
        "",
        "This is the harness precheck. The returned handoff should also include the official external comparator output when run on the WSL side.",
        "",
        "## Worst Traces",
        "",
        "| trace | failures | failure rate |",
        "|---|---:|---:|",
    ]
    for item in trace_summary.get("worst_traces", [])[:20]:
        trace_lines.append("| `{}` | `{}` | `{:.3f}` |".format(item["trace_id"], item["failures"], item["failure_rate"]))
    trace_summary_md.write_text("\n".join(trace_lines) + "\n", encoding="utf-8")
    trace_analysis_md.write_text("\n".join(trace_lines) + "\n", encoding="utf-8")

    smoke_lines = [
        "# Firecracker Pool Session Smoke",
        "",
        "| test | class | elapsed ms | notes |",
        "|---|---:|---:|---|",
    ]
    for row in smoke_rows:
        smoke_lines.append("| `{}` | `{}` | `{}` | {} |".format(
            row.get("test_id"),
            row.get("classification"),
            "{:.3f}".format(row.get("elapsed_ms")) if row.get("elapsed_ms") is not None else "",
            (row.get("notes") or "").replace("|", "/")[:160],
        ))
    smoke_md.write_text("\n".join(smoke_lines) + "\n", encoding="utf-8")
    write_pool_example(example_path)

    for path in (json_path, md_path, analysis_path, trace_analysis_json, trace_analysis_md, trace_summary_md, smoke_md):
        redact_file(path)

    return {
        "json": str(json_path),
        "markdown": str(md_path),
        "analysis": str(analysis_path),
        "trace_analysis_json": str(trace_analysis_json),
        "trace_analysis_md": str(trace_analysis_md),
        "trace_summary_md": str(trace_summary_md),
        "pool_smoke_md": str(smoke_md),
        "pool_example": str(example_path),
    }


def copy_return_artifacts(reports_dir, return_dir, job_id, raw_path, trace_out_path, smoke_path):
    return_dir = Path(return_dir)
    mkdir(return_dir)
    files = [
        Path(reports_dir) / "firecracker-lumi-phase6-{}.json".format(job_id),
        Path(reports_dir) / "firecracker-lumi-phase6-{}.md".format(job_id),
        Path(reports_dir) / "firecracker-lumi-phase6-{}-analysis.md".format(job_id),
        raw_path,
        trace_out_path,
        smoke_path,
        Path(reports_dir) / "trace-replay-firecracker-agenttrove-strict-safe-100-summary.md",
        Path(reports_dir) / "trace-replay-firecracker-agenttrove-strict-safe-100-analysis.json",
        Path(reports_dir) / "trace-replay-firecracker-agenttrove-strict-safe-100-analysis.md",
        Path(reports_dir) / "firecracker_pool_api_example.py",
        Path(reports_dir) / "firecracker-pool-session-smoke.md",
        Path(__file__),
    ]
    sbatch = Path(__file__).with_suffix(".sbatch")
    if sbatch.exists():
        files.append(sbatch)
    copied = []
    for src in files:
        if not Path(src).exists():
            continue
        dest_name = Path(src).name
        if dest_name == "firecracker_lumi_phase6.py":
            dest_name = "firecracker_lumi_phase6.py"
        dest = return_dir / dest_name
        shutil.copy2(str(src), str(dest))
        copied.append(str(dest))
    readme = return_dir / "README.md"
    readme.write_text(
        "\n".join([
            "# Firecracker LUMI Phase 6 Results",
            "",
            "Date: 2026-06-30",
            "",
            "This handoff contains the Phase 6 Firecracker/LUMI MVP backend run artifacts.",
            "",
            "Artifact hygiene:",
            "",
            "- No `SHA256SUMS` file is included.",
            "- Host Slurm environment dumps are intentionally omitted; only a small allowlisted Slurm summary is present.",
            "- JSON/JSONL/Markdown artifacts were passed through a secret-shaped value redaction helper.",
            "- Trace stdout/stderr are public risk-filtered corpus outputs and are retained so exact equivalence comparison remains possible.",
            "",
            "Network policy:",
            "",
            "- Default no-network operation is tested because Phase 6 Firecracker VMs are launched without a network device.",
            "- Transparent allowlist/proxy ACL design is deferred by user instruction and should be evaluated separately.",
            "",
            "Runtime hygiene:",
            "",
            "- Per-VM runtime directories are scratch owned by the harness lifecycle and are not durable state.",
            "- Real service implementations should honor the caller or supervisor environment for cache locations instead of forcing `PIP_CACHE_DIR`, `TORCH_HOME`, or related variables.",
        ]) + "\n",
        encoding="utf-8",
    )
    copied.append(str(readme))
    for path in copied:
        redact_file(path)
    return copied


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--kernel-path", required=True)
    ap.add_argument("--artifact-cache-dir", required=True)
    ap.add_argument("--rootfs-cache-dir", required=True)
    ap.add_argument("--handoff-dir", required=True)
    ap.add_argument("--return-dir", default=None)
    ap.add_argument("--mem-mib", type=int, default=768)
    ap.add_argument("--vcpus", type=int, default=1)
    ap.add_argument("--density", default="1,16,32,64,128")
    ap.add_argument("--pool-size", type=int, default=4)
    ap.add_argument("--skip-density", action="store_true")
    ap.add_argument("--skip-trace", action="store_true")
    args = ap.parse_args()

    job_id = os.environ.get("SLURM_JOB_ID", "local")
    run_dir = Path(args.run_dir)
    reports_dir = Path("reports")
    handoff_dir = Path(args.handoff_dir)
    workspace_template = handoff_dir / "workspaces" / "fixtures" / "mvp"
    mkdir(run_dir)
    mkdir(reports_dir)
    raw_path = reports_dir / "firecracker-lumi-phase6-{}-raw.jsonl".format(job_id)
    trace_out_path = reports_dir / "trace-replay-firecracker-agenttrove-strict-safe-100.jsonl"
    smoke_path = reports_dir / "firecracker-pool-session-smoke.jsonl"
    for path in (raw_path, trace_out_path, smoke_path):
        if path.exists():
            path.unlink()

    result = {
        "phase": 6,
        "host": host_snapshot(),
        "slurm": safe_slurm_snapshot(),
        "args": vars(args),
        "errors": [],
        "artifacts": {},
        "profiles": [],
        "pool_api_operations": {
            "implemented": [
                "pool/create",
                "pool/status",
                "session/acquire",
                "session/run",
                "session/start",
                "process/read",
                "process/write",
                "process/close_stdin",
                "process/status",
                "process/terminate",
                "session/reset",
                "session/release",
                "pool/close",
            ],
            "deferred": ["transparent network allowlist ACL", "read-after-sequence numeric cursor"],
            "notes": "process/read is a draining pipe read and behaves as a cursor-like poll for the current prototype.",
        },
        "network_policy": {
            "default": "denied by omission: no guest network device attached",
            "allowlist_acl": "deferred_by_user_instruction",
            "risk": "low pending gateway/proxy design choice",
        },
        "density": [],
        "trace_replay": {},
    }
    rows = []
    smoke_rows = []
    pools = []
    try:
        log("phase6 preparing artifacts")
        fc = download_firecracker(Path(args.artifact_cache_dir) / "firecracker")
        rootfs = phase5.prepare_rootfs(args.rootfs_cache_dir, args.artifact_cache_dir, {}, workspace_template)
        result["artifacts"] = {
            "firecracker": fc,
            "kernel": {"path": args.kernel_path, "bytes": Path(args.kernel_path).stat().st_size},
            "rootfs": rootfs,
        }
        result["profiles"] = profile_report(rootfs, args.kernel_path)

        log("phase6 creating smoke pool")
        pool = FirecrackerPool(
            size=args.pool_size,
            profile=PHASE6_PROFILE,
            fc_path=fc["path"],
            kernel_path=args.kernel_path,
            rootfs_path=rootfs["path"],
            run_dir=run_dir,
            mem_mib=args.mem_mib,
            vcpus=args.vcpus,
            pool_id="phase6-smoke",
        )
        pools.append(pool)
        pool_status = pool.create()
        result["pool_status_initial"] = pool_status
        with pool.session() as session:
            rows.extend(run_rootfs_profile(session, raw_path))
        smoke_extra, smoke_rows = run_pool_session_smoke(pool, raw_path, smoke_path)
        rows.extend(smoke_extra)
        rows.extend(run_reset_tests(pool, raw_path))
        rows.extend(run_security_smoke(pool, raw_path))
        recycle_row = run_vm_recycle_smoke(fc["path"], args.kernel_path, rootfs["path"], run_dir, args.mem_mib, args.vcpus, raw_path)
        rows.append(recycle_row)

        if not args.skip_trace:
            log("phase6 running exact trace candidate replay")
            _trace_rows, trace_summary = run_trace_replay(pool, handoff_dir, trace_out_path, raw_path)
            result["trace_replay"] = trace_summary
        else:
            trace_summary = {"classification": "deferred", "non_pass_rate": None}
            result["trace_replay"] = trace_summary
        pool.close()
        pools.remove(pool)

        if not args.skip_density:
            density_levels = [int(item) for item in args.density.split(",") if item.strip()]
            density_rows, density_summaries = run_density_tests(
                density_levels,
                fc["path"],
                args.kernel_path,
                rootfs["path"],
                run_dir,
                args.mem_mib,
                args.vcpus,
                raw_path,
            )
            rows.extend(density_rows)
            result["density"] = density_summaries
        else:
            result["density"] = []
        result["recommendation"] = classify_gates(rows, result["trace_replay"], result["density"])
    except Exception as exc:
        result["errors"].append({"fatal": repr(exc)})
        result.setdefault("recommendation", {"summary": "incomplete", "gates": {}})
    finally:
        for pool in list(pools):
            try:
                pool.close()
            except Exception:
                pass
        result["host_after"] = host_snapshot()
        reports = write_reports(result, rows, result.get("trace_replay", {}), reports_dir, job_id, smoke_rows)
        result["reports"] = reports
        if args.return_dir:
            copied = copy_return_artifacts(reports_dir, args.return_dir, job_id, raw_path, trace_out_path, smoke_path)
            result["return_artifacts"] = copied
        for path in run_dir.glob("vm-*"):
            shutil.rmtree(str(path), ignore_errors=True)
        print(json.dumps({
            "job_id": job_id,
            "reports": reports,
            "rows": len(rows),
            "trace_rows": sum(1 for _ in trace_out_path.open()) if trace_out_path.exists() else 0,
            "errors": result.get("errors", [])[-5:],
            "return_dir": args.return_dir,
        }, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
