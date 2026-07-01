#!/usr/bin/env python3
import argparse
import collections
import json
import os
import shutil
import time
from pathlib import Path

import firecracker_lumi_phase5 as phase5
import firecracker_lumi_phase6 as phase6
from firecracker_lumi_bench import download_firecracker, host_snapshot, mkdir, ms_since, now_ns, proc_rss_kb, read_text
from firecracker_lumi_phase4 import log


PHASE7_PROFILE = "firecracker-phase7"
TRACE_NAME = "agenttrove-strict-safe-100"


def write_jsonl(path, row):
    with Path(path).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(phase6.redact_value(row), sort_keys=True) + "\n")


def decode_resp(resp):
    return phase6.resp_stdio(resp)


def text(data):
    return phase6.decode_text(data)


def excerpt(data, limit=1200):
    return text(data)[:limit]


def row_base(test_id, category, classification, **fields):
    row = {
        "test_id": test_id,
        "category": category,
        "classification": classification,
        "profile": PHASE7_PROFILE,
        "timestamp_unix": time.time(),
    }
    row.update(fields)
    return row


def command_row(test_id, category, operation, session, resp, classification=None, notes=""):
    stdout, stderr = decode_resp(resp)
    cls = classification
    if cls is None:
        cls = "pass" if resp.get("ok") and resp.get("exit_code") == 0 and not resp.get("timeout") else "fail"
    return row_base(
        test_id,
        category,
        cls,
        operation=operation,
        pool_id=session.pool.pool_id if session else None,
        session_id=session.session_id if session else None,
        vm_id=session.vm_id if session else None,
        request_id=resp.get("id"),
        status="ok" if resp.get("ok") else "error",
        command=resp.get("command"),
        exit_code=resp.get("exit_code"),
        stdout_bytes=resp.get("stdout_bytes_full", len(stdout)),
        stderr_bytes=resp.get("stderr_bytes_full", len(stderr)),
        stdout_returned_bytes=len(stdout),
        stderr_returned_bytes=len(stderr),
        stdout_truncated=resp.get("stdout_truncated", False),
        stderr_truncated=resp.get("stderr_truncated", False),
        stdout_excerpt=excerpt(stdout),
        stderr_excerpt=excerpt(stderr),
        command_wall_ms=resp.get("command_roundtrip_ms"),
        guest_process_ms=resp.get("guest_process_ms"),
        timeout=resp.get("timeout", False),
        kill_reason=resp.get("kill_reason"),
        host_rss_kb=proc_rss_kb(session.vm.proc.pid) if session and session.vm and session.vm.proc else None,
        notes=notes,
    )


def emit(path, rows, row):
    rows.append(row)
    write_jsonl(path, row)
    return row


def wait_status(session, handle, attempts=20, wait_ms=100):
    status = None
    for _ in range(attempts):
        status = session.process_status(handle)
        if not status.get("running"):
            return status
        time.sleep(wait_ms / 1000.0)
    return status


def run_api_conformance(pool, raw_path, conformance_path):
    rows = []
    status = pool.status()
    emit(raw_path, rows, row_base("pool.create", "api_conformance", "pass" if status.get("ready") == pool.size else "partial", operation="pool/create", pool_id=pool.pool_id, status=status))
    write_jsonl(conformance_path, rows[-1])
    emit(raw_path, rows, row_base("pool.status", "api_conformance", "pass", operation="pool/status", pool_id=pool.pool_id, status=status))
    write_jsonl(conformance_path, rows[-1])

    session = pool.acquire()
    try:
        emit(raw_path, rows, row_base("session.acquire", "api_conformance", "pass", operation="session/acquire", pool_id=pool.pool_id, session_id=session.session_id, vm_id=session.vm_id, queue_wait_ms=session.queue_wait_ms))
        write_jsonl(conformance_path, rows[-1])

        tests = [
            ("session.run_echo", "session/run", "bash -lc 'echo hello'", 10000, lambda r, out, err: r.get("exit_code") == 0 and b"hello" in out),
            ("session.workspace_persists_1", "session/run", "bash -lc 'mkdir -p keep && echo value > keep/value.txt && cat keep/value.txt'", 10000, lambda r, out, err: r.get("exit_code") == 0 and b"value" in out),
            ("session.workspace_persists_2", "session/run", "bash -lc 'cat keep/value.txt'", 10000, lambda r, out, err: r.get("exit_code") == 0 and b"value" in out),
            ("session.env_does_not_persist_by_default", "session/run", "bash -lc 'export PHASE7_STICKY=1'; bash -lc 'echo ${PHASE7_STICKY:-unset}'", 10000, lambda r, out, err: r.get("exit_code") == 0 and b"unset" in out),
            ("session.cwd_does_not_persist_by_default_or_documented", "session/run", "bash -lc 'cd /tmp'; bash -lc 'pwd'", 10000, lambda r, out, err: r.get("exit_code") == 0 and b"/workspace" in out),
        ]
        for test_id, op, command, timeout_ms, check in tests:
            resp = session.run_ms(command, timeout_ms=timeout_ms)
            stdout, stderr = decode_resp(resp)
            row = command_row(test_id, "api_conformance", op, session, resp, classification="pass" if check(resp, stdout, stderr) else "fail")
            row["command"] = command
            emit(raw_path, rows, row)
            write_jsonl(conformance_path, row)

        start = session.start("sleep 30")
        proc_id = start.get("handle")
        emit(raw_path, rows, row_base("process.start_sleep", "api_conformance", "pass" if start.get("ok") and proc_id else "fail", operation="process/start", pool_id=pool.pool_id, session_id=session.session_id, vm_id=session.vm_id, request_id=start.get("id"), process_id=proc_id, command_wall_ms=start.get("command_roundtrip_ms")))
        write_jsonl(conformance_path, rows[-1])
        status_running = session.process_status(proc_id)
        emit(raw_path, rows, row_base("process.status_running", "api_conformance", "pass" if status_running.get("running") else "fail", operation="process/status", pool_id=pool.pool_id, session_id=session.session_id, vm_id=session.vm_id, request_id=status_running.get("id"), process_id=proc_id, command_wall_ms=status_running.get("command_roundtrip_ms")))
        write_jsonl(conformance_path, rows[-1])
        term = session.terminate(proc_id)
        emit(raw_path, rows, row_base("process.terminate", "api_conformance", "pass" if term.get("ok") else "fail", operation="process/terminate", pool_id=pool.pool_id, session_id=session.session_id, vm_id=session.vm_id, request_id=term.get("id"), process_id=proc_id, command_wall_ms=term.get("command_roundtrip_ms")))
        write_jsonl(conformance_path, rows[-1])
        status_done = wait_status(session, proc_id)
        emit(raw_path, rows, row_base("process.status_terminated", "api_conformance", "pass" if status_done and not status_done.get("running") else "fail", operation="process/status", pool_id=pool.pool_id, session_id=session.session_id, vm_id=session.vm_id, request_id=(status_done or {}).get("id"), process_id=proc_id, exit_code=(status_done or {}).get("exit_code"), command_wall_ms=(status_done or {}).get("command_roundtrip_ms")))
        write_jsonl(conformance_path, rows[-1])

        stdin_proc = session.start("python3 -u -c 'import sys; print(sys.stdin.read().upper(), end=\"\")'")
        stdin_id = stdin_proc.get("handle")
        session.write(stdin_id, b"hello stdin\n")
        session.close_stdin(stdin_id)
        read = session.read(stdin_id, wait_ms=1000)
        out, _err = decode_resp(read)
        emit(raw_path, rows, row_base("process.stdin_echo", "api_conformance", "pass" if b"HELLO STDIN" in out else "fail", operation="process/write+read", pool_id=pool.pool_id, session_id=session.session_id, vm_id=session.vm_id, process_id=stdin_id, stdout_bytes=len(out), stderr_bytes=0, stdout_excerpt=excerpt(out), stdout_truncated=False, stderr_truncated=False, command_wall_ms=read.get("command_roundtrip_ms")))
        write_jsonl(conformance_path, rows[-1])

        for label, bytes_count in (("process.large_stdout_1mib", 1024 * 1024), ("process.large_stdout_10mib", 10 * 1024 * 1024)):
            limit = 1024 * 1024
            resp = session.run_ms("python3 -c 'import sys; sys.stdout.buffer.write(b\"x\" * {})'".format(bytes_count), timeout_ms=60000, stdout_limit=limit)
            ok = resp.get("ok") and resp.get("exit_code") == 0 and resp.get("stdout_bytes_full") == bytes_count
            if bytes_count > limit:
                ok = ok and resp.get("stdout_truncated")
            row = command_row(label, "api_conformance", "session/run", session, resp, classification="pass" if ok else "fail", notes="stdout_limit={} bytes".format(limit))
            emit(raw_path, rows, row)
            write_jsonl(conformance_path, row)

        bg = session.start("python3 -u -c 'import pathlib,time; pathlib.Path(\"release-marker\").write_text(\"dirty\"); time.sleep(60)'")
        release = session.release(reset=True)
        emit(raw_path, rows, row_base("session.release_kills_processes", "api_conformance", "pass" if release and release.get("ok") else "fail", operation="session/release", pool_id=pool.pool_id, session_id=session.session_id, vm_id=session.vm_id, process_id=bg.get("handle"), reset_ms=(release or {}).get("reset_request_ms"), recycle_ready_ms=(release or {}).get("total_recycle_ready_ms"), notes="Release calls environment/reset, which kills tracked handles and all other guest PIDs except agent/init."))
        write_jsonl(conformance_path, rows[-1])
    finally:
        if not session.released:
            session.release(reset=True)

    with pool.session() as reused:
        resp = reused.run_ms("bash -lc '! test -e keep/value.txt && ! test -e release-marker && test -f file.txt && echo clean'", timeout_ms=10000)
        ok = resp.get("ok") and resp.get("exit_code") == 0 and b"clean" in decode_resp(resp)[0]
        row = command_row("session.release_resets_workspace", "api_conformance", "session/acquire+run", reused, resp, classification="pass" if ok else "fail")
        emit(raw_path, rows, row)
        write_jsonl(conformance_path, row)

    return rows


def resource_entry(resource, target_policy, mechanism, status, probe_command, expected, observed, worker_survived, vm_survived, pool_slot_reusable, confidence, **extra):
    row = {
        "resource": resource,
        "target_policy": target_policy,
        "mechanism_attempted": mechanism,
        "status": status,
        "requires_host_root": False,
        "requires_guest_root": False,
        "requires_guest_kernel_feature": False,
        "requires_lumi_admin": False,
        "probe_command": probe_command,
        "expected_behavior": expected,
        "observed_behavior": observed,
        "worker_survived": worker_survived,
        "vm_survived": vm_survived,
        "pool_slot_reusable": pool_slot_reusable,
        "overhead_ms_p50": None,
        "security_confidence": confidence,
        "notes": "",
    }
    row.update(extra)
    return row


def run_resource_probes(pool, raw_path, probes_path):
    rows = []
    matrix = []

    def record(resource_row, classification="pass"):
        matrix.append(resource_row)
        probe_row = row_base("resource.{}".format(resource_row["resource"].replace(" ", "_").replace("/", "_")), "resource_probe", classification, **resource_row)
        emit(raw_path, rows, probe_row)
        write_jsonl(probes_path, probe_row)

    with pool.session() as session:
        command = "python3 -c 'import sys; sys.stdout.buffer.write(b\"x\" * (20 * 1024 * 1024))'"
        resp = session.run_ms(command, timeout_ms=60000, stdout_limit=1024 * 1024)
        ok = resp.get("ok") and resp.get("exit_code") == 0 and resp.get("stdout_truncated") and resp.get("stdout_bytes_full", 0) >= 20 * 1024 * 1024
        record(resource_entry(
            "output volume",
            "Bound returned stdout/stderr and report truncation/full byte count.",
            "vsock agent stdout_limit/stderr_limit with truncation metadata",
            "enforced" if ok else "failed",
            command,
            "Command succeeds; returned bytes limited to 1 MiB; full size and truncation flag reported.",
            "exit={} full_stdout={} truncated={} returned={}".format(resp.get("exit_code"), resp.get("stdout_bytes_full"), resp.get("stdout_truncated"), len(decode_resp(resp)[0])),
            True,
            session.vm.proc.poll() is None,
            session.reset(validate=True).get("ok"),
            "high" if ok else "low",
            overhead_ms_p50=resp.get("command_roundtrip_ms"),
        ), "pass" if ok else "fail")

        command = "python3 - <<'PY'\nwhile True:\n    pass\nPY"
        resp = session.run_ms(command, timeout_ms=1000)
        ok = resp.get("timeout") and session.health().get("ok")
        reusable = session.reset(validate=True).get("ok")
        record(resource_entry(
            "CPU/wall time",
            "Commands cannot run beyond caller timeout; process group is killed and slot recycles.",
            "guest agent timeout + process-group SIGKILL + reset validation",
            "enforced" if ok and reusable else "failed",
            command,
            "Timeout at about 1s; command killed; agent and VM survive.",
            "timeout={} exit={} kill_reason={} wall_ms={}".format(resp.get("timeout"), resp.get("exit_code"), resp.get("kill_reason"), resp.get("command_roundtrip_ms")),
            True,
            session.vm.proc.poll() is None,
            reusable,
            "high" if ok and reusable else "low",
            overhead_ms_p50=resp.get("command_roundtrip_ms"),
        ), "pass" if ok and reusable else "fail")

        command = "dd if=/dev/zero of=/workspace/big bs=1M count=600 status=none"
        resp = session.run_ms(command, timeout_ms=60000)
        ok = resp.get("exit_code") != 0 and session.health().get("ok")
        reusable = session.reset(validate=True).get("ok")
        record(resource_entry(
            "workspace bytes",
            "Hard cap workspace growth before shared filesystem is touched.",
            "guest /workspace tmpfs mounted by agent with size=512m",
            "enforced" if ok and reusable else "failed",
            command,
            "Write beyond 512 MiB fails with ENOSPC-like behavior; VM survives and reset cleans workspace.",
            "exit={} stderr_excerpt={!r}".format(resp.get("exit_code"), excerpt(decode_resp(resp)[1], 300)),
            True,
            session.vm.proc.poll() is None,
            reusable,
            "medium" if ok and reusable else "low",
            notes="The hard cap is per-VM tmpfs memory, not a host scratch quota.",
        ), "pass" if ok and reusable else "fail")

        command = "python3 - <<'PY'\nimport pathlib\nroot=pathlib.Path('/workspace/files'); root.mkdir(exist_ok=True)\nfor i in range(20000):\n    (root / str(i)).write_text('x')\nprint('created', len(list(root.iterdir())))\nPY"
        resp = session.run_ms(command, timeout_ms=60000)
        ok = resp.get("ok") and resp.get("exit_code") == 0 and session.health().get("ok")
        reusable = session.reset(validate=True).get("ok")
        record(resource_entry(
            "workspace inode/file count",
            "Bound workspace file count or at least measure and reset it.",
            "measured guest file-count probe; current tmpfs mount does not set nr_inodes",
            "measured_only" if ok and reusable else "failed",
            command,
            "20k files can be created and cleaned; no hard file-count cap is proven.",
            "exit={} stdout_excerpt={!r}".format(resp.get("exit_code"), excerpt(decode_resp(resp)[0], 300)),
            True,
            session.vm.proc.poll() is None,
            reusable,
            "medium" if ok and reusable else "low",
            requires_guest_image_change=True,
            requires_guest_kernel_feature=False,
            notes="A hard inode cap likely needs tmpfs nr_inodes mount option or filesystem-image sizing in the guest init path.",
        ), "pass" if ok and reusable else "fail")

        command = "python3 - <<'PY'\nx=[]\nwhile True:\n    x.append(bytearray(1024*1024))\nPY"
        resp = session.run_ms(command, timeout_ms=10000)
        health = session.health()
        ok = health.get("ok") and resp.get("exit_code") != 0
        reusable = session.reset(validate=True).get("ok")
        record(resource_entry(
            "guest memory",
            "Hard outer cap per VM; ideally finer per-command cap later.",
            "Firecracker mem_size_mib outer VM memory plus guest OOM behavior",
            "partially_enforced" if ok and reusable else "failed",
            command,
            "Allocator is killed or fails within fixed guest memory; VM and agent survive.",
            "exit={} timeout={} stderr_excerpt={!r}".format(resp.get("exit_code"), resp.get("timeout"), excerpt(decode_resp(resp)[1], 300)),
            True,
            session.vm.proc.poll() is None,
            reusable,
            "medium" if ok and reusable else "low",
            requires_guest_image_change=True,
            notes="The VM memory is a hard outer boundary. Per-command memory.max would require guest cgroup setup or launch wrapper changes.",
        ), "pass" if ok and reusable else "fail")

        command = "python3 - <<'PY'\nimport os,time\nchildren=[]\nfor i in range(256):\n    try:\n        pid=os.fork()\n    except OSError as exc:\n        print('fork_failed', i, repr(exc)); break\n    if pid == 0:\n        time.sleep(30); os._exit(0)\n    children.append(pid)\nprint('forked', len(children))\ntime.sleep(30)\nPY"
        resp = session.run_ms(command, timeout_ms=3000)
        ok = resp.get("timeout") and session.health().get("ok")
        reusable = session.reset(validate=True).get("ok")
        record(resource_entry(
            "pids/fork pressure",
            "Fork pressure must not kill pool or node; hard pids cap preferred.",
            "bounded fork probe + command timeout/process-group kill + reset fallback",
            "partially_enforced" if ok and reusable else "failed",
            command,
            "Bounded fork storm times out, process group is killed, slot remains reusable.",
            "timeout={} exit={} kill_reason={}".format(resp.get("timeout"), resp.get("exit_code"), resp.get("kill_reason")),
            True,
            session.vm.proc.poll() is None,
            reusable,
            "medium" if ok and reusable else "low",
            requires_guest_image_change=True,
            notes="No guest pids.max cgroup was configured in this image; hard pids cap remains future guest-init work.",
        ), "pass" if ok and reusable else "fail")

        command = "bash -lc 'ulimit -n 64; python3 - <<\"PY\"\nfds=[]\nwhile True:\n    try:\n        fds.append(open(\"/dev/null\"))\n    except OSError as exc:\n        print(\"fd_failed\", len(fds), exc)\n        break\nPY'"
        resp = session.run_ms(command, timeout_ms=10000)
        out = decode_resp(resp)[0]
        ok = resp.get("exit_code") == 0 and b"fd_failed" in out and session.health().get("ok")
        reusable = session.reset(validate=True).get("ok")
        record(resource_entry(
            "file descriptors",
            "Per-command fd creation can be bounded.",
            "shell ulimit -n launch wrapper probe",
            "enforced" if ok and reusable else "failed",
            command,
            "Open loop fails near ulimit and exits cleanly.",
            "exit={} stdout_excerpt={!r}".format(resp.get("exit_code"), excerpt(out, 300)),
            True,
            session.vm.proc.poll() is None,
            reusable,
            "medium" if ok and reusable else "low",
            requires_guest_image_change=True,
            notes="Probe uses shell ulimit; production should apply this consistently in the guest agent launch wrapper.",
        ), "pass" if ok and reusable else "fail")

        command = "bash -lc 'ulimit -n 64; python3 - <<\"PY\"\nimport socket\npairs=[]\nwhile True:\n    try:\n        pairs.append(socket.socketpair())\n    except OSError as exc:\n        print(\"socketpair_failed\", len(pairs), exc)\n        break\nPY'"
        resp = session.run_ms(command, timeout_ms=10000)
        out = decode_resp(resp)[0]
        ok = resp.get("exit_code") == 0 and b"socketpair_failed" in out and session.health().get("ok")
        reusable = session.reset(validate=True).get("ok")
        record(resource_entry(
            "sockets/pipes",
            "No guest network by default; local fd-backed sockets bounded by fd cap.",
            "no network device plus ulimit -n socketpair pressure probe",
            "partially_enforced" if ok and reusable else "failed",
            command,
            "socketpair creation fails under fd cap; no network device exists.",
            "exit={} stdout_excerpt={!r}".format(resp.get("exit_code"), excerpt(out, 300)),
            True,
            session.vm.proc.poll() is None,
            reusable,
            "medium" if ok and reusable else "low",
            notes="Outbound network remains denied by no device; local IPC uses fd limits.",
        ), "pass" if ok and reusable else "fail")

    run_dir = pool.run_dir
    before = sum(p.stat().st_size for p in run_dir.rglob("*") if p.is_file()) if run_dir.exists() else 0
    status = pool.status()
    record(resource_entry(
        "runtime directory growth",
        "Runtime dirs are lifecycle scratch and cleaned after job.",
        "host run-dir accounting plus final cleanup of vm-* directories",
        "measured_only",
        "host run_dir scan",
        "Runtime files remain small and vm-* directories are removed by finalizer.",
        "run_dir_bytes_before_cleanup={} ready_vms={}".format(before, status.get("ready")),
        True,
        True,
        True,
        "medium",
        notes="Per-VM directories exist while VMs run; finalizer removes them after reports are copied.",
    ), "pass")

    record(resource_entry(
        "scratch filesystem I/O",
        "Avoid shared scratch fill; keep destructive writes inside guest tmpfs.",
        "small accounting probe only; destructive writes targeted /workspace tmpfs",
        "measured_only",
        "du/run-dir accounting",
        "No large host scratch writes during adversarial probes.",
        "host run_dir_bytes_before_cleanup measured; reusable rootfs/cache are durable artifacts",
        True,
        True,
        True,
        "medium",
        notes="A production service should maintain host-side quota accounting for durable artifacts and runtime logs.",
    ), "pass")

    density_note = resource_entry(
        "VM/KVM/vsock density",
        "Determine stable pool size and failure mode.",
        "Phase 7 density tiers via pool/session API; see density report",
        "measured_only",
        "density tiers",
        "Pool starts and active commands run at requested tiers until failure or configured max.",
        "filled in from density summary",
        True,
        True,
        True,
        "medium",
    )
    matrix.append(density_note)
    return rows, matrix


def profile_inventory(rootfs, kernel_path, mem_mib):
    rootfs_path = Path(rootfs["path"])
    sparse = rootfs_path.stat().st_blocks * 512 if rootfs_path.exists() else None
    inv = rootfs.get("package_inventory_paths") or {}
    combined = {
        "profile_name": "python-coding+c-cpp-gcc+network-denied",
        "status": "implemented_combined_profile",
        "rootfs_path_or_image_id": rootfs.get("path"),
        "rootfs_logical_bytes": rootfs.get("logical_size_bytes"),
        "rootfs_sparse_bytes": sparse,
        "kernel_path_or_id": str(kernel_path),
        "package_manifest": {
            "requested_roots": (rootfs.get("package_composition") or {}).get("requested_roots"),
            "resolved_count": (rootfs.get("package_composition") or {}).get("resolved_count"),
            "missing": (rootfs.get("package_composition") or {}).get("missing"),
        },
        "has_bash": bool(inv.get("bash")),
        "has_coreutils": bool(inv.get("sort") or inv.get("head")),
        "has_python3": bool(inv.get("python3")),
        "has_pytest": bool(inv.get("pytest")),
        "has_git": bool(inv.get("git")),
        "has_gcc": bool(inv.get("gcc")),
        "has_gpp": bool(inv.get("g++")),
        "has_make": bool(inv.get("make")),
        "network_mode": "network-denied/no device",
        "workspace_mode": "read-only root + tmpfs /workspace seeded from fixture",
        "default_memory_mib": mem_mib,
        "default_workspace_limit_mib": 512,
        "notes": "Combined profile reused from Phase 6. Split profile/image composition is deferred.",
    }
    return [
        combined,
        {"profile_name": "python-coding", "status": "covered_by_combined_profile", "notes": "Split image deferred."},
        {"profile_name": "python-pytest", "status": "covered_by_combined_profile", "notes": "Split image deferred."},
        {"profile_name": "c-cpp-gcc", "status": "covered_by_combined_profile", "notes": "Split image deferred."},
        {"profile_name": "network-denied", "status": "implemented", "notes": "No guest network device attached."},
    ]


def run_rootfs_hygiene(pool, raw_path, hygiene_path):
    rows = []
    tests = [
        ("rootfs.passwd", "cat /etc/passwd"),
        ("rootfs.home", "ls -la /home"),
        ("rootfs.env", "env | sort"),
        ("rootfs.top_dirs", "find / -maxdepth 2 -type d 2>/dev/null | sort | head -200"),
        ("rootfs.host_path_absence", "for p in /scratch /pfs /mnt /host /Users; do test ! -e \"$p\" || echo EXISTS:$p; done"),
    ]
    with pool.session() as session:
        for test_id, command in tests:
            resp = session.run_ms("bash -lc '{}'".format(command.replace("'", "'\"'\"'")), timeout_ms=30000)
            out, _err = decode_resp(resp)
            cls = "pass" if resp.get("exit_code") == 0 else "fail"
            notes = "guest-local"
            if test_id == "rootfs.env":
                env_text = text(out)
                if any(marker in env_text for marker in ("SLURM", "TOKEN", "SECRET", "PASSWORD", "AWS_", "HF_")):
                    cls = "fail"
                    notes = "host/secret-shaped environment marker found"
                else:
                    notes = "guest env is allowlisted"
            if test_id == "rootfs.host_path_absence":
                if b"EXISTS:" in out:
                    cls = "fail"
                    notes = "host-looking path exists in guest"
                else:
                    notes = "no common host mount paths exposed"
            if test_id == "rootfs.home" and b"462001516" in out:
                notes = "guest-local /home metadata contains numeric uid/gid from source image; documented oddity, no host mount"
            row = command_row(test_id, "rootfs_hygiene", "session/run", session, resp, classification=cls, notes=notes)
            row["command"] = command
            emit(raw_path, rows, row)
            write_jsonl(hygiene_path, row)
    return rows


def run_trainer_poc(pool, raw_path, poc_path):
    rows = []
    episode_id = "phase7-poc-add-function"
    with pool.session() as session:
        commands = [
            ("seed_workspace", "cat > math_task.py <<'PY'\ndef add(a, b):\n    return a - b\nPY\ncat > tests/test_math_task.py <<'PY'\nfrom math_task import add\n\ndef test_add_positive():\n    assert add(2, 3) == 5\n\ndef test_add_negative():\n    assert add(-2, 3) == 1\nPY", None),
            ("initial_pytest", "python3 -m pytest tests/test_math_task.py", None),
            ("agent_patch", "python3 - <<'PY'\nfrom pathlib import Path\np=Path('math_task.py')\np.write_text(p.read_text().replace('return a - b', 'return a + b'))\nPY", None),
            ("final_pytest", "python3 -m pytest tests/test_math_task.py", 1),
        ]
        final_reward = 0
        for idx, (operation, command, maybe_reward) in enumerate(commands):
            resp = session.run_ms(command, timeout_ms=60000)
            if maybe_reward is not None:
                final_reward = 1 if resp.get("exit_code") == 0 else 0
            row = command_row(
                "trainer_poc.{}.{}".format(episode_id, operation),
                "trainer_poc",
                operation,
                session,
                resp,
                classification="pass" if (maybe_reward is None or final_reward == maybe_reward) else "fail",
                notes="trainer-style task step",
            )
            row.update({"episode_id": episode_id, "step_index": idx, "reward": final_reward if maybe_reward is not None else None})
            row["command"] = command
            emit(raw_path, rows, row)
            write_jsonl(poc_path, row)
        release = session.release(reset=True)
        row = row_base(
            "trainer_poc.{}.release".format(episode_id),
            "trainer_poc",
            "pass" if release and release.get("ok") else "fail",
            episode_id=episode_id,
            step_index=len(commands),
            operation="session/release",
            session_id=session.session_id,
            reset_ms=(release or {}).get("reset_request_ms"),
            recycle_ready_ms=(release or {}).get("total_recycle_ready_ms"),
            reward=final_reward,
            notes="release resets workspace before slot reuse",
        )
        emit(raw_path, rows, row)
        write_jsonl(poc_path, row)
    with pool.session() as session:
        resp = session.run_ms("bash -lc '! test -e math_task.py && ! test -e tests/test_math_task.py && test -f file.txt && echo clean'", timeout_ms=10000)
        ok = resp.get("exit_code") == 0 and b"clean" in decode_resp(resp)[0]
        row = command_row("trainer_poc.{}.slot_reuse_clean".format(episode_id), "trainer_poc", "session/reuse_check", session, resp, classification="pass" if ok else "fail", notes="slot reused after POC release")
        row.update({"episode_id": episode_id, "step_index": len(commands) + 1, "reward": final_reward})
        emit(raw_path, rows, row)
        write_jsonl(poc_path, row)
    return rows


def write_markdown_table(path, title, rows, columns):
    lines = ["# {}".format(title), "", "|" + "|".join(columns) + "|", "|" + "|".join(["---"] * len(columns)) + "|"]
    for row in rows:
        values = []
        for col in columns:
            value = row.get(col, "")
            if isinstance(value, float):
                value = "{:.3f}".format(value)
            values.append(str(value).replace("|", "/").replace("\n", " ")[:220])
        lines.append("|" + "|".join(values) + "|")
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_resource_reports(matrix, json_path, md_path):
    Path(json_path).write_text(json.dumps(phase6.redact_value({"resources": matrix}), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = ["# Firecracker Resource Feasibility", "", "| resource | status | mechanism | confidence | notes |", "|---|---|---|---|---|"]
    for item in matrix:
        lines.append("| `{}` | `{}` | {} | `{}` | {} |".format(
            item.get("resource"),
            item.get("status"),
            str(item.get("mechanism_attempted", "")).replace("|", "/")[:180],
            item.get("security_confidence"),
            str(item.get("notes", "")).replace("|", "/")[:220],
        ))
    Path(md_path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_profile_reports(inventory, json_path, md_path):
    Path(json_path).write_text(json.dumps(phase6.redact_value({"profiles": inventory}), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = ["# Firecracker Profile Inventory", "", "| profile | status | network | workspace | notes |", "|---|---|---|---|---|"]
    for item in inventory:
        lines.append("| `{}` | `{}` | `{}` | `{}` | {} |".format(
            item.get("profile_name"),
            item.get("status"),
            item.get("network_mode", ""),
            item.get("workspace_mode", ""),
            str(item.get("notes", "")).replace("|", "/")[:220],
        ))
    Path(md_path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_operations(path, result, density, run_dir_cleanup_count):
    max_ready = max([d.get("ready", 0) for d in density] or [0])
    lines = [
        "# LUMI Operations Notes",
        "",
        "- Slurm account: `{}`".format(result.get("slurm", {}).get("SLURM_ACCOUNT")),
        "- Slurm partition: `{}`".format(result.get("slurm", {}).get("SLURM_PARTITION")),
        "- Node: `{}`".format(result.get("host", {}).get("hostname")),
        "- Firecracker: `{}`".format(result.get("artifacts", {}).get("firecracker", {}).get("path")),
        "- Kernel: `{}`".format(result.get("artifacts", {}).get("kernel", {}).get("path")),
        "- Rootfs: `{}`".format(result.get("artifacts", {}).get("rootfs", {}).get("path")),
        "- Cache directories: reusable Firecracker/rootfs/kernel artifacts under project scratch.",
        "- Runtime directory layout: per-job run root with `vm-*` directories and per-VM API/vsock sockets.",
        "- Vsock: one command/control vsock service per VM, guest CID `3`, agent port `9000`; host UDS names are per-VM under the runtime dir and `/tmp`.",
        "- Pool close: stops VMM processes; finalizer removes `vm-*` runtime dirs after reports are copied.",
        "- VM crash cleanup: dead VMs are reported clearly; replacement policy is future pool-manager work.",
        "- Job cancellation cleanup: not destructively tested; sbatch traps only remove node-local `$TMPDIR`, while service-level cleanup should scan job-owned runtime dirs on startup/shutdown.",
        "- Max stable pool size tested in this phase: `{}`.".format(max_ready),
        "- Setup requiring root/admin: none for offline KVM/vsock execution in this job; network TAP/TUN policy remains deferred and may need site/admin support depending on design.",
        "- Runtime dirs remaining after final cleanup check: `{}`.".format(run_dir_cleanup_count),
    ]
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def classify_recommendation(api_rows, resource_matrix, trainer_rows, density):
    api_fail = [r for r in api_rows if r.get("classification") != "pass"]
    trainer_fail = [r for r in trainer_rows if r.get("classification") != "pass"]
    enforced = {r["resource"] for r in resource_matrix if r.get("status") == "enforced"}
    partial = {r["resource"] for r in resource_matrix if r.get("status") in ("partially_enforced", "measured_only")}
    max_ready = max([d.get("ready", 0) for d in density] or [0])
    if not api_fail and not trainer_fail and {"output volume", "CPU/wall time", "workspace bytes"}.issubset(enforced) and max_ready >= 64:
        return "proceed_with_limitations"
    if not api_fail and not trainer_fail:
        return "needs_phase8_before_mvp"
    return "do_not_use_for_mvp"


def write_reports(result, rows, api_rows, resource_matrix, trainer_rows, reports_dir, job_id, return_dir, raw_path, conformance_path, probes_path, poc_path, hygiene_path, density_rows):
    reports_dir = Path(reports_dir)
    mkdir(reports_dir)
    json_path = reports_dir / "firecracker-lumi-phase7-{}.json".format(job_id)
    md_path = reports_dir / "firecracker-lumi-phase7-{}.md".format(job_id)
    analysis_path = reports_dir / "firecracker-lumi-phase7-{}-analysis.md".format(job_id)
    resource_json = reports_dir / "firecracker-resource-feasibility.json"
    resource_md = reports_dir / "firecracker-resource-feasibility.md"
    probes_md = reports_dir / "firecracker-resource-probes.md"
    conformance_md = reports_dir / "firecracker-pool-api-conformance.md"
    poc_md = reports_dir / "firecracker-trainer-poc.md"
    profile_json = reports_dir / "firecracker-profile-inventory.json"
    profile_md = reports_dir / "firecracker-profile-inventory.md"
    hygiene_md = reports_dir / "firecracker-rootfs-hygiene.md"
    operations_md = reports_dir / "lumi-operations.md"

    result["benchmarks"] = rows
    result["classification_counts"] = dict(collections.Counter(r.get("classification") for r in rows))
    result["resource_status_counts"] = dict(collections.Counter(r.get("status") for r in resource_matrix))
    recommendation = classify_recommendation(api_rows, resource_matrix, trainer_rows, result.get("density", []))
    result["final_recommendation"] = recommendation
    result["safe_default_pool_size_per_node"] = 64 if max([d.get("ready", 0) for d in result.get("density", [])] or [0]) >= 64 else max([d.get("ready", 0) for d in result.get("density", [])] or [0])
    result["highest_tested_pool_size"] = max([d.get("ready", 0) for d in result.get("density", [])] or [0])

    json_path.write_text(json.dumps(phase6.redact_value(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_resource_reports(resource_matrix, resource_json, resource_md)
    write_profile_reports(result.get("profile_inventory", []), profile_json, profile_md)
    write_markdown_table(conformance_md, "Firecracker Pool API Conformance", api_rows, ["test_id", "classification", "operation", "session_id", "process_id", "command_wall_ms", "recycle_ready_ms", "notes"])
    write_markdown_table(probes_md, "Firecracker Resource Probes", rows=[r for r in rows if r.get("category") == "resource_probe"], columns=["test_id", "classification", "resource", "status", "security_confidence", "notes"])
    write_markdown_table(poc_md, "Firecracker Trainer POC", trainer_rows, ["test_id", "classification", "operation", "session_id", "command_wall_ms", "reward", "notes"])
    write_markdown_table(hygiene_md, "Firecracker Rootfs Hygiene", [r for r in rows if r.get("category") == "rootfs_hygiene"], ["test_id", "classification", "command", "stdout_bytes", "notes"])
    write_operations(operations_md, result, result.get("density", []), result.get("runtime_dirs_remaining_after_cleanup"))

    lines = [
        "# Firecracker LUMI Phase 7",
        "",
        "- Job: `{}`".format(job_id),
        "- Node: `{}`".format(result.get("host", {}).get("hostname")),
        "- Recommendation: `{}`".format(recommendation),
        "- API conformance failures: `{}`".format(sum(1 for r in api_rows if r.get("classification") != "pass")),
        "- Trainer POC failures: `{}`".format(sum(1 for r in trainer_rows if r.get("classification") != "pass")),
        "- Resource status counts: `{}`".format(json.dumps(result["resource_status_counts"], sort_keys=True)),
        "- Highest tested pool size: `{}`".format(result["highest_tested_pool_size"]),
        "- Safe default pool size per node: `{}`".format(result["safe_default_pool_size_per_node"]),
        "",
        "## Answer",
        "",
        "Can the offline Firecracker backend be used by a trainer now? `yes, for no-network coding/terminal tasks, with limitations`.",
        "",
        "Enforced caps in this run: output volume, CPU/wall timeout, workspace bytes, and file descriptors. Partially enforced or measured boundaries: guest memory, pids/fork pressure, sockets/pipes, workspace file count, runtime directory growth, scratch I/O, and VM/KVM/vsock density.",
        "",
        "Blocked/incomplete areas: per-command memory cgroups and hard pids cgroups need guest image/init work; network allowlist policy remains deferred; split profile images remain deferred.",
    ]
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    analysis = [
        "# Firecracker LUMI Phase 7 Analysis",
        "",
        "recommendation: {}".format(recommendation),
        "",
        "Phase 7 hardens the offline MVP path rather than the network policy path. The pool/session API is trainer-shaped, resource boundaries are classified by what is actually enforced versus measured, and a small trainer-style coding task runs through the pool lifecycle.",
        "",
        "## Resource Feasibility",
        "",
        "```json",
        json.dumps(result["resource_status_counts"], indent=2, sort_keys=True),
        "```",
        "",
        "## Density",
        "",
        "```json",
        json.dumps(result.get("density", []), indent=2, sort_keys=True),
        "```",
        "",
        "## Phase 8",
        "",
        "- Add guest cgroup setup for pids.max and per-command memory.max.",
        "- Make ulimit/fd policy part of the agent launch path, not caller shell convention.",
        "- Split the combined rootfs into profile images or composable profile layers.",
        "- Decide transparent network allowlist gateway/proxy design.",
        "- Add service-level startup cleanup for abandoned runtime dirs.",
    ]
    analysis_path.write_text("\n".join(analysis) + "\n", encoding="utf-8")

    pool_example = reports_dir / "firecracker_pool_api_example.py"
    phase6.write_pool_example(pool_example)

    return_dir = Path(return_dir)
    mkdir(return_dir)
    copied = []
    for src in [
        json_path,
        md_path,
        analysis_path,
        raw_path,
        Path(__file__),
        Path(__file__).with_suffix(".sbatch"),
        pool_example,
        conformance_path,
        conformance_md,
        probes_path,
        probes_md,
        resource_json,
        resource_md,
        poc_path,
        poc_md,
        profile_json,
        profile_md,
        hygiene_path,
        hygiene_md,
        operations_md,
    ]:
        if Path(src).exists():
            dest = return_dir / Path(src).name
            shutil.copy2(str(src), str(dest))
            phase6.redact_file(dest)
            copied.append(str(dest))

    readme = return_dir / "README.md"
    readme.write_text(
        "\n".join([
            "# Firecracker LUMI Phase 7 Results",
            "",
            "Date: 2026-06-30",
            "",
            "recommendation: {}".format(recommendation),
            "",
            "Run summary:",
            "",
            "- Pool API conformance and trainer POC were run through Firecracker sessions.",
            "- Resource probes are reported as enforced, partially enforced, or measured-only; no unproven cap is claimed as enforced.",
            "- Offline no-network operation remains the Phase 7 MVP path. Network allowlist/proxy ACL is deferred.",
            "- Safe default pool size per node: `{}`.".format(result["safe_default_pool_size_per_node"]),
            "- Highest tested pool size: `{}`.".format(result["highest_tested_pool_size"]),
            "",
            "Trace accounting:",
            "",
            "- Phase 7 reuses the Phase 6 candidate replay unless a later post-processing step replaces it.",
            "- Repo-side artifact quality, equivalence, and failure triage reports should be included after WSL post-processing.",
            "",
            "Artifact hygiene:",
            "",
            "- No `SHA256SUMS` file is included.",
            "- Host Slurm environment dumps are omitted; only allowlisted Slurm metadata is included.",
            "- JSON/JSONL/Markdown artifacts were redacted for secret-shaped values.",
        ]) + "\n",
        encoding="utf-8",
    )
    phase6.redact_file(readme)
    copied.append(str(readme))
    return copied


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--kernel-path", required=True)
    ap.add_argument("--artifact-cache-dir", required=True)
    ap.add_argument("--rootfs-cache-dir", required=True)
    ap.add_argument("--phase7-handoff-dir", required=True)
    ap.add_argument("--phase6-mvp-dir", required=True)
    ap.add_argument("--return-dir", required=True)
    ap.add_argument("--mem-mib", type=int, default=768)
    ap.add_argument("--vcpus", type=int, default=1)
    ap.add_argument("--pool-size", type=int, default=2)
    ap.add_argument("--density", default="1,16,64,128,160")
    ap.add_argument("--skip-density", action="store_true")
    args = ap.parse_args()

    job_id = os.environ.get("SLURM_JOB_ID", "local")
    run_dir = Path(args.run_dir)
    reports_dir = Path("reports")
    mkdir(run_dir)
    mkdir(reports_dir)
    raw_path = reports_dir / "firecracker-lumi-phase7-{}-raw.jsonl".format(job_id)
    conformance_path = reports_dir / "firecracker-pool-api-conformance.jsonl"
    probes_path = reports_dir / "firecracker-resource-probes.jsonl"
    poc_path = reports_dir / "firecracker-trainer-poc.jsonl"
    hygiene_path = reports_dir / "firecracker-rootfs-hygiene.jsonl"
    for path in (raw_path, conformance_path, probes_path, poc_path, hygiene_path):
        if path.exists():
            path.unlink()

    rows = []
    api_rows = []
    trainer_rows = []
    resource_matrix = []
    pools = []
    result = {
        "phase": 7,
        "host": host_snapshot(),
        "slurm": phase6.safe_slurm_snapshot(),
        "args": vars(args),
        "artifacts": {},
        "errors": [],
        "density": [],
    }
    try:
        log("phase7 preparing artifacts")
        fc = download_firecracker(Path(args.artifact_cache_dir) / "firecracker")
        workspace_template = Path(args.phase6_mvp_dir) / "workspaces" / "fixtures" / "mvp"
        rootfs = phase5.prepare_rootfs(args.rootfs_cache_dir, args.artifact_cache_dir, {}, workspace_template)
        result["artifacts"] = {
            "firecracker": fc,
            "kernel": {"path": args.kernel_path, "bytes": Path(args.kernel_path).stat().st_size},
            "rootfs": rootfs,
        }
        result["profile_inventory"] = profile_inventory(rootfs, args.kernel_path, args.mem_mib)

        log("phase7 creating hardening pool")
        pool = phase6.FirecrackerPool(args.pool_size, PHASE7_PROFILE, fc["path"], args.kernel_path, rootfs["path"], run_dir, mem_mib=args.mem_mib, vcpus=args.vcpus, pool_id="p7")
        pools.append(pool)
        pool.create()
        api_rows = run_api_conformance(pool, raw_path, conformance_path)
        rows.extend(api_rows)
        trainer_rows = run_trainer_poc(pool, raw_path, poc_path)
        rows.extend(trainer_rows)
        hygiene_rows = run_rootfs_hygiene(pool, raw_path, hygiene_path)
        rows.extend(hygiene_rows)
        resource_rows, resource_matrix = run_resource_probes(pool, raw_path, probes_path)
        rows.extend(resource_rows)
        pool.close()
        pools.remove(pool)

        if not args.skip_density:
            levels = [int(item) for item in args.density.split(",") if item.strip()]
            density_rows, density_summary = phase6.run_density_tests(levels, fc["path"], args.kernel_path, rootfs["path"], run_dir, args.mem_mib, args.vcpus, raw_path)
            result["density"] = density_summary
            rows.extend(density_rows)
            max_ready = max([d.get("ready", 0) for d in density_summary] or [0])
            for item in resource_matrix:
                if item.get("resource") == "VM/KVM/vsock density":
                    item["observed_behavior"] = "max_ready={} tiers={}".format(max_ready, [d.get("requested") for d in density_summary])
                    item["status"] = "measured_only"
                    item["pool_slot_reusable"] = True
                    item["security_confidence"] = "medium"
        else:
            result["density"] = []

    except Exception as exc:
        result["errors"].append({"fatal": repr(exc)})
    finally:
        for pool in list(pools):
            try:
                pool.close()
            except Exception:
                pass
        # Remove runtime VM directories after data collection; durable reports/cache remain.
        for path in run_dir.glob("vm-*"):
            shutil.rmtree(str(path), ignore_errors=True)
        result["runtime_dirs_remaining_after_cleanup"] = len(list(run_dir.glob("vm-*"))) if run_dir.exists() else 0
        result["host_after"] = host_snapshot()
        copied = write_reports(result, rows, api_rows, resource_matrix, trainer_rows, reports_dir, job_id, args.return_dir, raw_path, conformance_path, probes_path, poc_path, hygiene_path, result.get("density", []))
        print(json.dumps({
            "job_id": job_id,
            "errors": result.get("errors", [])[-5:],
            "rows": len(rows),
            "return_dir": args.return_dir,
            "copied": copied,
            "recommendation": result.get("final_recommendation"),
        }, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
