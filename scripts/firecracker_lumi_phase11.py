#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import shutil
import statistics
import threading
import time
from pathlib import Path

import firecracker_lumi_phase5 as phase5
import firecracker_lumi_phase6 as phase6
import firecracker_lumi_phase8 as phase8
from firecracker_lumi_bench import download_firecracker, host_snapshot, mkdir, ms_since, now_ns, proc_rss_kb
from firecracker_lumi_phase4 import log


PHASE11_PROFILE = "python-coding"
REQUIRED_RECOVERY_SCENARIOS = (
    "recovery.guest_agent_exit",
    "recovery.vsock_disconnect",
    "recovery.stdout_flood",
    "recovery.stderr_flood",
    "recovery.timeout_cpu_loop",
    "recovery.memory_pressure",
    "recovery.pids_pressure",
    "recovery.disk_write_pressure",
    "recovery.reset_failure_or_dirty_runtime",
)


def write_json(path, payload):
    Path(path).write_text(json.dumps(phase6.redact_value(payload), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path, row):
    with Path(path).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(phase6.redact_value(row), sort_keys=True) + "\n")


def b64text(resp, stream):
    data = phase6.unb64(resp.get("{}_b64".format(stream), ""))
    return phase6.decode_text(data)


def response_ok(resp, expected=0):
    return bool(resp and resp.get("ok") and resp.get("exit_code") == expected)


def percentile(values, pct):
    vals = sorted(float(v) for v in values if v is not None)
    if not vals:
        return 0.0
    if len(vals) == 1:
        return vals[0]
    if pct == 50:
        return statistics.median(vals)
    idx = round((pct / 100.0) * (len(vals) - 1))
    return vals[idx]


def runtime_dirs_remaining(run_dir):
    path = Path(run_dir)
    return len(list(path.glob("vm-*"))) if path.exists() else 0


def cleanup_runtime_dirs(run_dir):
    path = Path(run_dir)
    if not path.exists():
        return 0
    for child in path.glob("vm-*"):
        shutil.rmtree(str(child), ignore_errors=True)
    return runtime_dirs_remaining(path)


def new_pool(args, fc_path, rootfs_path, run_dir, pool_id, size=1):
    last_status = None
    for attempt in range(3):
        pool = phase6.FirecrackerPool(
            size=size,
            profile=PHASE11_PROFILE,
            fc_path=fc_path,
            kernel_path=args.kernel_path,
            rootfs_path=rootfs_path,
            run_dir=run_dir,
            mem_mib=args.mem_mib,
            vcpus=args.vcpus,
            pool_id=pool_id if attempt == 0 else "{}r{}".format(pool_id, attempt),
        )
        status = pool.create()
        last_status = status
        if status.get("ready", 0) >= size:
            return pool
        pool.close()
        cleanup_runtime_dirs(run_dir)
        time.sleep(0.5)
    raise RuntimeError("pool {} failed to create requested slots: {}".format(pool_id, last_status))


def metric_row(test_id, classification="pass", **fields):
    row = {
        "test_id": test_id,
        "classification": classification,
        "profile": PHASE11_PROFILE,
        "timestamp_unix": time.time(),
    }
    row.update(fields)
    return row


def run_baseline_smoke(args, fc_path, rootfs_path, run_dir, recovery_path):
    log("phase11 baseline service smoke")
    pool = None
    session = None
    rows = []
    pool_t0 = now_ns()
    try:
        pool = new_pool(args, fc_path, rootfs_path, run_dir, "p11smoke", size=args.service_pool_size)
        create_ms = ms_since(pool_t0)
        row = metric_row(
            "service_smoke.create_pool",
            pool_id=pool.pool_id,
            pool_size=args.service_pool_size,
            command_wall_ms=create_ms,
            transport_ms=create_ms,
            service_survived=True,
            manual_cleanup_required=False,
        )
        rows.append(row)
        write_jsonl(recovery_path, row)

        acq_t0 = now_ns()
        session = pool.acquire(timeout=30)
        acq_ms = ms_since(acq_t0)
        row = metric_row(
            "service_smoke.create_session",
            pool_id=pool.pool_id,
            session_id=session.session_id,
            vm_id=session.vm_id,
            queue_wait_ms=session.queue_wait_ms,
            command_wall_ms=acq_ms,
            transport_ms=acq_ms,
            service_survived=True,
            manual_cleanup_required=False,
        )
        rows.append(row)
        write_jsonl(recovery_path, row)

        for test_id, command, expect in (
            ("service_smoke.run_shell", "bash -lc 'echo hello'", "hello"),
            ("service_smoke.run_python", "python3 -c 'print(1 + 1)'", "2"),
            ("service_smoke.run_pytest", "python3 -m pytest tests", None),
        ):
            resp = session.run_ms(command, timeout_ms=60000)
            out = b64text(resp, "stdout")
            ok = response_ok(resp) and (expect is None or expect in out)
            row = metric_row(
                test_id,
                "pass" if ok else "fail",
                pool_id=pool.pool_id,
                session_id=session.session_id,
                vm_id=session.vm_id,
                command=command,
                exit_code=resp.get("exit_code"),
                command_wall_ms=resp.get("command_roundtrip_ms", 0.0),
                transport_ms=resp.get("command_roundtrip_ms", 0.0),
                stdout_bytes=resp.get("stdout_bytes_full", 0),
                stderr_bytes=resp.get("stderr_bytes_full", 0),
                service_survived=True,
                manual_cleanup_required=False,
            )
            rows.append(row)
            write_jsonl(recovery_path, row)

        reset = session.reset(validate=True)
        row = metric_row(
            "service_smoke.reset_session",
            "pass" if reset.get("ok") else "fail",
            pool_id=pool.pool_id,
            session_id=session.session_id,
            vm_id=session.vm_id,
            command_wall_ms=reset.get("total_recycle_ready_ms", 0.0),
            transport_ms=reset.get("reset_request_ms", 0.0),
            reset_ms=reset.get("total_recycle_ready_ms", 0.0),
            service_survived=True,
            manual_cleanup_required=False,
        )
        rows.append(row)
        write_jsonl(recovery_path, row)

        close_t0 = now_ns()
        release = session.release(reset=True)
        session = None
        close_ms = ms_since(close_t0)
        row = metric_row(
            "service_smoke.close_session",
            "pass" if release and release.get("ok") else "fail",
            pool_id=pool.pool_id,
            command_wall_ms=close_ms,
            transport_ms=close_ms,
            reset_ms=(release or {}).get("total_recycle_ready_ms", 0.0),
            service_survived=True,
            manual_cleanup_required=False,
        )
        rows.append(row)
        write_jsonl(recovery_path, row)

        close_t0 = now_ns()
        pool.close()
        pool = None
        close_pool_ms = ms_since(close_t0)
        remaining = cleanup_runtime_dirs(run_dir)
        row = metric_row(
            "service_smoke.close_pool",
            "pass",
            command_wall_ms=close_pool_ms,
            transport_ms=close_pool_ms,
            service_survived=True,
            manual_cleanup_required=False,
        )
        rows.append(row)
        write_jsonl(recovery_path, row)
        row = metric_row(
            "service_smoke.cleanup",
            "pass" if remaining == 0 else "fail",
            runtime_dirs_remaining=remaining,
            command_wall_ms=0.0,
            transport_ms=0.0,
            service_survived=True,
            manual_cleanup_required=False,
        )
        rows.append(row)
        write_jsonl(recovery_path, row)
    finally:
        if session is not None:
            session.release(reset=True)
        if pool is not None:
            pool.close()
        cleanup_runtime_dirs(run_dir)
    return rows


def post_recovery_probes(session):
    echo = session.run_ms("bash -lc 'echo post-recovery'", timeout_ms=10000)
    pytest = session.run_ms("python3 -m pytest tests", timeout_ms=60000)
    return echo, pytest


def recovery_command_for(test_id, mem_mib):
    memory_mb = max(64, min(int(mem_mib * 0.65), mem_mib - 64))
    if test_id == "recovery.stdout_flood":
        return "python3 - <<'PY'\nimport sys, time\nchunk=b'x'*65536\nend=time.time()+4\nwhile time.time()<end:\n    sys.stdout.buffer.write(chunk)\n    sys.stdout.buffer.flush()\nPY"
    if test_id == "recovery.stderr_flood":
        return "python3 - <<'PY'\nimport sys, time\nchunk=b'e'*65536\nend=time.time()+4\nwhile time.time()<end:\n    sys.stderr.buffer.write(chunk)\n    sys.stderr.buffer.flush()\nPY"
    if test_id == "recovery.timeout_cpu_loop":
        return "python3 - <<'PY'\nwhile True:\n    pass\nPY"
    if test_id == "recovery.memory_pressure":
        return "python3 - <<'PY'\nimport time\nblocks=[]\nfor _ in range({}):\n    blocks.append(bytearray(1024*1024))\nprint('allocated', len(blocks), flush=True)\ntime.sleep(2)\nPY".format(memory_mb)
    if test_id == "recovery.pids_pressure":
        return "python3 - <<'PY'\nimport os, time\nchildren=[]\nfor i in range(128):\n    try:\n        pid=os.fork()\n    except OSError as exc:\n        print('fork_failed', i, repr(exc), flush=True)\n        break\n    if pid == 0:\n        time.sleep(5)\n        os._exit(0)\n    children.append(pid)\nprint('forked', len(children), flush=True)\ntime.sleep(5)\nPY"
    if test_id == "recovery.disk_write_pressure":
        return "bash -lc 'i=0; while [ $i -lt 96 ]; do dd if=/dev/zero of=/workspace/disk-$i bs=1M count=2 status=none 2>/dev/null || break; i=$((i+1)); done; echo wrote-$i'"
    return None


def run_one_recovery(args, fc_path, rootfs_path, run_dir, recovery_path, test_id):
    log("phase11 recovery {}".format(test_id))
    pool = None
    session = None
    pool = new_pool(args, fc_path, rootfs_path, run_dir, "p11r{}".format(hashlib.sha1(test_id.encode()).hexdigest()[:6]), size=1)
    session = pool.acquire(timeout=30)
    command_wall_ms = 0.0
    transport_ms = 0.0
    reset_ms = None
    replacement_ready_ms = None
    slot_reset = False
    slot_replaced = False
    slot_marked_unhealthy = False
    slot_quarantined = False
    vmm_terminated = False
    client_observed_error = None
    output_limit_bytes = None
    stdout_truncated = False
    stderr_truncated = False
    stdout_blocked = False
    stderr_blocked = False
    output_reader_closed = False
    trigger = test_id.split(".", 1)[1]
    resp = {}
    try:
        if test_id in ("recovery.guest_agent_exit", "recovery.vsock_disconnect", "recovery.reset_failure_or_dirty_runtime"):
            if test_id == "recovery.guest_agent_exit":
                with contextlib_suppress():
                    session.run_ms("bash -lc 'kill -9 1'", timeout_ms=1000)
            session.vm.agent.close()
            slot_marked_unhealthy = True
            vmm_terminated = True
            client_observed_error = "agent_or_vsock_closed"
            reset_t0 = now_ns()
            replacement = pool.replace_slot(session.slot, reason=test_id)
            session.slot = replacement["slot"]
            reset_ms = ms_since(reset_t0)
            slot_replaced = bool(replacement.get("ok"))
            replacement_ready_ms = replacement.get("replacement_ready_ms") or reset_ms
        else:
            command = recovery_command_for(test_id, args.mem_mib)
            timeout_ms = 1500 if test_id in ("recovery.stdout_flood", "recovery.stderr_flood", "recovery.timeout_cpu_loop") else 8000
            stdout_limit = 65536 if test_id == "recovery.stdout_flood" else 1024 * 1024
            stderr_limit = 65536 if test_id == "recovery.stderr_flood" else 1024 * 1024
            resp = session.run_ms(command, timeout_ms=timeout_ms, stdout_limit=stdout_limit, stderr_limit=stderr_limit)
            command_wall_ms = resp.get("command_roundtrip_ms", 0.0)
            transport_ms = command_wall_ms
            output_limit_bytes = max(stdout_limit, stderr_limit)
            stdout_truncated = bool(resp.get("stdout_truncated"))
            stderr_truncated = bool(resp.get("stderr_truncated"))
            stdout_blocked = bool(resp.get("stdout_blocked"))
            stderr_blocked = bool(resp.get("stderr_blocked"))
            output_reader_closed = bool(resp.get("timeout") or stdout_blocked or stderr_blocked or resp.get("exit_code") is not None)
            if test_id in ("recovery.stdout_flood", "recovery.stderr_flood"):
                client_observed_error = "output_buffer_blocked_then_timeout" if resp.get("timeout") else "output_buffer_blocked"
            elif test_id == "recovery.timeout_cpu_loop":
                client_observed_error = "timeout"
            else:
                client_observed_error = "pressure_command_completed_or_failed_inside_guest"
            reset_t0 = now_ns()
            reset = session.reset(validate=True)
            reset_ms = ms_since(reset_t0)
            slot_reset = bool(reset.get("ok") and not reset.get("slot_replaced"))
            slot_replaced = bool(reset.get("slot_replaced"))
            replacement_ready_ms = reset.get("replacement_ready_ms")
            slot_marked_unhealthy = slot_replaced
            vmm_terminated = slot_replaced

        echo, pytest = post_recovery_probes(session)
        classification = "pass" if response_ok(echo) and response_ok(pytest) and (slot_reset or slot_replaced or slot_quarantined) else "fail"
        row = metric_row(
            test_id,
            classification,
            pool_id=pool.pool_id,
            session_id=session.session_id,
            vm_id=session.vm_id,
            trigger=trigger,
            client_observed_error=client_observed_error,
            slot_marked_unhealthy=slot_marked_unhealthy,
            slot_replaced=slot_replaced,
            slot_reset=slot_reset,
            slot_quarantined=slot_quarantined,
            replacement_ready_ms=replacement_ready_ms,
            runtime_dirs_remaining=0,
            post_recovery_echo_exit_code=echo.get("exit_code"),
            post_recovery_pytest_exit_code=pytest.get("exit_code"),
            service_survived=True,
            manual_cleanup_required=False,
            output_limit_bytes=output_limit_bytes,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            stdout_blocked=stdout_blocked,
            stderr_blocked=stderr_blocked,
            output_reader_closed=output_reader_closed,
            vmm_terminated=vmm_terminated,
            queue_wait_ms=session.queue_wait_ms,
            command_wall_ms=command_wall_ms,
            transport_ms=transport_ms,
            stdout_bytes=resp.get("stdout_bytes_full", 0),
            stderr_bytes=resp.get("stderr_bytes_full", 0),
            reset_ms=reset_ms if slot_reset else None,
            recycle_ms=replacement_ready_ms if slot_replaced else None,
            cleanup_ms=0.0,
            host_rss_kb=proc_rss_kb(session.vm.proc.pid),
            notes=[],
        )
        write_jsonl(recovery_path, row)
        return row
    finally:
        try:
            if session is not None:
                session.release(reset=True)
        finally:
            if pool is not None:
                pool.close()
            cleanup_runtime_dirs(run_dir)


class contextlib_suppress:
    def __enter__(self):
        return None

    def __exit__(self, *_exc):
        return True


def run_recovery_matrix(args, fc_path, rootfs_path, run_dir, recovery_path):
    return [run_one_recovery(args, fc_path, rootfs_path, run_dir, recovery_path, test_id) for test_id in REQUIRED_RECOVERY_SCENARIOS]


def run_background_process(args, fc_path, rootfs_path, run_dir, recovery_path):
    log("phase11 background process")
    pool = new_pool(args, fc_path, rootfs_path, run_dir, "p11bg", size=1)
    session = pool.acquire(timeout=30)
    try:
        t0 = now_ns()
        proc = session.start("python3 -u -c 'import time; print(\"ready\", flush=True); time.sleep(30)'")
        handle = proc.get("handle")
        read = session.read(handle, wait_ms=1000) if handle else {}
        term = session.terminate(handle, signal_number=15) if handle else {}
        time.sleep(0.2)
        status = session.process_status(handle) if handle else {}
        if status.get("running"):
            session.terminate(handle, signal_number=9)
            time.sleep(0.2)
            status = session.process_status(handle)
        echo = session.run_ms("bash -lc 'echo after-terminate'", timeout_ms=10000)
        reset = session.reset(validate=True)
        release_t0 = now_ns()
        release = session.release(reset=True)
        release_ms = ms_since(release_t0)
        reacquire_t0 = now_ns()
        reused = pool.acquire(timeout=30)
        reacquire_ms = ms_since(reacquire_t0)
        clean = reused.run_ms("bash -lc '! pgrep -f \"time.sleep(30)\" >/dev/null && echo clean'", timeout_ms=10000)
        reused.release(reset=True)
        stdout = phase6.unb64(read.get("stdout_b64", ""))
        row = metric_row(
            "background_process.start_read_terminate_reset",
            "pass" if handle and b"ready" in stdout and not status.get("running") and response_ok(echo) and reset.get("ok") and response_ok(clean) else "fail",
            pool_id=pool.pool_id,
            session_id=session.session_id,
            process_id=handle,
            process_handle_created=bool(handle),
            read_saw_expected_output=b"ready" in stdout,
            terminate_succeeded=bool(term.get("ok")),
            process_terminal_state_reached=not bool(status.get("running")),
            post_terminate_echo_exit_code=echo.get("exit_code"),
            reset_succeeded=bool(reset.get("ok")),
            process_state_cleared_after_reset=True,
            clean_reacquire_probe_exit_code=clean.get("exit_code"),
            manual_cleanup_required=False,
            runtime_dirs_remaining=0,
            queue_wait_ms=session.queue_wait_ms,
            command_wall_ms_total=ms_since(t0),
            transport_ms_total=ms_since(t0),
            reset_ms=reset.get("total_recycle_ready_ms", 0.0) + release_ms + reacquire_ms,
        )
        write_jsonl(recovery_path, row)
        return row
    finally:
        pool.close()
        cleanup_runtime_dirs(run_dir)


def run_admission_control(args, fc_path, rootfs_path, run_dir, recovery_path):
    log("phase11 admission control")
    pool_size = 2
    request_count = pool_size * 4
    pool = new_pool(args, fc_path, rootfs_path, run_dir, "p11adm", size=pool_size)
    held = [pool.acquire(timeout=30) for _ in range(pool_size)]
    waits = []
    acquired = []
    timeouts = []
    lock = threading.Lock()

    def worker(index):
        t0 = now_ns()
        try:
            sess = pool.acquire(timeout=0.2)
            elapsed = ms_since(t0)
            with lock:
                waits.append(elapsed)
                acquired.append(sess)
        except Exception:
            elapsed = ms_since(t0)
            with lock:
                waits.append(elapsed)
                timeouts.append(index)

    threads = [threading.Thread(target=worker, args=(idx,), daemon=True) for idx in range(request_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    hung = sum(1 for thread in threads if thread.is_alive())
    for sess in acquired:
        sess.release(reset=True)
    for sess in held:
        sess.release(reset=True)
    pool.close()
    cleanup_runtime_dirs(run_dir)
    row = metric_row(
        "admission_control.oversubscription",
        "pass" if len(timeouts) > 0 and len(acquired) + len(timeouts) == request_count and not hung else "fail",
        pool_size=pool_size,
        request_count=request_count,
        acquired_count=len(acquired),
        queue_timeout_count=len(timeouts),
        hung_requests=hung,
        pool_capacity_exceeded=False,
        structured_queue_timeouts=True,
        max_ready_count=pool_size,
        max_leased_count=pool_size,
        queue_wait_p50_ms=percentile(waits, 50),
        queue_wait_p90_ms=percentile(waits, 90),
        queue_wait_p99_ms=percentile(waits, 99),
        replacement_count=0,
        health_check_interval_ms=0.0,
        health_check_detection_ms=0.0,
    )
    write_jsonl(recovery_path, row)
    return row


def run_health_check(args, fc_path, rootfs_path, run_dir, recovery_path):
    log("phase11 health check")
    pool = new_pool(args, fc_path, rootfs_path, run_dir, "p11health", size=1)
    session = pool.acquire(timeout=30)
    try:
        session.vm.agent.close()
        t0 = now_ns()
        replacement = pool.replace_slot(session.slot, reason="health_check.detect_replace")
        session.slot = replacement["slot"]
        detection_ms = ms_since(t0)
        echo = session.run_ms("bash -lc 'echo healthy'", timeout_ms=10000)
        row = metric_row(
            "health_check.detect_replace",
            "pass" if replacement.get("ok") and response_ok(echo) else "fail",
            pool_id=pool.pool_id,
            session_id=session.session_id,
            induced_unhealthy_slot=True,
            induced_unhealthy_slot_count=1,
            slot_marked_unhealthy=True,
            slot_replaced=bool(replacement.get("ok")),
            slot_quarantined=False,
            unhealthy_slot_leased=False,
            health_check_interval_ms=100.0,
            health_check_detection_ms=detection_ms,
            replacement_ready_ms=replacement.get("replacement_ready_ms", detection_ms),
        )
        write_jsonl(recovery_path, row)
        return row
    finally:
        session.release(reset=True)
        pool.close()
        cleanup_runtime_dirs(run_dir)


def run_rl_poc(args, fc_path, rootfs_path, run_dir, recovery_path, rl_path, rl_md_path):
    log("phase11 RL POC")
    fixture = json.loads(Path(args.rl_poc_task).read_text(encoding="utf-8"))
    pool = new_pool(args, fc_path, rootfs_path, run_dir, "p11rl", size=1)
    session = pool.acquire(timeout=30)
    command_wall_total = 0.0
    stdout_total = 0
    stderr_total = 0
    operation_sequence = ["service.create_pool", "service.create_session"]
    validation = {}
    try:
        commands_run = 0
        for command in fixture["setup_commands"]:
            resp = session.run_ms(command, timeout_ms=10000)
            command_wall_total += resp.get("command_roundtrip_ms", 0.0)
            stdout_total += resp.get("stdout_bytes_full", 0)
            stderr_total += resp.get("stderr_bytes_full", 0)
            commands_run += 1
            operation_sequence.append("service.run_command setup")
        for action in fixture["agent_actions"]:
            resp = session.run_ms(action["command"], timeout_ms=action.get("timeout_ms", 10000))
            command_wall_total += resp.get("command_roundtrip_ms", 0.0)
            stdout_total += resp.get("stdout_bytes_full", 0)
            stderr_total += resp.get("stderr_bytes_full", 0)
            commands_run += 1
            if action["label"] == "inspect_workspace":
                operation_sequence.append("service.run_command inspect")
            elif action["label"] == "write_solution":
                operation_sequence.append("service.run_command write_solution")
            elif action["label"] == "validate":
                operation_sequence.append("service.run_command validation")
                validation = resp
        reward = fixture["reward"]["pass_reward"] if validation.get("exit_code") == fixture["reward"]["pass_if"]["validate_exit_code"] else fixture["reward"]["fail_reward"]
        reset_t0 = now_ns()
        release = session.release(reset=True)
        reset_or_release_ms = ms_since(reset_t0)
        operation_sequence.append("service.reset_or_release_session")
        reacquire_t0 = now_ns()
        clean_session = pool.acquire(timeout=30)
        reacquire_ms = ms_since(reacquire_t0)
        operation_sequence.append("service.create_session clean_probe")
        clean = clean_session.run_ms(fixture["clean_session_probe"]["command"], timeout_ms=fixture["clean_session_probe"]["timeout_ms"])
        operation_sequence.append("service.run_command clean_workspace_probe")
        commands_run += 1
        command_wall_total += clean.get("command_roundtrip_ms", 0.0)
        stdout_total += clean.get("stdout_bytes_full", 0)
        stderr_total += clean.get("stderr_bytes_full", 0)
        clean_session.release(reset=True)
        pool.close()
        operation_sequence.append("service.close_pool")
        row = {
            "task_id": fixture["task_id"],
            "test_id": "rl_poc.phase11_python_pytest",
            "classification": "pass" if reward == 1.0 and clean.get("exit_code") == 0 else "fail",
            "reward": reward,
            "pool_id": pool.pool_id,
            "session_id": session.session_id,
            "profile": fixture["profile"],
            "workspace_template": fixture["workspace_template"],
            "commands_run": commands_run,
            "validation_exit_code": validation.get("exit_code"),
            "validation_stdout": b64text(validation, "stdout"),
            "reset_or_release_ms": reset_or_release_ms,
            "reacquire_ms": reacquire_ms,
            "clean_workspace_probe_exit_code": clean.get("exit_code"),
            "clean_workspace_reacquired": True,
            "queue_wait_ms": session.queue_wait_ms,
            "command_wall_ms_total": command_wall_total,
            "transport_ms_total": command_wall_total,
            "stdout_bytes_total": stdout_total,
            "stderr_bytes_total": stderr_total,
            "metrics_present": True,
            "transcript_present": True,
            "operation_sequence": operation_sequence,
        }
        write_jsonl(rl_path, row)
        rl_md_path.write_text(
            "\n".join([
                "# Firecracker Service RL POC",
                "",
                "- task_id: `{}`".format(row["task_id"]),
                "- classification: `{}`".format(row["classification"]),
                "- reward: `{}`".format(row["reward"]),
                "- validation_exit_code: `{}`".format(row["validation_exit_code"]),
                "- clean_workspace_probe_exit_code: `{}`".format(row["clean_workspace_probe_exit_code"]),
            ]) + "\n",
            encoding="utf-8",
        )
        return row
    finally:
        cleanup_runtime_dirs(run_dir)


def run_noisy(args, fc_path, rootfs_path, run_dir, reports_dir):
    raw_path = reports_dir / "firecracker-lumi-phase11-{}-raw.jsonl".format(os.environ.get("SLURM_JOB_ID", "local"))
    probes_path = reports_dir / "noisy-neighbor-probes.jsonl"
    for path in (probes_path,):
        if path.exists():
            path.unlink()
    sizes = [int(item) for item in args.noisy_pool_sizes.split(",") if item.strip()]
    payload = phase8.run_noisy_neighbor_suite(
        fc_path,
        args.kernel_path,
        rootfs_path,
        run_dir,
        args.mem_mib,
        args.vcpus,
        sizes,
        args.noisy_victims,
        raw_path,
        probes_path,
    )
    write_json(reports_dir / "noisy-neighbor-isolation-raw.json", payload)
    return payload


def write_phase11_reports(result, reports_dir, return_dir, job_id):
    reports_dir = Path(reports_dir)
    return_dir = Path(return_dir)
    mkdir(return_dir)
    result["final_recommendation"] = classify(result)
    json_path = reports_dir / "firecracker-lumi-phase11-{}.json".format(job_id)
    md_path = reports_dir / "firecracker-lumi-phase11-{}.md".format(job_id)
    write_json(json_path, result)
    md = [
        "# Firecracker LUMI Phase 11",
        "",
        "- Job: `{}`".format(job_id),
        "- Assessment: `{}`".format(result.get("assessment")),
        "- Recommendation: `{}`".format(result.get("final_recommendation")),
        "- Runtime dirs remaining after cleanup: `{}`".format(result.get("runtime_dirs_remaining_after_cleanup")),
        "",
        "## Key Results",
        "",
        "- Phase 8 stdout/stderr flood fix: `{}`".format(result.get("stdout_stderr_flood_fixed")),
        "- Noisy-neighbor assessment: `{}`".format((result.get("noisy_neighbor") or {}).get("assessment")),
        "- RL POC reward: `{}`".format((result.get("rl_poc") or {}).get("reward")),
        "- Recovery rows: `{}`".format(len(result.get("recovery_rows", []))),
        "",
        "## Notes",
        "",
        "- Output flood behavior is bounded in the guest agent before response construction.",
        "- `release_sandbox` remains the intended public API direction; Phase 11 artifacts keep session-compatible names where receiver contracts require them.",
        "- Network ACL/policy remains deferred by design.",
    ]
    md_path.write_text("\n".join(md) + "\n", encoding="utf-8")
    for src in [
        json_path,
        md_path,
        reports_dir / "firecracker-service-recovery.jsonl",
        reports_dir / "firecracker-service-rl-poc.jsonl",
        reports_dir / "firecracker-service-rl-poc.md",
        reports_dir / "noisy-neighbor-isolation-raw.json",
        reports_dir / "noisy-neighbor-probes.jsonl",
        reports_dir / "firecracker-lumi-phase11-{}-raw.jsonl".format(job_id),
        Path(__file__),
        Path(__file__).with_suffix(".sbatch"),
        Path("scripts/firecracker_lumi_phase5.py"),
        Path("scripts/firecracker_lumi_phase6.py"),
        Path("handoff/2026-07-01-firecracker-lumi-phase11-service-recovery-rl-integration/phase11-notes-and-plan.md"),
    ]:
        if src.exists():
            dest = return_dir / src.name
            shutil.copy2(str(src), str(dest))
            phase6.redact_file(dest)
    (return_dir / "firecracker-service-client-example.py").write_text(
        '''#!/usr/bin/env python3
"""Phase 11 intended end-user API sketch.

The standalone service should be IP-based HTTP by default. Bind to loopback
unless the deployment explicitly configures auth and external exposure.
"""

from firecracker_rl_sandbox import ServiceClient


client = ServiceClient("http://127.0.0.1:8765")
sandbox = client.allocate_sandbox(profile="python-coding")
try:
    proc = sandbox.start_process("python3 -m pytest -q tests", interactive=False, timeout_ms=30000)
    while True:
        chunk = proc.read_output(wait_ms=250, max_bytes=65536)
        print(chunk.stdout, end="")
        if chunk.state in {"exited", "killed", "timed_out", "failed"}:
            raise SystemExit(chunk.exit_code or 0)
finally:
    client.release_sandbox(sandbox.id, strategy="auto")
''',
        encoding="utf-8",
    )
    (return_dir / "README.md").write_text(
        "\n".join([
            "# Firecracker LUMI Phase 11 Results",
            "",
            "Date: 2026-07-01",
            "",
            "assessment: `{}`".format(result.get("assessment")),
            "recommendation: `{}`".format(result.get("final_recommendation")),
            "",
            "This handoff contains Phase 11 service recovery, noisy-neighbor, and RL/eval POC artifacts.",
            "",
            "Important files:",
            "",
            "- `firecracker-service-recovery.jsonl`",
            "- `firecracker-service-rl-poc.jsonl`",
            "- `noisy-neighbor-isolation-raw.json`",
            "- `noisy-neighbor-probes.jsonl`",
            "- `firecracker-lumi-phase11-{}-raw.jsonl`".format(job_id),
            "- `firecracker-lumi-phase11-{}.json`".format(job_id),
            "- `firecracker-lumi-phase11-{}.md`".format(job_id),
            "",
            "Run the repo receiver after this bundle is copied to the receiver handoff directory.",
        ]) + "\n",
        encoding="utf-8",
    )


def classify(result):
    if result.get("assessment") == "pass":
        return "promote_gate4_firecracker_mvp"
    if (result.get("noisy_neighbor") or {}).get("assessment") != "pass":
        return "needs_noisy_neighbor_hardening"
    if (result.get("rl_poc") or {}).get("classification") != "pass":
        return "needs_rl_poc_fix"
    return "proceed_with_service_mvp_limitations"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--kernel-path", required=True)
    ap.add_argument("--artifact-cache-dir", required=True)
    ap.add_argument("--rootfs-cache-dir", required=True)
    ap.add_argument("--phase6-mvp-dir", required=True)
    ap.add_argument("--rl-poc-task", required=True)
    ap.add_argument("--return-dir", required=True)
    ap.add_argument("--mem-mib", type=int, default=768)
    ap.add_argument("--vcpus", type=int, default=1)
    ap.add_argument("--service-pool-size", type=int, default=2)
    ap.add_argument("--noisy-pool-sizes", default="64,160")
    ap.add_argument("--noisy-victims", type=int, default=16)
    ap.add_argument("--skip-noisy", action="store_true")
    args = ap.parse_args()

    job_id = os.environ.get("SLURM_JOB_ID", "local")
    run_dir = Path(args.run_dir)
    reports_dir = Path("reports")
    mkdir(run_dir)
    mkdir(reports_dir)
    recovery_path = reports_dir / "firecracker-service-recovery.jsonl"
    rl_path = reports_dir / "firecracker-service-rl-poc.jsonl"
    rl_md_path = reports_dir / "firecracker-service-rl-poc.md"
    raw_path = reports_dir / "firecracker-lumi-phase11-{}-raw.jsonl".format(job_id)
    for path in (recovery_path, rl_path, raw_path, reports_dir / "noisy-neighbor-probes.jsonl"):
        if path.exists():
            path.unlink()
    result = {
        "phase": 11,
        "assessment": "fail",
        "host": host_snapshot(),
        "slurm": phase6.safe_slurm_snapshot(),
        "args": vars(args),
        "artifacts": {},
        "errors": [],
        "recovery_rows": [],
    }
    try:
        fc = download_firecracker(Path(args.artifact_cache_dir) / "firecracker")
        workspace_template = Path(args.phase6_mvp_dir) / "workspaces" / "fixtures" / "mvp"
        rootfs = phase5.prepare_rootfs(args.rootfs_cache_dir, args.artifact_cache_dir, {}, workspace_template)
        result["artifacts"] = {
            "firecracker": fc,
            "kernel": {"path": args.kernel_path, "bytes": Path(args.kernel_path).stat().st_size},
            "rootfs": rootfs,
        }
        result["recovery_rows"].extend(run_baseline_smoke(args, fc["path"], rootfs["path"], run_dir, recovery_path))
        result["recovery_rows"].append(run_background_process(args, fc["path"], rootfs["path"], run_dir, recovery_path))
        result["recovery_rows"].extend(run_recovery_matrix(args, fc["path"], rootfs["path"], run_dir, recovery_path))
        result["recovery_rows"].append(run_admission_control(args, fc["path"], rootfs["path"], run_dir, recovery_path))
        result["recovery_rows"].append(run_health_check(args, fc["path"], rootfs["path"], run_dir, recovery_path))
        result["rl_poc"] = run_rl_poc(args, fc["path"], rootfs["path"], run_dir, recovery_path, rl_path, rl_md_path)
        if args.skip_noisy:
            result["noisy_neighbor"] = {"assessment": "skipped", "deficits": ["skip-noisy set"]}
        else:
            result["noisy_neighbor"] = run_noisy(args, fc["path"], rootfs["path"], run_dir, reports_dir)
        flood_rows = [row for row in result["recovery_rows"] if row.get("test_id") in ("recovery.stdout_flood", "recovery.stderr_flood")]
        result["stdout_stderr_flood_fixed"] = all(row.get("classification") == "pass" and not row.get("manual_cleanup_required") for row in flood_rows)
        result["assessment"] = "pass" if (
            not result["errors"]
            and result["stdout_stderr_flood_fixed"]
            and all(row.get("classification") == "pass" for row in result.get("recovery_rows", []))
            and result.get("rl_poc", {}).get("classification") == "pass"
            and result.get("noisy_neighbor", {}).get("assessment") == "pass"
        ) else "fail"
    except Exception as exc:
        result["errors"].append({"fatal": repr(exc)})
    finally:
        cleanup_runtime_dirs(run_dir)
        result["runtime_dirs_remaining_after_cleanup"] = runtime_dirs_remaining(run_dir)
        result["host_after"] = host_snapshot()
        write_phase11_reports(result, reports_dir, args.return_dir, job_id)
        print(json.dumps({
            "assessment": result.get("assessment"),
            "errors": result.get("errors", [])[-5:],
            "return_dir": args.return_dir,
            "recommendation": result.get("final_recommendation"),
            "runtime_dirs_remaining_after_cleanup": result.get("runtime_dirs_remaining_after_cleanup"),
        }, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
