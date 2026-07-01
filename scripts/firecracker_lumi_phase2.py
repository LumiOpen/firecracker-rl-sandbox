#!/usr/bin/env python3
import argparse
import collections
import hashlib
import json
import os
import shlex
import shutil
import tempfile
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from firecracker_lumi_bench import (
    FirecrackerVM,
    build_initramfs,
    download_firecracker,
    download_kernel,
    host_snapshot,
    mkdir,
    ms_since,
    now_ns,
    proc_rss_kb,
    read_text,
    summarize,
    summarize_command_results,
)


def log(message):
    print("[{}] {}".format(time.strftime("%Y-%m-%d %H:%M:%S"), message), flush=True)


def light_host_snapshot():
    meminfo = {}
    for line in read_text("/proc/meminfo").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].rstrip(":") in ("MemAvailable", "MemFree", "MemTotal"):
            meminfo[parts[0].rstrip(":")] = int(parts[1])
    return {
        "timestamp_unix": time.time(),
        "loadavg": read_text("/proc/loadavg").strip(),
        "meminfo": meminfo,
        "cgroup_memory": {
            "memory_max": read_text("/sys/fs/cgroup/memory.max").strip(),
            "memory_current": read_text("/sys/fs/cgroup/memory.current").strip(),
        },
    }


class HostSampler(threading.Thread):
    def __init__(self, interval_s=1.0):
        super(HostSampler, self).__init__()
        self.daemon = True
        self.interval_s = interval_s
        self.samples = []
        self._stop_event = threading.Event()

    def run(self):
        while not self._stop_event.is_set():
            try:
                self.samples.append(light_host_snapshot())
            except Exception as exc:
                self.samples.append({"timestamp_unix": time.time(), "error": str(exc)})
            self._stop_event.wait(self.interval_s)

    def finish(self):
        self._stop_event.set()
        self.join(timeout=5)
        return self.samples


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def compact_command_result(result, max_excerpt=2048):
    stdout = result.get("stdout", "") or ""
    stderr = result.get("stderr", "") or ""
    compact = {}
    for key in (
        "cmd",
        "elapsed_ms",
        "exit_code",
        "rss_kb_before",
        "rss_kb_after",
        "host_cpu_seconds_delta",
    ):
        compact[key] = result.get(key)
    compact.update({
        "stdout_chars": len(stdout),
        "stderr_chars": len(stderr),
        "stdout_sha256": sha256_text(stdout),
        "stderr_sha256": sha256_text(stderr),
        "stdout_excerpt": stdout[:max_excerpt],
        "stderr_excerpt": stderr[:max_excerpt],
    })
    if len(stdout) > max_excerpt:
        compact["stdout_suffix"] = stdout[-max_excerpt:]
    if len(stderr) > max_excerpt:
        compact["stderr_suffix"] = stderr[-max_excerpt:]
    return compact


def compact_error(exc):
    return {
        "type": exc.__class__.__name__,
        "error": str(exc),
        "traceback_tail": traceback.format_exc()[-4000:],
    }


def bash_lc(script):
    if "\n" in script:
        raise ValueError("serial command scripts must be single-line")
    return "bash -lc {}".format(shlex.quote(script))


def vm_rss_summary(vms):
    rss = [proc_rss_kb(vm.proc.pid) for vm in vms if vm.proc is not None and vm.proc.poll() is None]
    rss = [x for x in rss if x is not None]
    return {
        "count": len(rss),
        "sum_kb": sum(rss),
        "per_vm_kb": summarize(rss),
    }


def stop_vms(vms):
    for vm in vms:
        try:
            vm.stop()
        except Exception:
            pass


def restore_from_snapshot(vm_id, fc, initrd, run_dir, snapshot_path, mem_path, args, command="bash -lc 'echo ready'"):
    vm = FirecrackerVM(vm_id, fc["path"], "", initrd["image"], run_dir, mem_mib=args.mem_mib, vcpus=args.vcpus)
    try:
        prep = vm.prepare_files()
        launch_ms = vm.start_process()
        t_load = now_ns()
        load_resp = vm.load_snapshot(snapshot_path, mem_path, resume=True)
        load_ms = ms_since(t_load)
        cmd = vm.command(command, timeout=args.command_timeout)
        rec = {
            "vm_id": vm_id,
            "file_setup": prep,
            "launch_ms": launch_ms,
            "load_ms": load_ms,
            "load_response": load_resp,
            "command": compact_command_result(cmd),
            "restore_to_command_done_ms": load_ms + cmd["elapsed_ms"],
            "rss_kb_after_command": proc_rss_kb(vm.proc.pid),
        }
        return rec, vm, None
    except Exception as exc:
        try:
            vm.stop()
        except Exception:
            pass
        return {"vm_id": vm_id}, None, compact_error(exc)


def create_clean_snapshot(fc, kernel, initrd, run_dir, args, name):
    vm = FirecrackerVM("{}-source".format(name), fc["path"], kernel["path"], initrd["image"], run_dir,
                       mem_mib=args.mem_mib, vcpus=args.vcpus)
    try:
        boot = vm.boot(timeout=args.boot_timeout)
        baseline = {
            "noop": compact_command_result(vm.command("", timeout=5, noop=True)),
            "echo_ready": compact_command_result(vm.command("bash -lc 'echo ready'", timeout=args.command_timeout)),
            "pwd": compact_command_result(vm.command("bash -lc 'pwd'", timeout=args.command_timeout)),
            "workspace_manifest": compact_command_result(vm.command(
                "bash -lc 'find /workspace -type f -printf \"%P\\n\" | sort | sha256sum'",
                timeout=args.command_timeout,
            )),
            "env_hash": compact_command_result(vm.command(
                "bash -lc 'env | sort | sha256sum'",
                timeout=args.command_timeout,
            )),
            "processes": compact_command_result(vm.command(
                "bash -lc 'ps -eo pid,ppid,comm,args | sed -n \"1,80p\"'",
                timeout=args.command_timeout,
            )),
            "python_version": compact_command_result(vm.command(
                bash_lc("python3 -c 'import sys; print(sys.version)'"),
                timeout=args.command_timeout,
            )),
        }
        pause_t0 = now_ns()
        pause = vm.pause()
        pause_ms = ms_since(pause_t0)
        snapshot_path = Path(run_dir) / "{}.vmstate".format(name)
        mem_path = Path(run_dir) / "{}.mem".format(name)
        snap_t0 = now_ns()
        snapshot = vm.snapshot(snapshot_path, mem_path)
        snapshot_ms = ms_since(snap_t0)
        rec = {
            "source_boot": boot,
            "baseline": baseline,
            "pause": pause,
            "pause_ms": pause_ms,
            "snapshot": snapshot,
            "snapshot_create_ms": snapshot_ms,
            "snapshot_path": str(snapshot_path),
            "snapshot_bytes": snapshot_path.stat().st_size if snapshot_path.exists() else None,
            "mem_path": str(mem_path),
            "mem_bytes": mem_path.stat().st_size if mem_path.exists() else None,
        }
        return rec
    finally:
        vm.stop()


def run_userland_probe(args, fc, kernel, initrd, run_dir):
    log("running userland probe")
    vm = FirecrackerVM("userland-probe", fc["path"], kernel["path"], initrd["image"], run_dir,
                       mem_mib=args.mem_mib, vcpus=args.vcpus)
    tools = [
        "python3", "git", "bash", "coreutils", "sed", "awk", "find", "grep", "diff",
        "patch", "tar", "gzip", "gcc", "clang", "make",
    ]
    commands = {
        "python_version": "python3 -c 'import sys, sysconfig; print(sys.version); print(sys.executable); print(sysconfig.get_platform())'",
        "pytest_version": "python3 -m pytest --version",
        "git_version": "git --version",
        "coreutils_echo": "printf 'ok\\n' | wc -c",
        "sed_awk_find_grep": "printf 'a\\nneedle\\n' >/tmp/u.txt; sed -n '2p' /tmp/u.txt; awk '/needle/{print $1}' /tmp/u.txt; find /workspace -type f | grep small.txt",
        "diff_patch_tar_gzip": "printf 'one\\n' >/tmp/a.txt; printf 'two\\n' >/tmp/b.txt; diff -u /tmp/a.txt /tmp/b.txt >/tmp/a.patch || true; patch /tmp/a.txt /tmp/a.patch >/tmp/patch.log 2>&1 || true; tar -czf /tmp/a.tgz /tmp/a.txt; gzip -t /tmp/a.tgz; cat /tmp/a.txt",
        "gcc_version": "gcc --version | head -1",
        "clang_version": "clang --version | head -1",
    }
    try:
        boot = vm.boot(timeout=args.boot_timeout)
        out = {"boot": boot, "tools": {}}
        for tool in tools:
            cmd = "bash -lc 'command -v {} 2>/dev/null || true'".format(tool)
            out["tools"][tool] = compact_command_result(vm.command(cmd, timeout=args.command_timeout))
        out["commands"] = {}
        for name, cmd in commands.items():
            out["commands"][name] = compact_command_result(vm.command(bash_lc(cmd), timeout=max(args.command_timeout, 60)))
        return out
    finally:
        vm.stop()


def run_snapshot_as_reset(args, fc, kernel, initrd, run_dir):
    log("running snapshot-as-reset checks")
    out = create_clean_snapshot(fc, kernel, initrd, run_dir, args, "phase2-reset-clean")
    snapshot_path = out["snapshot_path"]
    mem_path = out["mem_path"]
    out["workspace_sizes"] = {}
    for n in args.snapshot_reset_workspace_sizes:
        log("snapshot reset mutation size {}".format(n))
        dirty_rec, dirty_vm, dirty_err = restore_from_snapshot(
            "reset-dirty-{}".format(n), fc, initrd, run_dir, snapshot_path, mem_path, args
        )
        dirty = {"restore": dirty_rec, "restore_error": dirty_err}
        try:
            if dirty_vm is not None:
                mutate_cmd = (
                    "bash -lc 'set -e; rm -rf /workspace/phase2_mutation_{n}; "
                    "rm -f /workspace/small.txt; "
                    "printf dirty > /workspace/file.txt; "
                    "mkdir -p /workspace/phase2_mutation_{n}; "
                    "for i in $(seq 1 {n}); do printf \"new-$i\\n\" > /workspace/phase2_mutation_{n}/file_$i.txt; done; "
                    "(cd /tmp && sleep 600) & echo $! >/tmp/phase2-bg.pid; "
                    "export FC_PHASE2_DIRTY=1; cd /tmp; "
                    "echo mutated-{n}'"
                ).format(n=n)
                dirty["mutate"] = compact_command_result(dirty_vm.command(mutate_cmd, timeout=max(60, n / 200.0)))
                dirty["dirty_check"] = compact_command_result(dirty_vm.command(
                    (
                        "bash -lc 'set -e; test ! -e /workspace/small.txt; "
                        "test -f /workspace/phase2_mutation_{n}/file_{n}.txt; "
                        "grep -q dirty /workspace/file.txt; "
                        "kill -0 $(cat /tmp/phase2-bg.pid); "
                        "test \"$(pwd)\" = /workspace; "
                        "! env | grep -q FC_PHASE2_DIRTY; "
                        "echo dirty-state-visible'"
                    ).format(n=n),
                    timeout=args.command_timeout,
                ))
        finally:
            if dirty_vm is not None:
                dirty_vm.stop()

        clean_rec, clean_vm, clean_err = restore_from_snapshot(
            "reset-clean-{}".format(n), fc, initrd, run_dir, snapshot_path, mem_path, args
        )
        clean = {"restore": clean_rec, "restore_error": clean_err}
        try:
            if clean_vm is not None:
                clean["clean_check"] = compact_command_result(clean_vm.command(
                    (
                        "bash -lc 'set -e; test -f /workspace/small.txt; "
                        "grep -q needle /workspace/small.txt; "
                        "test ! -e /workspace/phase2_mutation_{n}; "
                        "! grep -q dirty /workspace/file.txt; "
                        "test ! -e /tmp/phase2-bg.pid; "
                        "test \"$(pwd)\" = /workspace; "
                        "! env | grep -q FC_PHASE2_DIRTY; "
                        "echo clean-ready'"
                    ).format(n=n),
                    timeout=args.command_timeout,
                ))
                clean["agent_noop_after_clean_check"] = compact_command_result(clean_vm.command("", timeout=5, noop=True))
        finally:
            if clean_vm is not None:
                clean_vm.stop()
        out["workspace_sizes"][str(n)] = {
            "dirty": dirty,
            "clean_restore": clean,
            "state_clean": (
                dirty.get("dirty_check", {}).get("exit_code") == 0
                and clean.get("clean_check", {}).get("exit_code") == 0
                and clean.get("agent_noop_after_clean_check", {}).get("exit_code") == 0
            ),
        }
    out["note"] = (
        "The serial agent launches each command in a fresh bash process, so cwd/env mutations "
        "inside one command do not persist by design. The checks verify the restored command "
        "environment starts in /workspace, does not retain FC_PHASE2_DIRTY, and the agent still "
        "responds to no-op commands. Background process existence is checked with kill -0 "
        "because /proc is not reliably mounted in this minimal generated initramfs."
    )
    return out


def run_parallel_snapshot_restore(args, fc, kernel, initrd, run_dir):
    log("preparing snapshot for parallel restore")
    source = create_clean_snapshot(fc, kernel, initrd, run_dir, args, "phase2-parallel-restore")
    snapshot_path = source["snapshot_path"]
    mem_path = source["mem_path"]
    mem_bytes = source.get("mem_bytes") or 0
    out = {"source_snapshot": source, "counts": {}}
    for count in args.parallel_restore_counts:
        log("parallel snapshot restore count {}".format(count))
        sampler = HostSampler(args.host_sample_interval_s)
        sampler.start()
        t0 = now_ns()
        samples = []
        failures = []
        workers = count if args.max_workers <= 0 else min(count, args.max_workers)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [
                ex.submit(restore_from_snapshot, "par-restore-{}-{}".format(count, i), fc, initrd,
                          run_dir, snapshot_path, mem_path, args)
                for i in range(count)
            ]
            for fut in as_completed(futs):
                rec, vm, err = fut.result()
                if err is not None:
                    failures.append({"vm_id": rec.get("vm_id"), "error": err})
                else:
                    samples.append(rec)
                if vm is not None:
                    vm.stop()
        wall_ms = ms_since(t0)
        host_samples = sampler.finish()
        out["counts"][str(count)] = {
            "requested": count,
            "succeeded": len(samples),
            "failed": len(failures),
            "failures": failures[:50],
            "wall_ms": wall_ms,
            "restore_to_command_done_ms": summarize([s["restore_to_command_done_ms"] for s in samples]),
            "load_ms": summarize([s["load_ms"] for s in samples]),
            "launch_ms": summarize([s["launch_ms"] for s in samples]),
            "rss_kb_after_command": summarize([s["rss_kb_after_command"] for s in samples if s.get("rss_kb_after_command") is not None]),
            "estimated_snapshot_memory_read_bytes": mem_bytes * count,
            "estimated_snapshot_memory_read_mib_per_s": ((mem_bytes * count) / 1024.0 / 1024.0) / (wall_ms / 1000.0) if wall_ms else None,
            "host_samples": host_samples,
            "sample_records": samples[:min(len(samples), args.max_saved_samples)],
        }
    return out


def boot_one(vm_id, args, fc, kernel, initrd, run_dir, command="bash -lc 'echo ready'"):
    vm = FirecrackerVM(vm_id, fc["path"], kernel["path"], initrd["image"], run_dir,
                       mem_mib=args.mem_mib, vcpus=args.vcpus)
    try:
        t0 = now_ns()
        boot = vm.boot(timeout=args.boot_timeout)
        cmd = vm.command(command, timeout=args.command_timeout)
        rec = {
            "vm_id": vm_id,
            "boot": boot,
            "first_command": compact_command_result(cmd),
            "launch_to_first_command_done_ms": ms_since(t0),
            "rss_kb_after_command": proc_rss_kb(vm.proc.pid),
        }
        return rec, vm, None
    except Exception as exc:
        try:
            vm.stop()
        except Exception:
            pass
        return {"vm_id": vm_id}, None, compact_error(exc)


def boot_many_keep(prefix, count, args, fc, kernel, initrd, run_dir):
    workers = count if args.max_workers <= 0 else min(count, args.max_workers)
    vms = []
    records = []
    failures = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [
            ex.submit(boot_one, "{}-{}".format(prefix, i), args, fc, kernel, initrd, run_dir)
            for i in range(count)
        ]
        for fut in as_completed(futs):
            rec, vm, err = fut.result()
            if err is not None:
                failures.append({"vm_id": rec.get("vm_id"), "error": err})
            else:
                records.append(rec)
                vms.append(vm)
    return vms, records, failures


def run_parallel_boot(args, fc, kernel, initrd, run_dir):
    out = {}
    for count in args.parallel_boot_counts:
        log("fully parallel boot count {}".format(count))
        sampler = HostSampler(args.host_sample_interval_s)
        sampler.start()
        t0 = now_ns()
        vms, records, failures = boot_many_keep("par-boot-{}".format(count), count, args, fc, kernel, initrd, run_dir)
        wall_ms = ms_since(t0)
        host_during = light_host_snapshot()
        rss = vm_rss_summary(vms)
        stop_vms(vms)
        host_samples = sampler.finish()
        out[str(count)] = {
            "requested": count,
            "booted": len(records),
            "failed": len(failures),
            "success_rate": len(records) / float(count) if count else 0.0,
            "wall_ms": wall_ms,
            "launch_to_first_command_done_ms": summarize([r["launch_to_first_command_done_ms"] for r in records]),
            "boot_to_ready_ms": summarize([r["boot"]["boot_to_ready_ms"] for r in records]),
            "vmm_launch_ms": summarize([r["boot"]["vmm_launch_ms"] for r in records]),
            "first_command_ms": summarize([r["first_command"]["elapsed_ms"] for r in records]),
            "rss": rss,
            "configured_guest_memory_mib_total": count * args.mem_mib,
            "host_during": host_during,
            "host_samples": host_samples,
            "failures": failures[:50],
            "sample_records": records[:min(len(records), args.max_saved_samples)],
        }
    return out


def run_density_until_saturation(args, fc, kernel, initrd, run_dir):
    out = {}
    for count in args.density_counts:
        log("idle density count {}".format(count))
        sampler = HostSampler(args.host_sample_interval_s)
        sampler.start()
        t0 = now_ns()
        vms, records, failures = boot_many_keep("density-{}".format(count), count, args, fc, kernel, initrd, run_dir)
        wall_ms = ms_since(t0)
        host_during = light_host_snapshot()
        rss_idle = vm_rss_summary(vms)
        out[str(count)] = {
            "requested": count,
            "booted": len(records),
            "failed": len(failures),
            "success_rate": len(records) / float(count) if count else 0.0,
            "wall_ms": wall_ms,
            "boot_to_ready_ms": summarize([r["boot"]["boot_to_ready_ms"] for r in records]),
            "launch_to_first_command_done_ms": summarize([r["launch_to_first_command_done_ms"] for r in records]),
            "host_rss_idle": rss_idle,
            "configured_guest_memory_mib_total": count * args.mem_mib,
            "host_during_idle": host_during,
            "failures": failures[:100],
            "sample_records": records[:min(len(records), args.max_saved_samples)],
        }
        stop_vms(vms)
        out[str(count)]["host_samples"] = sampler.finish()
        if failures and args.stop_density_on_failure:
            break
    stable = [int(k) for k, v in out.items() if v["failed"] == 0 and v["booted"] == v["requested"]]
    out["max_stable_vms_observed"] = max(stable) if stable else 0
    return out


def run_command_across_vms(vms, cmd, timeout, max_workers):
    workers = len(vms) if max_workers <= 0 else min(len(vms), max_workers)
    samples = []
    failures = []

    def task(vm):
        try:
            return vm.vm_id, compact_command_result(vm.command(cmd, timeout=timeout)), None
        except Exception as exc:
            return vm.vm_id, None, compact_error(exc)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(task, vm) for vm in vms]
        for fut in as_completed(futs):
            vm_id, rec, err = fut.result()
            if err is not None:
                failures.append({"vm_id": vm_id, "error": err})
            else:
                samples.append(rec)
    return {
        "summary": summarize_command_results([
            {
                "elapsed_ms": s["elapsed_ms"],
                "exit_code": s["exit_code"],
                "stdout": s["stdout_excerpt"],
                "stderr": s["stderr_excerpt"],
                "rss_kb_after": s["rss_kb_after"],
                "host_cpu_seconds_delta": s["host_cpu_seconds_delta"],
            }
            for s in samples
        ]),
        "failed": len(failures),
        "failures": failures[:50],
        "sample_records": samples[:50],
    }


def run_active_density(args, fc, kernel, initrd, run_dir):
    workloads = collections.OrderedDict([
        ("python_print", "bash -lc 'python3 -c \"print(1)\"'"),
        ("pytest", "bash -lc 'python3 -m pytest /workspace/tests'"),
        ("grep", "bash -lc 'grep needle /workspace/file.txt >/dev/null'"),
        ("find", "bash -lc 'find /workspace -type f | wc -l >/dev/null'"),
    ])
    out = {}
    for count in args.active_density_counts:
        log("active density count {}".format(count))
        sampler = HostSampler(args.host_sample_interval_s)
        sampler.start()
        t0 = now_ns()
        vms, records, failures = boot_many_keep("active-density-{}".format(count), count, args, fc, kernel, initrd, run_dir)
        boot_wall_ms = ms_since(t0)
        payload = {
            "requested": count,
            "booted": len(records),
            "boot_failed": len(failures),
            "boot_failures": failures[:50],
            "boot_wall_ms": boot_wall_ms,
            "configured_guest_memory_mib_total": count * args.mem_mib,
            "host_rss_before_workloads": vm_rss_summary(vms),
            "workloads": {},
        }
        for name, cmd in workloads.items():
            log("active density {} workload {}".format(count, name))
            w_t0 = now_ns()
            payload["workloads"][name] = run_command_across_vms(
                vms, cmd, timeout=max(args.command_timeout, 120), max_workers=args.max_workers
            )
            payload["workloads"][name]["wall_ms"] = ms_since(w_t0)
            payload["workloads"][name]["host_after"] = light_host_snapshot()
            payload["workloads"][name]["host_rss_after"] = vm_rss_summary(vms)
        stop_vms(vms)
        payload["host_samples"] = sampler.finish()
        out[str(count)] = payload
    return out


def run_command_api_stress(args, fc, kernel, initrd, run_dir):
    log("running command API stress")
    vm = FirecrackerVM("command-stress", fc["path"], kernel["path"], initrd["image"], run_dir,
                       mem_mib=args.mem_mib, vcpus=args.vcpus)
    out = {
        "stdin_protocol_supported": False,
        "stdin_note": "The current serial agent accepts one shell command line. Stdin is represented here with shell-encoded here-docs; a true stdin stream would need a protocol extension.",
    }
    try:
        out["boot"] = vm.boot(timeout=args.boot_timeout)
        noop = []
        for _ in range(args.stress_noop_iters):
            noop.append(vm.command("", timeout=5, noop=True))
        out["noop_transport"] = summarize_command_results(noop)
        commands = collections.OrderedDict([
            ("large_stdout", "python3 -c {}".format(shlex.quote(
                "import sys; sys.stdout.write('x' * {} + '\\n')".format(args.stress_large_stdout_bytes)
            ))),
            ("large_stderr", "python3 -c {}".format(shlex.quote(
                "import sys; sys.stderr.write('e' * {} + '\\n')".format(args.stress_large_stderr_bytes)
            ))),
            ("binary_stdout", "python3 -c {}".format(shlex.quote(
                "import sys; sys.stdout.buffer.write(bytes(range(256)) * {}); sys.stdout.write('\\n')".format(
                    max(1, args.stress_binary_bytes // 256)
                )
            ))),
            ("shell_encoded_stdin", "printf 'hello from encoded stdin\\n' | wc -c"),
            ("guest_timeout_cancellation", "timeout 1 bash -lc 'sleep 5'"),
            ("background_start", "sleep 2 & echo $! >/tmp/stress-bg.pid; echo started"),
            ("background_poll_running", "kill -0 $(cat /tmp/stress-bg.pid) && echo running"),
            ("background_poll_done", "sleep 3; kill -0 $(cat /tmp/stress-bg.pid) 2>/dev/null && echo still-present || echo done"),
            ("multi_command_1", "echo one"),
            ("multi_command_2", "pwd"),
            ("multi_command_3", "echo three"),
        ])
        out["commands"] = {}
        for name, cmd in commands.items():
            out["commands"][name] = compact_command_result(vm.command(bash_lc(cmd), timeout=max(args.command_timeout, 60)))
    finally:
        vm.stop()

    timeout_vm = FirecrackerVM("command-stress-host-timeout", fc["path"], kernel["path"], initrd["image"], run_dir,
                               mem_mib=args.mem_mib, vcpus=args.vcpus)
    try:
        timeout_vm.boot(timeout=args.boot_timeout)
        try:
            timeout_vm.command("bash -lc 'sleep 5; echo late'", timeout=1)
            out["host_side_timeout"] = {"unexpected_success": True}
        except Exception as exc:
            out["host_side_timeout"] = {
                "expected_timeout": True,
                "error": compact_error(exc),
                "note": "The current serial protocol detects host-side timeout but does not cancel the guest command; the harness kills this disposable VM after recording the timeout.",
            }
    finally:
        timeout_vm.stop()
    return out


def run_probe_in_fresh_vm(name, cmd, args, fc, kernel, initrd, run_dir, timeout=None):
    vm = FirecrackerVM("security-{}".format(name), fc["path"], kernel["path"], initrd["image"], run_dir,
                       mem_mib=args.mem_mib, vcpus=args.vcpus)
    rec = {"command": cmd}
    try:
        rec["boot"] = vm.boot(timeout=args.boot_timeout)
        try:
            rec["result"] = compact_command_result(vm.command(bash_lc(cmd), timeout=timeout or args.command_timeout))
        except Exception as exc:
            rec["result_error"] = compact_error(exc)
        try:
            rec["agent_survival"] = compact_command_result(vm.command("bash -lc 'echo alive'", timeout=5))
        except Exception as exc:
            rec["agent_survival_error"] = compact_error(exc)
    finally:
        vm.stop()
    return rec


def run_security_resource_probes(args, fc, kernel, initrd, run_dir):
    log("running security/resource probes")
    probes = collections.OrderedDict([
        ("host_filesystem_attempts", "for p in /pfs /scratch /Users /mnt /host /etc/shadow; do if [ -e \"$p\" ]; then echo EXISTS:$p; ls -ld \"$p\"; else echo ABSENT:$p; fi; done; mount | sed -n '1,80p'"),
        ("env_leakage", "env | sort; echo --sensitive--; env | grep -Ei 'token|secret|password|credential|aws|hf_|slurm' || true"),
        ("proc_and_devices", "cat /proc/1/status 2>/tmp/proc-status.err | sed -n '1,40p'; echo --proc-status-err--; cat /tmp/proc-status.err 2>/dev/null || true; echo --mount-errors--; cat /tmp/mount-proc.err /tmp/mount-dev.err /tmp/mount-sys.err 2>/dev/null || true; echo --dev--; ls -la /dev | sed -n '1,120p'"),
        ("network_policy", "python3 -c {}".format(shlex.quote(
            "import socket; socket.create_connection(('example.com', 80), timeout=2); print('network-ok')"
        ))),
        ("memory_pressure", "python3 -c {}".format(shlex.quote(
            "size={}*1024*1024; buf=bytearray(size); [buf.__setitem__(i, 1) for i in range(0, len(buf), 4096)]; print('allocated', len(buf))".format(
                args.security_memory_pressure_mib
            )
        ))),
        ("disk_fill", "python3 -c 'open(\"/tmp/fill\", \"wb\").write(b\"0\" * {} * 1024 * 1024)'; sync; ls -lh /tmp/fill; rm -f /tmp/fill".format(args.security_disk_fill_mib)),
        ("process_storm", "timeout 5 bash -lc 'for i in $(seq 1 {}); do sleep 10 & done; echo spawned; wait'".format(args.security_process_count)),
        ("cpu_pressure", "timeout 3 python3 -c 'while True: pass'"),
    ])
    out = {}
    for name, cmd in probes.items():
        out[name] = run_probe_in_fresh_vm(name, cmd, args, fc, kernel, initrd, run_dir, timeout=max(args.command_timeout, 20))
    out["note"] = (
        "The process_storm probe is a bounded fork-bomb-style pressure test, not an unbounded fork bomb. "
        "It runs inside a disposable one-vCPU VM and then verifies whether the command agent still answers."
    )
    return out


def markdown_table_summary(summary):
    if not summary or summary.get("n", 0) == 0:
        return "`n=0`"
    return "n={n} mean={mean:.3f} p50={p50:.3f} p90={p90:.3f} p99={p99:.3f} max={max:.3f}".format(**summary)


def markdown_report(result):
    lines = []
    lines.append("# Firecracker LUMI Phase 2 Benchmark Report")
    lines.append("")
    lines.append("Generated: {}".format(time.strftime("%Y-%m-%d %H:%M:%S %Z")))
    lines.append("")
    args = result.get("args", {})
    host = result.get("host_before", {})
    mem = host.get("meminfo", {})
    lines.append("## Scope")
    lines.append("")
    lines.append("- Guest memory: `{}` MiB; vCPUs: `{}`.".format(args.get("mem_mib"), args.get("vcpus")))
    lines.append("- Snapshot reset workspace sizes: `{}`.".format(args.get("snapshot_reset_workspace_sizes")))
    lines.append("- Parallel restore counts: `{}`.".format(args.get("parallel_restore_counts")))
    lines.append("- Parallel boot counts: `{}`.".format(args.get("parallel_boot_counts")))
    lines.append("- Idle density counts: `{}`.".format(args.get("density_counts")))
    lines.append("- Active density counts: `{}`.".format(args.get("active_density_counts")))
    lines.append("- Max worker cap: `{}` (`0` means count-sized full parallelism).".format(args.get("max_workers")))
    lines.append("")
    lines.append("## Host")
    lines.append("")
    lines.append("- Node: `{}`.".format(host.get("hostname")))
    lines.append("- Kernel: `{}`.".format(host.get("uname")))
    lines.append("- CPU: `{}`; logical CPUs visible: `{}`.".format(host.get("cpuinfo_model"), host.get("cpu_count_logical")))
    if mem:
        lines.append("- MemTotal: `{:.1f} GiB`; MemAvailable before run: `{:.1f} GiB`.".format(
            mem.get("MemTotal", 0) / 1024.0 / 1024.0,
            mem.get("MemAvailable", 0) / 1024.0 / 1024.0,
        ))
    lines.append("- SLURM: `{}`.".format(json.dumps(host.get("slurm", {}), sort_keys=True)))
    lines.append("")
    lines.append("## Artifacts")
    lines.append("")
    lines.append("- Firecracker: `{}` `{}`.".format(
        result.get("firecracker", {}).get("release"), result.get("firecracker", {}).get("version")
    ))
    lines.append("- Kernel: `{}`.".format(result.get("kernel", {}).get("key")))
    initrd = result.get("initramfs", {})
    lines.append("- Initramfs: `{:.1f} MiB`; build `{:.1f} ms`; pytest `{}` installed `{}`.".format(
        initrd.get("image_bytes", 0) / 1024.0 / 1024.0,
        initrd.get("build_ms", 0.0),
        initrd.get("pytest", {}).get("package"),
        initrd.get("pytest", {}).get("installed"),
    ))
    lines.append("")
    lines.append("## More Realistic Userland")
    lines.append("")
    userland = result.get("userland_probe", {})
    for name, payload in userland.get("commands", {}).items():
        lines.append("- `{}` exit `{}` in `{:.3f}` ms; stdout: `{}`; stderr: `{}`.".format(
            name,
            payload.get("exit_code"),
            payload.get("elapsed_ms") or 0.0,
            payload.get("stdout_excerpt", "").replace("\n", "\\n")[:220],
            payload.get("stderr_excerpt", "").replace("\n", "\\n")[:220],
        ))
    lines.append("")
    lines.append("## Snapshot As Real Reset")
    lines.append("")
    reset = result.get("snapshot_as_reset", {})
    lines.append("- Snapshot create: HTTP `{}` in `{:.3f}` ms; memory image `{:.1f}` MiB.".format(
        reset.get("snapshot", {}).get("http"),
        reset.get("snapshot_create_ms") or 0.0,
        (reset.get("mem_bytes") or 0) / 1024.0 / 1024.0,
    ))
    lines.append("")
    lines.append("| mutated files | dirty check | clean check | agent health | restore-to-command ms |")
    lines.append("|---:|---:|---:|---:|---|")
    for n, payload in sorted(reset.get("workspace_sizes", {}).items(), key=lambda kv: int(kv[0])):
        clean = payload.get("clean_restore", {})
        restore = clean.get("restore", {})
        lines.append("| {} | {} | {} | {} | {:.3f} |".format(
            n,
            payload.get("dirty", {}).get("dirty_check", {}).get("exit_code"),
            clean.get("clean_check", {}).get("exit_code"),
            clean.get("agent_noop_after_clean_check", {}).get("exit_code"),
            restore.get("restore_to_command_done_ms") or 0.0,
        ))
    lines.append("")
    lines.append(reset.get("note", ""))
    lines.append("")
    lines.append("## Parallel Snapshot Restore")
    lines.append("")
    lines.append("| restores | succeeded | failed | wall ms | restore p50/p99 ms | load p50/p99 ms | est mem-read MiB/s |")
    lines.append("|---:|---:|---:|---:|---|---|---:|")
    for count, payload in sorted(result.get("parallel_snapshot_restore", {}).get("counts", {}).items(), key=lambda kv: int(kv[0])):
        r = payload.get("restore_to_command_done_ms", {})
        l = payload.get("load_ms", {})
        lines.append("| {} | {} | {} | {:.1f} | {:.3f}/{:.3f} | {:.3f}/{:.3f} | {:.1f} |".format(
            count, payload.get("succeeded"), payload.get("failed"), payload.get("wall_ms") or 0.0,
            r.get("p50", 0.0), r.get("p99", 0.0), l.get("p50", 0.0), l.get("p99", 0.0),
            payload.get("estimated_snapshot_memory_read_mib_per_s") or 0.0,
        ))
    lines.append("")
    lines.append("## Fully Parallel Boot")
    lines.append("")
    lines.append("| VMs | booted | failed | wall ms | first-command p50/p99 ms | boot-ready p50/p99 ms | RSS sum GiB |")
    lines.append("|---:|---:|---:|---:|---|---|---:|")
    for count, payload in sorted(result.get("parallel_boot", {}).items(), key=lambda kv: int(kv[0])):
        fc_s = payload.get("launch_to_first_command_done_ms", {})
        br = payload.get("boot_to_ready_ms", {})
        rss_sum = payload.get("rss", {}).get("sum_kb", 0) / 1024.0 / 1024.0
        lines.append("| {} | {} | {} | {:.1f} | {:.3f}/{:.3f} | {:.3f}/{:.3f} | {:.2f} |".format(
            count, payload.get("booted"), payload.get("failed"), payload.get("wall_ms") or 0.0,
            fc_s.get("p50", 0.0), fc_s.get("p99", 0.0), br.get("p50", 0.0), br.get("p99", 0.0), rss_sum,
        ))
    lines.append("")
    lines.append("## Density Until Saturation")
    lines.append("")
    density = result.get("density_until_saturation", {})
    lines.append("- Max stable VMs observed: `{}`.".format(density.get("max_stable_vms_observed")))
    lines.append("")
    lines.append("| VMs | booted | failed | wall ms | configured GiB | RSS sum GiB | cgroup memory.current | loadavg |")
    lines.append("|---:|---:|---:|---:|---:|---:|---|---|")
    for count, payload in sorted([(k, v) for k, v in density.items() if k != "max_stable_vms_observed"], key=lambda kv: int(kv[0])):
        host = payload.get("host_during_idle", {})
        cgroup = host.get("cgroup_memory", {})
        lines.append("| {} | {} | {} | {:.1f} | {:.1f} | {:.2f} | `{}` | `{}` |".format(
            count,
            payload.get("booted"),
            payload.get("failed"),
            payload.get("wall_ms") or 0.0,
            (payload.get("configured_guest_memory_mib_total") or 0) / 1024.0,
            payload.get("host_rss_idle", {}).get("sum_kb", 0) / 1024.0 / 1024.0,
            cgroup.get("memory_current"),
            host.get("loadavg"),
        ))
    lines.append("")
    lines.append("## Active Density")
    lines.append("")
    for count, payload in sorted(result.get("active_density", {}).items(), key=lambda kv: int(kv[0])):
        lines.append("### {} VMs".format(count))
        lines.append("")
        lines.append("- Booted `{}`; boot failures `{}`; boot wall `{:.1f}` ms.".format(
            payload.get("booted"), payload.get("boot_failed"), payload.get("boot_wall_ms") or 0.0
        ))
        lines.append("")
        lines.append("| workload | failed | wall ms | latency |")
        lines.append("|---|---:|---:|---|")
        for name, w in payload.get("workloads", {}).items():
            lines.append("| `{}` | {} | {:.1f} | {} |".format(
                name,
                w.get("failed"),
                w.get("wall_ms") or 0.0,
                markdown_table_summary(w.get("summary", {}).get("latency_ms", {})),
            ))
        lines.append("")
    lines.append("## Command API Stress")
    lines.append("")
    stress = result.get("command_api_stress", {})
    lines.append("- No-op transport: `{}`.".format(json.dumps(stress.get("noop_transport", {}).get("latency_ms", {}), sort_keys=True)))
    lines.append("- True stdin stream supported by current agent: `{}`.".format(stress.get("stdin_protocol_supported")))
    lines.append("")
    lines.append("| case | exit | ms | stdout chars | stderr chars |")
    lines.append("|---|---:|---:|---:|---:|")
    for name, payload in stress.get("commands", {}).items():
        lines.append("| `{}` | {} | {:.3f} | {} | {} |".format(
            name, payload.get("exit_code"), payload.get("elapsed_ms") or 0.0,
            payload.get("stdout_chars"), payload.get("stderr_chars"),
        ))
    if stress.get("host_side_timeout"):
        lines.append("")
        lines.append("- Host-side timeout behavior: `{}`.".format(json.dumps(stress.get("host_side_timeout"), sort_keys=True)[:800]))
    lines.append("")
    lines.append("## Security And Resource Probes")
    lines.append("")
    security = result.get("security_resource_probes", {})
    lines.append(security.get("note", ""))
    lines.append("")
    lines.append("| probe | command exit | survival exit | stdout excerpt |")
    lines.append("|---|---:|---:|---|")
    for name, payload in security.items():
        if name == "note":
            continue
        result_payload = payload.get("result", {})
        survival = payload.get("agent_survival", {})
        lines.append("| `{}` | {} | {} | `{}` |".format(
            name,
            result_payload.get("exit_code"),
            survival.get("exit_code"),
            result_payload.get("stdout_excerpt", "").replace("\n", "\\n")[:240],
        ))
    lines.append("")
    lines.append("## Limitations")
    lines.append("")
    lines.append("- Measurements use the serial-console command agent because unprivileged TAP networking was not available in the earlier LUMI probe.")
    lines.append("- The guest is an initramfs assembled from host binaries, not a full distro rootfs. Python/control-plane figures are useful for comparing VM command overhead and reset behavior, but not a full user distribution boot.")
    lines.append("- Binary stdout over the serial line is intentionally treated as a stress/protocol probe; production use should frame or encode binary payloads.")
    if result.get("errors"):
        lines.append("")
        lines.append("## Harness Errors")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(result.get("errors"), indent=2, sort_keys=True)[:8000])
        lines.append("```")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", default=None)
    ap.add_argument("--mem-mib", type=int, default=512)
    ap.add_argument("--vcpus", type=int, default=1)
    ap.add_argument("--boot-timeout", type=float, default=45.0)
    ap.add_argument("--command-timeout", type=float, default=45.0)
    ap.add_argument("--with-pytest", action="store_true")
    ap.add_argument("--snapshot-reset-workspace-sizes", type=int, nargs="+", default=[1000, 10000])
    ap.add_argument("--parallel-restore-counts", type=int, nargs="+", default=[10, 50, 100])
    ap.add_argument("--parallel-boot-counts", type=int, nargs="+", default=[10, 50, 100, 200, 300, 500])
    ap.add_argument("--density-counts", type=int, nargs="+", default=[200, 300, 500])
    ap.add_argument("--active-density-counts", type=int, nargs="+", default=[50, 100, 200])
    ap.add_argument("--max-workers", type=int, default=0)
    ap.add_argument("--max-saved-samples", type=int, default=20)
    ap.add_argument("--host-sample-interval-s", type=float, default=1.0)
    ap.add_argument("--stress-noop-iters", type=int, default=1000)
    ap.add_argument("--stress-large-stdout-bytes", type=int, default=1024 * 1024)
    ap.add_argument("--stress-large-stderr-bytes", type=int, default=1024 * 1024)
    ap.add_argument("--stress-binary-bytes", type=int, default=64 * 1024)
    ap.add_argument("--security-memory-pressure-mib", type=int, default=256)
    ap.add_argument("--security-disk-fill-mib", type=int, default=64)
    ap.add_argument("--security-process-count", type=int, default=256)
    ap.add_argument("--stop-density-on-failure", action="store_true")
    ap.add_argument("--skip-parallel-restore", action="store_true")
    ap.add_argument("--skip-parallel-boot", action="store_true")
    ap.add_argument("--skip-density", action="store_true")
    ap.add_argument("--skip-active-density", action="store_true")
    ap.add_argument("--skip-command-stress", action="store_true")
    ap.add_argument("--skip-security", action="store_true")
    args = ap.parse_args()

    run_dir = Path(args.run_dir or tempfile.mkdtemp(prefix="fc-phase2-"))
    mkdir(run_dir)
    result = {"run_dir": str(run_dir), "args": vars(args), "host_before": host_snapshot(), "errors": []}
    try:
        cache = run_dir / "cache"
        log("downloading/resolving Firecracker and kernel")
        fc = download_firecracker(cache)
        kernel = download_kernel(cache)
        log("building initramfs")
        initrd = build_initramfs(run_dir / "build", args.with_pytest)
        result["firecracker"] = fc
        result["kernel"] = kernel
        result["initramfs"] = initrd

        stages = [
            ("userland_probe", lambda: run_userland_probe(args, fc, kernel, initrd, run_dir)),
            ("snapshot_as_reset", lambda: run_snapshot_as_reset(args, fc, kernel, initrd, run_dir)),
        ]
        if not args.skip_parallel_restore:
            stages.append(("parallel_snapshot_restore", lambda: run_parallel_snapshot_restore(args, fc, kernel, initrd, run_dir)))
        if not args.skip_parallel_boot:
            stages.append(("parallel_boot", lambda: run_parallel_boot(args, fc, kernel, initrd, run_dir)))
        if not args.skip_density:
            stages.append(("density_until_saturation", lambda: run_density_until_saturation(args, fc, kernel, initrd, run_dir)))
        if not args.skip_active_density:
            stages.append(("active_density", lambda: run_active_density(args, fc, kernel, initrd, run_dir)))
        if not args.skip_command_stress:
            stages.append(("command_api_stress", lambda: run_command_api_stress(args, fc, kernel, initrd, run_dir)))
        if not args.skip_security:
            stages.append(("security_resource_probes", lambda: run_security_resource_probes(args, fc, kernel, initrd, run_dir)))

        for name, fn in stages:
            log("stage start: {}".format(name))
            t0 = now_ns()
            try:
                result[name] = fn()
                result[name + "_elapsed_ms"] = ms_since(t0)
            except Exception as exc:
                result["errors"].append({"stage": name, "error": compact_error(exc)})
                log("stage failed: {}: {}".format(name, exc))
    finally:
        result["host_after"] = host_snapshot()
        report_json = run_dir / "firecracker_lumi_phase2_results.json"
        report_md = run_dir / "firecracker_lumi_phase2_report.md"
        report_json.write_text(json.dumps(result, indent=2, sort_keys=True))
        report_md.write_text(markdown_report(result))
        print("RESULT_JSON={}".format(report_json), flush=True)
        print("RESULT_MD={}".format(report_md), flush=True)


if __name__ == "__main__":
    main()
