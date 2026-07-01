#!/usr/bin/env python3
import argparse
import base64
import collections
import hashlib
import json
import os
import queue
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import traceback
from pathlib import Path

from firecracker_lumi_bench import (
    FirecrackerVM,
    build_initramfs,
    copy_preserve,
    download_firecracker,
    download_kernel,
    host_snapshot,
    mkdir,
    ms_since,
    now_ns,
    proc_cpu_seconds,
    proc_rss_kb,
    read_text,
    run,
    summarize,
)


JSON_PREFIX = "__FC_JSON__"


def log(message):
    print("[{}] {}".format(time.strftime("%Y-%m-%d %H:%M:%S"), message), flush=True)


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(text):
    return base64.b64decode(text.encode("ascii")) if text else b""


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def excerpt(data, limit=512):
    if data is None:
        return ""
    return data[:limit].decode("utf-8", "replace")


def compact_error(exc):
    return {
        "type": exc.__class__.__name__,
        "error": str(exc),
        "traceback_tail": traceback.format_exc()[-4000:],
    }


def cgroup_paths():
    out = {
        "proc_self_cgroup": read_text("/proc/self/cgroup").strip(),
        "mountinfo_cgroup": [],
        "memory_current_candidates": {},
        "pids_current_candidates": {},
    }
    for line in read_text("/proc/self/mountinfo").splitlines():
        if " cgroup" in line:
            out["mountinfo_cgroup"].append(line)
    rels = []
    for line in out["proc_self_cgroup"].splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3:
            rels.append(parts[2].lstrip("/"))
    roots = [Path("/sys/fs/cgroup")]
    for rel in rels:
        roots.append(Path("/sys/fs/cgroup") / rel)
    for root in roots:
        for name, target in (
            ("memory_current", out["memory_current_candidates"]),
            ("pids_current", out["pids_current_candidates"]),
        ):
            path = root / name.replace("_", ".")
            if path.exists():
                target[str(path)] = read_text(path).strip()
    return out


def fs_type(path):
    p = run(["stat", "-f", "-c", "%T", str(path)], check=False)
    return p.stdout.strip() if p.returncode == 0 else p.stderr.strip()


def operational_lumi_checks(fc, run_dir):
    checks = {
        "partition": os.environ.get("SLURM_JOB_PARTITION"),
        "account": os.environ.get("SLURM_JOB_ACCOUNT") or os.environ.get("SLURM_ACCOUNT"),
        "job_id": os.environ.get("SLURM_JOB_ID"),
        "node": run(["hostname"], check=False).stdout.strip(),
        "cpus_on_node": os.environ.get("SLURM_CPUS_ON_NODE"),
        "cpus_per_task": os.environ.get("SLURM_CPUS_PER_TASK"),
        "mem_per_node": os.environ.get("SLURM_MEM_PER_NODE"),
        "firecracker_binary_path": fc.get("path"),
        "jailer_path": shutil.which("jailer"),
        "paths": {},
        "cgroup": cgroup_paths(),
        "seccomp": {
            "proc_status_seccomp": None,
            "firecracker_note": "Firecracker has built-in seccomp filters; this harness does not use jailer-specific seccomp setup.",
        },
        "controllers": {},
        "filesystem_types": {
            "scratch_run_dir": fs_type(run_dir),
            "snapshot_directory": fs_type(run_dir),
            "image_cache_directory": fs_type(Path(run_dir) / "cache"),
            "tmp": fs_type(tempfile.gettempdir()),
        },
        "cross_partition_account_matrix": {
            "classification": "unsupported",
            "notes": "This single job records the current Slurm allocation. Running all intended account/partition combinations requires separate sbatch submissions.",
        },
    }
    for path in ("/dev/kvm", "/dev/vhost-vsock", "/dev/net/tun"):
        p = Path(path)
        info = {"exists": p.exists(), "readable": os.access(path, os.R_OK), "writable": os.access(path, os.W_OK)}
        try:
            st = p.stat()
            info["mode_octal"] = oct(st.st_mode & 0o7777)
            info["uid"] = st.st_uid
            info["gid"] = st.st_gid
        except Exception as exc:
            info["stat_error"] = str(exc)
        checks["paths"][path] = info
    status = read_text("/proc/self/status")
    for line in status.splitlines():
        if line.startswith("Seccomp:"):
            checks["seccomp"]["proc_status_seccomp"] = line.split(":", 1)[1].strip()
            break
    for path in ("/sys/fs/cgroup/cgroup.controllers", "/sys/fs/cgroup/cgroup.subtree_control"):
        checks["controllers"][path] = read_text(path).strip()
    checks["vsock_host_python"] = {
        "has_af_vsock": hasattr(socket, "AF_VSOCK"),
        "has_vmaddr_cid_host": hasattr(socket, "VMADDR_CID_HOST"),
    }
    return checks


PHASE3_AGENT = r'''#!/usr/bin/env python3
import base64
import json
import os
import selectors
import signal
import subprocess
import sys
import threading
import time
import traceback

PREFIX = "__FC_JSON__"
PROCS = {}
NEXT_HANDLE = 1
BASE_ENV = dict(os.environ)
BASE_CWD = "/workspace"


def emit(payload):
    sys.stdout.write(PREFIX + json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n")
    sys.stdout.flush()


class Proc:
    def __init__(self, handle, popen):
        self.handle = handle
        self.popen = popen
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.lock = threading.Lock()
        self.stdout_done = False
        self.stderr_done = False
        self.started = time.time()
        self.threads = [
            threading.Thread(target=self._pump, args=(popen.stdout, self.stdout, "stdout"), daemon=True),
            threading.Thread(target=self._pump, args=(popen.stderr, self.stderr, "stderr"), daemon=True),
        ]
        for t in self.threads:
            t.start()

    def _pump(self, stream, buf, name):
        try:
            while True:
                data = os.read(stream.fileno(), 4096)
                if not data:
                    break
                with self.lock:
                    buf.extend(data)
        finally:
            with self.lock:
                if name == "stdout":
                    self.stdout_done = True
                else:
                    self.stderr_done = True

    def status(self):
        rc = self.popen.poll()
        with self.lock:
            return {
                "handle": self.handle,
                "pid": self.popen.pid,
                "running": rc is None,
                "returncode": rc,
                "stdout_len": len(self.stdout),
                "stderr_len": len(self.stderr),
                "stdout_done": self.stdout_done,
                "stderr_done": self.stderr_done,
                "started_unix": self.started,
            }

    def read(self, stdout_cursor, stderr_cursor, max_bytes, wait_ms):
        deadline = time.time() + max(wait_ms, 0) / 1000.0
        while True:
            with self.lock:
                have_stdout = len(self.stdout) > stdout_cursor
                have_stderr = len(self.stderr) > stderr_cursor
                rc = self.popen.poll()
                done = rc is not None and self.stdout_done and self.stderr_done
                if have_stdout or have_stderr or done or time.time() >= deadline:
                    stdout_end = min(len(self.stdout), stdout_cursor + max_bytes)
                    stderr_end = min(len(self.stderr), stderr_cursor + max_bytes)
                    out = bytes(self.stdout[stdout_cursor:stdout_end])
                    err = bytes(self.stderr[stderr_cursor:stderr_end])
                    return {
                        "stdout_b64": base64.b64encode(out).decode("ascii"),
                        "stderr_b64": base64.b64encode(err).decode("ascii"),
                        "stdout_cursor": stdout_end,
                        "stderr_cursor": stderr_end,
                        "stdout_len": len(self.stdout),
                        "stderr_len": len(self.stderr),
                        "returncode": rc,
                        "stdout_done": self.stdout_done,
                        "stderr_done": self.stderr_done,
                    }
            time.sleep(0.005)


def response(req, ok=True, **payload):
    body = {"id": req.get("id"), "type": "response", "ok": ok}
    body.update(payload)
    emit(body)


def op_start(req):
    global NEXT_HANDLE
    cmd = req.get("cmd")
    cwd = req.get("cwd") or BASE_CWD
    env = BASE_ENV.copy()
    env.update(req.get("env") or {})
    p = subprocess.Popen(
        ["/bin/bash", "-lc", cmd],
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid,
    )
    handle = str(NEXT_HANDLE)
    NEXT_HANDLE += 1
    PROCS[handle] = Proc(handle, p)
    response(req, handle=handle, pid=p.pid)


def get_proc(req):
    handle = str(req.get("handle"))
    if handle not in PROCS:
        raise RuntimeError("unknown process handle {}".format(handle))
    return PROCS[handle]


def op_read(req):
    proc = get_proc(req)
    response(req, **proc.read(
        int(req.get("stdout_cursor", 0)),
        int(req.get("stderr_cursor", 0)),
        int(req.get("max_bytes", 65536)),
        int(req.get("wait_ms", 0)),
    ))


def op_write(req):
    proc = get_proc(req)
    data = base64.b64decode((req.get("data_b64") or "").encode("ascii"))
    proc.popen.stdin.write(data)
    proc.popen.stdin.flush()
    response(req, bytes_written=len(data))


def op_close_stdin(req):
    proc = get_proc(req)
    try:
        proc.popen.stdin.close()
    except Exception:
        pass
    response(req, closed=True)


def signal_number(name):
    if isinstance(name, int):
        return name
    name = str(name)
    if not name.startswith("SIG"):
        name = "SIG" + name
    return getattr(signal, name)


def op_signal(req):
    proc = get_proc(req)
    sig = signal_number(req.get("signal", "TERM"))
    os.killpg(os.getpgid(proc.popen.pid), sig)
    response(req, signal=sig)


def op_terminate(req):
    proc = get_proc(req)
    sig = signal.SIGKILL if req.get("force") else signal.SIGTERM
    os.killpg(os.getpgid(proc.popen.pid), sig)
    response(req, signal=sig)


def op_status(req):
    proc = get_proc(req)
    response(req, status=proc.status())


def op_health(req):
    response(req, cwd=os.getcwd(), process_count=len(PROCS), time_unix=time.time())


def op_reset(req):
    for proc in list(PROCS.values()):
        if proc.popen.poll() is None:
            try:
                os.killpg(os.getpgid(proc.popen.pid), signal.SIGKILL)
            except Exception:
                pass
    PROCS.clear()
    os.chdir(BASE_CWD)
    response(req, reset=True, cwd=os.getcwd(), process_count=0)


OPS = {
    "process/start": op_start,
    "process/read": op_read,
    "process/write": op_write,
    "process/close_stdin": op_close_stdin,
    "process/signal": op_signal,
    "process/terminate": op_terminate,
    "process/status": op_status,
    "environment/health": op_health,
    "environment/reset": op_reset,
}


def main():
    os.chdir(BASE_CWD)
    emit({"type": "agent_ready", "cwd": os.getcwd(), "pid": os.getpid()})
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        line = line.rstrip("\n\r")
        if not line:
            continue
        try:
            req = json.loads(line)
            op = req.get("op")
            if op not in OPS:
                response(req, ok=False, error="unsupported op {}".format(op))
                continue
            OPS[op](req)
        except Exception as exc:
            emit({
                "id": None,
                "type": "error",
                "ok": False,
                "error": str(exc),
                "traceback": traceback.format_exc()[-2000:],
            })


if __name__ == "__main__":
    main()
'''


def copy_if_exists(path, root, copied):
    if not path:
        return
    p = Path(path)
    if p.exists():
        try:
            copy_preserve(str(p), root)
            copied.append(str(p))
        except Exception as exc:
            copied.append("FAILED {}: {}".format(p, exc))


def add_compiler_support(root):
    copied = []
    gcc = shutil.which("gcc")
    if not gcc:
        return {"copied": copied, "available": False}
    for cmd in (
        [gcc, "-print-prog-name=cc1"],
        [gcc, "-print-prog-name=as"],
        [gcc, "-print-prog-name=ld"],
        [gcc, "-print-file-name=crt1.o"],
        [gcc, "-print-file-name=crti.o"],
        [gcc, "-print-file-name=crtn.o"],
        [gcc, "-print-libgcc-file-name"],
    ):
        p = run(cmd, check=False)
        copy_if_exists(p.stdout.strip(), root, copied)
    for path in ("/usr/include", "/usr/lib64/gcc", "/usr/lib/gcc"):
        src = Path(path)
        if src.exists():
            dest = Path(root) / str(src).lstrip("/")
            if not dest.exists():
                shutil.copytree(str(src), str(dest), symlinks=True)
            copied.append(path)
    for tool in ("as", "ld", "collect2"):
        p = shutil.which(tool)
        copy_if_exists(p, root, copied)
    return {"copied": copied, "available": True}


def build_phase3_initramfs(build_dir, with_pytest=True, with_compiler_support=False):
    initrd = build_initramfs(build_dir, with_pytest)
    root = Path(initrd["root"])
    (root / "agent.py").write_text(PHASE3_AGENT)
    (root / "agent.py").chmod(0o755)
    (root / "workspace/before.txt").write_text("one\n")
    (root / "workspace/after.txt").write_text("two\n")
    (root / "workspace/table.txt").write_text("alpha 1\nbeta 2\n")
    (root / "workspace/hello.c").write_text(
        "#include <stdio.h>\nint main(void) { puts(\"hello-c\"); return 0; }\n"
    )
    (root / "workspace/tests/test_unittest.py").write_text(
        "import unittest\n\n"
        "class BasicTest(unittest.TestCase):\n"
        "    def test_truth(self):\n"
        "        self.assertTrue(True)\n"
    )
    (root / "workspace/change.patch").write_text(
        "--- before.txt\n"
        "+++ before.txt\n"
        "@@ -1 +1 @@\n"
        "-one\n"
        "+two\n"
    )
    compiler_support = add_compiler_support(root) if with_compiler_support else {
        "available": False,
        "copied": [],
        "notes": "Skipped by default because copying headers/libgcc made the initramfs too large for a 512MiB guest.",
    }
    git_init = run(["git", "-C", str(root / "workspace"), "init", "-q"], check=False)
    (root / "root/.gitconfig").write_text(
        "[safe]\n"
        "\tdirectory = /workspace\n"
    )
    initrd["workspace_git_init"] = {
        "returncode": git_init.returncode,
        "stdout": git_init.stdout[-1000:],
        "stderr": git_init.stderr[-1000:],
    }
    init = root / "init"
    init.write_text("""#!/bin/bash
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export LD_LIBRARY_PATH=/lib64:/usr/lib64:/lib:/usr/lib
mount -t devtmpfs devtmpfs /dev 2>/tmp/mount-dev.err || true
mount -t proc proc /proc 2>/tmp/mount-proc.err || true
mount -t sysfs sysfs /sys 2>/tmp/mount-sys.err || true
exec </dev/ttyS0 >/dev/ttyS0 2>&1
stty -echo 2>/dev/null || true
cd /workspace
export HOME=/root
export PYTHONUNBUFFERED=1
echo __FC_AGENT_READY__
exec python3 /agent.py
""")
    init.chmod(0o755)
    image = Path(initrd["image"])
    t0 = now_ns()
    cmd = "cd '{}' && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1 > '{}'".format(
        str(root), str(image)
    )
    run(["bash", "-lc", cmd])
    initrd["phase3_agent"] = {
        "protocol": "json_lines_over_serial",
        "framing_prefix": JSON_PREFIX,
        "process_api": [
            "process/start",
            "process/read",
            "process/write",
            "process/close_stdin",
            "process/signal",
            "process/terminate",
            "process/status",
            "environment/reset",
            "environment/health",
        ],
    }
    initrd["image_bytes"] = image.stat().st_size
    initrd["phase3_rebuild_ms"] = ms_since(t0)
    initrd["compiler_support"] = compiler_support
    return initrd


class Phase3VM(FirecrackerVM):
    def __init__(self, *args, **kwargs):
        super(Phase3VM, self).__init__(*args, **kwargs)
        self.req_seq = 0

    def wait_json(self, req_id=None, timeout=10.0):
        deadline = time.time() + timeout
        recent = []
        while time.time() < deadline:
            try:
                _, src, line = self.q.get(timeout=0.1)
            except queue.Empty:
                continue
            if line is None:
                continue
            recent.append({"src": src, "line": line[:500]})
            if not line.startswith(JSON_PREFIX):
                continue
            payload = json.loads(line[len(JSON_PREFIX):])
            if req_id is None or payload.get("id") == req_id:
                return payload
        raise RuntimeError("timeout waiting for json response id={} recent={}".format(req_id, recent[-20:]))

    def request(self, op, timeout=10.0, **payload):
        self.req_seq += 1
        req_id = "r{}".format(self.req_seq)
        msg = {"id": req_id, "op": op}
        msg.update(payload)
        self.send_line(json.dumps(msg, separators=(",", ":"), sort_keys=True))
        resp = self.wait_json(req_id=req_id, timeout=timeout)
        if not resp.get("ok", False):
            raise RuntimeError("agent request failed op={} response={}".format(op, resp))
        return resp

    def send_malformed(self, line="{not-json", timeout=5.0):
        self.send_line(line)
        return self.wait_json(req_id=None, timeout=timeout)

    def health(self, timeout=5.0):
        return self.request("environment/health", timeout=timeout)

    def process_start(self, cmd, cwd="/workspace", env=None, timeout=5.0):
        return self.request("process/start", timeout=timeout, cmd=cmd, cwd=cwd, env=env or {})

    def read_process(self, handle, stdout_cursor=0, stderr_cursor=0, max_bytes=65536, wait_ms=0, timeout=10.0):
        return self.request(
            "process/read",
            timeout=timeout,
            handle=handle,
            stdout_cursor=stdout_cursor,
            stderr_cursor=stderr_cursor,
            max_bytes=max_bytes,
            wait_ms=wait_ms,
        )

    def write_process(self, handle, data, timeout=5.0):
        return self.request("process/write", timeout=timeout, handle=handle, data_b64=b64(data))

    def close_stdin(self, handle, timeout=5.0):
        return self.request("process/close_stdin", timeout=timeout, handle=handle)

    def signal_process(self, handle, sig, timeout=5.0):
        return self.request("process/signal", timeout=timeout, handle=handle, signal=sig)

    def terminate_process(self, handle, force=False, timeout=5.0):
        return self.request("process/terminate", timeout=timeout, handle=handle, force=bool(force))

    def status_process(self, handle, timeout=5.0):
        return self.request("process/status", timeout=timeout, handle=handle)

    def reset_agent(self, timeout=5.0):
        return self.request("environment/reset", timeout=timeout)


def new_phase3_vm(vm_id, args, fc, kernel, initrd, run_dir):
    return Phase3VM(vm_id, fc["path"], kernel["path"], initrd["image"], run_dir, mem_mib=args.mem_mib, vcpus=args.vcpus)


def boot_phase3_vm(vm_id, args, fc, kernel, initrd, run_dir):
    vm = new_phase3_vm(vm_id, args, fc, kernel, initrd, run_dir)
    boot = vm.boot(timeout=args.boot_timeout)
    ready_json = vm.wait_json(req_id=None, timeout=10)
    return vm, boot, ready_json


def collect_process(vm, handle, timeout_s=30.0, chunk_bytes=65536, wait_ms=100):
    stdout_cursor = 0
    stderr_cursor = 0
    stdout_parts = []
    stderr_parts = []
    t0 = now_ns()
    timed_out = False
    returncode = None
    read_count = 0
    first_output_ms = None
    while True:
        if (now_ns() - t0) / 1e9 > timeout_s:
            timed_out = True
            try:
                vm.terminate_process(handle, force=True)
            except Exception:
                pass
            break
        resp = vm.read_process(
            handle,
            stdout_cursor=stdout_cursor,
            stderr_cursor=stderr_cursor,
            max_bytes=chunk_bytes,
            wait_ms=wait_ms,
            timeout=max(5.0, wait_ms / 1000.0 + 5.0),
        )
        read_count += 1
        out = unb64(resp.get("stdout_b64"))
        err = unb64(resp.get("stderr_b64"))
        if (out or err) and first_output_ms is None:
            first_output_ms = ms_since(t0)
        stdout_parts.append(out)
        stderr_parts.append(err)
        stdout_cursor = resp["stdout_cursor"]
        stderr_cursor = resp["stderr_cursor"]
        returncode = resp.get("returncode")
        done = (
            returncode is not None
            and stdout_cursor >= resp.get("stdout_len", 0)
            and stderr_cursor >= resp.get("stderr_len", 0)
            and resp.get("stdout_done")
            and resp.get("stderr_done")
        )
        if done:
            break
    stdout = b"".join(stdout_parts)
    stderr = b"".join(stderr_parts)
    return {
        "stdout": stdout,
        "stderr": stderr,
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_sha256": sha256_bytes(stderr),
        "stdout_excerpt": excerpt(stdout),
        "stderr_excerpt": excerpt(stderr),
        "exit_code": returncode,
        "elapsed_ms": ms_since(t0),
        "timeout": timed_out,
        "read_count": read_count,
        "first_output_ms": first_output_ms,
    }


def run_blocking(vm, cmd, timeout_s=30.0, stdin=None, close_stdin=True, chunk_bytes=65536):
    start = vm.process_start(cmd, timeout=10)
    handle = start["handle"]
    if stdin:
        vm.write_process(handle, stdin)
    if close_stdin:
        vm.close_stdin(handle)
    result = collect_process(vm, handle, timeout_s=timeout_s, chunk_bytes=chunk_bytes)
    result["handle"] = handle
    result["pid"] = start.get("pid")
    return result


def test_row(test_id, category, command, transport, result=None, classification="pass", notes="", timeout=None,
             kill_reason=None, agent_survived=None, vm_survived=None, rss_before=None, rss_after=None,
             cpu_before=None, cpu_after=None):
    result = result or {}
    return {
        "test_id": test_id,
        "category": category,
        "command_or_operation": command,
        "transport": transport,
        "exit_code": result.get("exit_code"),
        "stdout_excerpt": result.get("stdout_excerpt", ""),
        "stderr_excerpt": result.get("stderr_excerpt", ""),
        "stdout_sha256": result.get("stdout_sha256", sha256_bytes(b"")),
        "stderr_sha256": result.get("stderr_sha256", sha256_bytes(b"")),
        "stdout_bytes": result.get("stdout_bytes", 0),
        "stderr_bytes": result.get("stderr_bytes", 0),
        "elapsed_ms": result.get("elapsed_ms"),
        "timeout": bool(result.get("timeout", False)) if timeout is None else timeout,
        "kill_reason": kill_reason,
        "agent_survived": agent_survived,
        "vm_survived": vm_survived,
        "rss_kb_before": rss_before,
        "rss_kb_after": rss_after,
        "host_cpu_seconds_delta": (
            cpu_after - cpu_before if cpu_before is not None and cpu_after is not None else None
        ),
        "classification": classification,
        "notes": notes,
        "read_count": result.get("read_count"),
        "first_output_ms": result.get("first_output_ms"),
    }


def health_survived(vm):
    try:
        vm.health(timeout=5)
        return True
    except Exception:
        return False


def run_command_transport_semantics(vm, args):
    rows = []
    transport = "serial_console_json_process_api"
    rss_before = proc_rss_kb(vm.proc.pid)
    cpu_before = proc_cpu_seconds(vm.proc.pid)
    result = run_blocking(vm, "echo stdout; echo stderr >&2", timeout_s=10)
    rows.append(test_row(
        "transport.stdout_stderr", "command_transport_semantics",
        "bash -lc 'echo stdout; echo stderr >&2'", transport, result,
        "pass" if result["stdout"] == b"stdout\n" and result["stderr"] == b"stderr\n" else "fail",
        agent_survived=health_survived(vm), vm_survived=vm.proc.poll() is None,
        rss_before=rss_before, rss_after=proc_rss_kb(vm.proc.pid), cpu_before=cpu_before,
        cpu_after=proc_cpu_seconds(vm.proc.pid),
    ))
    binary = run_blocking(
        vm,
        "python3 -c 'import sys; sys.stdout.buffer.write(bytes(range(256))*256)'",
        timeout_s=20,
    )
    rows.append(test_row(
        "transport.binary_64k", "command_transport_semantics",
        "python binary stdout 64KiB", transport, binary,
        "pass" if binary["stdout_bytes"] == 65536 and binary["exit_code"] == 0 else "fail",
        notes="Binary output is base64-framed inside JSON responses.",
        agent_survived=health_survived(vm), vm_survived=vm.proc.poll() is None,
    ))
    stdin_start = now_ns()
    start = vm.process_start(
        "python3 -c 'import sys; sys.stdout.write(sys.stdin.read().upper()); sys.stdout.flush()'",
        timeout=10,
    )
    vm.write_process(start["handle"], b"hello stdin\n")
    vm.close_stdin(start["handle"])
    stdin_result = collect_process(vm, start["handle"], timeout_s=20)
    stdin_result["elapsed_ms"] = ms_since(stdin_start)
    rows.append(test_row(
        "transport.true_stdin_eof", "command_transport_semantics",
        "stdin write after start plus EOF", transport, stdin_result,
        "pass" if stdin_result["stdout"] == b"HELLO STDIN\n" else "fail",
        notes="Uses process/write followed by process/close_stdin.",
        agent_survived=health_survived(vm), vm_survived=vm.proc.poll() is None,
    ))
    incremental_start = vm.process_start("for i in 1 2 3; do echo $i; sleep 1; done", timeout=10)
    partial = vm.read_process(incremental_start["handle"], wait_ms=600, timeout=5)
    partial_out = unb64(partial.get("stdout_b64"))
    rest = collect_process(vm, incremental_start["handle"], timeout_s=10)
    rows.append(test_row(
        "transport.incremental_read", "command_transport_semantics",
        "read output before process exit", transport, rest,
        "pass" if partial_out and rest["exit_code"] == 0 else "fail",
        notes="First partial read returned {} bytes before process exit.".format(len(partial_out)),
        agent_survived=health_survived(vm), vm_survived=vm.proc.poll() is None,
    ))
    for size in args.large_output_sizes:
        for stream in ("stdout", "stderr"):
            redir = "" if stream == "stdout" else " >&2"
            cmd = "python3 -c 'import sys; sys.{s}.write(\"x\"*{n})'".format(
                s="stdout" if stream == "stdout" else "stderr", n=size
            ) + redir
            result = run_blocking(vm, cmd, timeout_s=max(args.command_timeout, size / 50000.0 + 30))
            rows.append(test_row(
                "transport.large_{}_{}".format(stream, size),
                "command_transport_semantics",
                "{} {} bytes".format(stream, size),
                transport,
                result,
                "pass" if result["exit_code"] == 0 and result["{}_bytes".format(stream)] == size else "fail",
                agent_survived=health_survived(vm), vm_survived=vm.proc.poll() is None,
            ))
    sleep_start = vm.process_start("sleep 30", timeout=10)
    time.sleep(0.5)
    vm.terminate_process(sleep_start["handle"], force=False)
    cancelled = collect_process(vm, sleep_start["handle"], timeout_s=10)
    rows.append(test_row(
        "transport.host_cancellation", "command_transport_semantics",
        "process/terminate sleep 30", transport, cancelled,
        "pass" if cancelled["exit_code"] is not None and cancelled["exit_code"] < 0 else "fail",
        kill_reason="process/terminate",
        agent_survived=health_survived(vm), vm_survived=vm.proc.poll() is None,
    ))
    sig_start = vm.process_start("trap 'echo interrupted; exit 130' INT; sleep 30", timeout=10)
    time.sleep(0.5)
    vm.signal_process(sig_start["handle"], "SIGINT")
    sig_result = collect_process(vm, sig_start["handle"], timeout_s=10)
    rows.append(test_row(
        "transport.signal_sigint", "command_transport_semantics",
        "process/signal SIGINT", transport, sig_result,
        "pass" if sig_result["exit_code"] == 130 and b"interrupted" in sig_result["stdout"] else "minor_mismatch",
        agent_survived=health_survived(vm), vm_survived=vm.proc.poll() is None,
    ))
    timeout_start = vm.process_start("sleep 30", timeout=10)
    timeout_result = collect_process(vm, timeout_start["handle"], timeout_s=1)
    rows.append(test_row(
        "transport.timeout_enforcement", "command_transport_semantics",
        "host timeout then SIGKILL", transport, timeout_result,
        "pass" if timeout_result["timeout"] else "fail",
        kill_reason="host_timeout_sigkill",
        agent_survived=health_survived(vm), vm_survived=vm.proc.poll() is None,
    ))
    malformed = vm.send_malformed("{not-json", timeout=5)
    rows.append(test_row(
        "transport.malformed_frame_survival", "command_transport_semantics",
        "malformed json frame", transport,
        {"elapsed_ms": 0.0, "stdout": b"", "stderr": json.dumps(malformed).encode("utf-8")},
        "pass" if health_survived(vm) else "fail",
        notes="Agent returns an error frame and continues.",
        agent_survived=health_survived(vm), vm_survived=vm.proc.poll() is None,
    ))
    return rows


def run_process_api_semantics(vm, args):
    rows = []
    transport = "serial_console_json_process_api"
    start = vm.process_start(
        "python3 -c 'import sys,time; print(\"ready\", flush=True); print(sys.stdin.readline().strip().upper(), flush=True); time.sleep(1)'",
        timeout=10,
    )
    partial = vm.read_process(start["handle"], wait_ms=500, timeout=5)
    vm.write_process(start["handle"], b"hello\n")
    vm.close_stdin(start["handle"])
    result = collect_process(vm, start["handle"], timeout_s=10)
    rows.append(test_row(
        "process.start_read_write_close_status", "process_api_semantics",
        "start/read/write/close/status", transport, result,
        "pass" if b"ready" in unb64(partial.get("stdout_b64")) and b"HELLO" in result["stdout"] else "fail",
        notes="Partial read before stdin write plus exit collection after EOF.",
        agent_survived=health_survived(vm), vm_survived=vm.proc.poll() is None,
    ))
    handles = []
    for i in range(3):
        handles.append(vm.process_start("echo proc-{}; sleep 1".format(i), timeout=10)["handle"])
    multi_results = [collect_process(vm, h, timeout_s=10) for h in handles]
    rows.append(test_row(
        "process.multiple_processes", "process_api_semantics",
        "three concurrent processes", transport,
        {
            "stdout": b"".join(r["stdout"] for r in multi_results),
            "stderr": b"".join(r["stderr"] for r in multi_results),
            "stdout_bytes": sum(r["stdout_bytes"] for r in multi_results),
            "stderr_bytes": sum(r["stderr_bytes"] for r in multi_results),
            "stdout_sha256": sha256_bytes(b"".join(r["stdout"] for r in multi_results)),
            "stderr_sha256": sha256_bytes(b"".join(r["stderr"] for r in multi_results)),
            "stdout_excerpt": excerpt(b"".join(r["stdout"] for r in multi_results)),
            "stderr_excerpt": "",
            "exit_code": 0 if all(r["exit_code"] == 0 for r in multi_results) else 1,
            "elapsed_ms": max(r["elapsed_ms"] for r in multi_results),
        },
        "pass" if all(r["exit_code"] == 0 for r in multi_results) else "fail",
        agent_survived=health_survived(vm), vm_survived=vm.proc.poll() is None,
    ))
    bg = run_blocking(vm, "sleep 10 & echo $!", timeout_s=5)
    rows.append(test_row(
        "process.background_from_shell", "process_api_semantics",
        "bash -lc 'sleep 10 & echo $!'", transport, bg,
        "minor_mismatch",
        notes="Shell background processes can be started, but they are not first-class handles unless launched through process/start.",
        agent_survived=health_survived(vm), vm_survived=vm.proc.poll() is None,
    ))
    nonzero = run_blocking(vm, "printf 'err\\n' >&2; exit 7", timeout_s=10)
    rows.append(test_row(
        "process.nonzero_survival", "process_api_semantics",
        "stderr then exit 7", transport, nonzero,
        "pass" if nonzero["exit_code"] == 7 and health_survived(vm) else "fail",
        agent_survived=health_survived(vm), vm_survived=vm.proc.poll() is None,
    ))
    sigs = []
    for sig in ("SIGINT", "SIGTERM", "SIGKILL"):
        p = vm.process_start("trap 'echo interrupted; exit 130' INT; sleep 30", timeout=10)
        time.sleep(0.2)
        if sig == "SIGKILL":
            vm.terminate_process(p["handle"], force=True)
        else:
            vm.signal_process(p["handle"], sig)
        r = collect_process(vm, p["handle"], timeout_s=10)
        sigs.append((sig, r))
        rows.append(test_row(
            "process.signal_{}".format(sig.lower()), "process_api_semantics",
            "send {}".format(sig), transport, r,
            "pass" if r["exit_code"] is not None else "fail",
            kill_reason=sig,
            agent_survived=health_survived(vm), vm_survived=vm.proc.poll() is None,
        ))
    reset = vm.reset_agent(timeout=5)
    rows.append(test_row(
        "process.environment_reset_agent", "process_api_semantics",
        "environment/reset", transport,
        {"stdout": json.dumps(reset).encode("utf-8"), "stderr": b"", "exit_code": 0, "elapsed_ms": 0.0},
        "pass" if reset.get("process_count") == 0 else "fail",
        notes="Agent-level reset kills tracked processes and resets cwd to /workspace; snapshot reset is tested separately.",
        agent_survived=health_survived(vm), vm_survived=vm.proc.poll() is None,
    ))
    return rows


def run_no_network_workflows(vm, args):
    rows = []
    commands = collections.OrderedDict([
        ("git_status", "git status"),
        ("git_diff_no_index", "git diff --no-index before.txt after.txt || test $? -eq 1"),
        ("pytest", "python3 -m pytest tests"),
        ("unittest", "python3 -m unittest discover"),
        ("grep", "grep -R needle ."),
        ("find_py", "find . -name '*.py' -print"),
        ("sed", "sed -n '1,20p' file.txt"),
        ("awk", "awk '{print $1}' table.txt"),
        ("diff", "diff -u before.txt after.txt || test $? -eq 1"),
        ("patch", "cp before.txt patch-target.txt; sed 's/before.txt/patch-target.txt/g' change.patch > /tmp/change.patch; patch -p0 < /tmp/change.patch; cat patch-target.txt"),
        ("tar_gzip", "tar -czf /tmp/archive.tgz .; gzip -c file.txt > /tmp/file.txt.gz; test -s /tmp/archive.tgz; test -s /tmp/file.txt.gz"),
        ("gcc_version", "gcc --version"),
        ("gcc_build", "gcc hello.c -o /tmp/hello && /tmp/hello"),
    ])
    for name, cmd in commands.items():
        r = run_blocking(vm, cmd, timeout_s=60)
        rows.append(test_row(
            "offline.{}".format(name), "no_network_workflows", cmd,
            "serial_console_json_process_api", r,
            "pass" if r["exit_code"] == 0 else "fail",
            agent_survived=health_survived(vm), vm_survived=vm.proc.poll() is None,
        ))
    denied = collections.OrderedDict([
        ("curl_example", "curl https://example.com"),
        ("pip_install", "python3 -m pip install requests"),
        ("git_clone", "git clone https://github.com/openai/codex /tmp/codex"),
        ("socket_example", "python3 -c 'import socket; socket.create_connection((\"example.com\", 80), timeout=2)'"),
    ])
    for name, cmd in denied.items():
        r = run_blocking(vm, cmd, timeout_s=30)
        rows.append(test_row(
            "offline.denied.{}".format(name), "no_network_workflows", cmd,
            "serial_console_json_process_api", r,
            "pass" if r["exit_code"] != 0 and health_survived(vm) else "fail",
            notes="Expected network-dependent workflow denial.",
            agent_survived=health_survived(vm), vm_survived=vm.proc.poll() is None,
        ))
    return rows


def workspace_hash(vm):
    return run_blocking(
        vm,
        "find /workspace -xdev -type f -printf '%P\\0' | sort -z | xargs -0 sha256sum 2>/dev/null | sha256sum",
        timeout_s=60,
    )


def restore_phase3_from_snapshot(vm_id, args, fc, initrd, run_dir, snapshot_path, mem_path):
    vm = Phase3VM(vm_id, fc["path"], "", initrd["image"], run_dir, mem_mib=args.mem_mib, vcpus=args.vcpus)
    vm.prepare_files()
    launch_ms = FirecrackerVM.start_process(vm)
    t0 = now_ns()
    load = vm.load_snapshot(snapshot_path, mem_path, resume=True)
    load_ms = ms_since(t0)
    ready = vm.health(timeout=10)
    return vm, {"launch_ms": launch_ms, "load_ms": load_ms, "load_response": load, "health": ready}


def run_filesystem_reset_semantics(args, fc, kernel, initrd, run_dir):
    rows = []
    source, boot, ready = boot_phase3_vm("phase3-reset-source", args, fc, kernel, initrd, run_dir)
    try:
        baseline = workspace_hash(source)
        tmp_baseline = run_blocking(source, "find /tmp -maxdepth 1 -type f -printf '%f\\n' | sort", timeout_s=10)
        source.pause()
        snapshot_path = Path(run_dir) / "phase3-reset.vmstate"
        mem_path = Path(run_dir) / "phase3-reset.mem"
        t0 = now_ns()
        snap = source.snapshot(snapshot_path, mem_path)
        snapshot_ms = ms_since(t0)
    finally:
        source.stop()
    metadata = {
        "source_boot": boot,
        "ready": ready,
        "baseline_workspace_hash": baseline,
        "baseline_tmp": tmp_baseline,
        "snapshot_response": snap,
        "snapshot_create_ms": snapshot_ms,
        "snapshot_path": str(snapshot_path),
        "snapshot_bytes": snapshot_path.stat().st_size if snapshot_path.exists() else None,
        "mem_path": str(mem_path),
        "mem_bytes": mem_path.stat().st_size if mem_path.exists() else None,
    }
    for count in args.reset_file_counts:
        dirty_vm, dirty_restore = restore_phase3_from_snapshot(
            "phase3-reset-dirty-{}".format(count), args, fc, initrd, run_dir, snapshot_path, mem_path
        )
        try:
            mutate = (
                "set -e; rm -rf /workspace/phase3-dirty /tmp/phase3-dirty; "
                "mkdir -p /workspace/phase3-dirty/nested /tmp/phase3-dirty; "
                "echo changed > /workspace/small.txt; rm -f /workspace/before.txt; "
                "mv /workspace/after.txt /workspace/renamed-after.txt; "
                "printf '#!/bin/sh\\necho executable\\n' > /workspace/phase3-dirty/run.sh; chmod +x /workspace/phase3-dirty/run.sh; "
                "ln -s small.txt /workspace/phase3-dirty/symlink-small; "
                "ln /workspace/file.txt /workspace/phase3-dirty/hardlink-file 2>/tmp/hardlink.err || true; "
                "for i in $(seq 1 {n}); do echo file-$i > /workspace/phase3-dirty/nested/file_$i.txt; done; "
                "python3 -c 'import time; f=open(\"/workspace/phase3-dirty/held.log\", \"a\"); f.write(\"held\\n\"); f.flush(); time.sleep(30)' & echo $! >/tmp/phase3-bg.pid; "
                "echo tmpdirty > /tmp/phase3-dirty/file; echo mutated"
            ).format(n=count)
            dirty = run_blocking(dirty_vm, mutate, timeout_s=max(60, count / 500.0))
            dirty_check = run_blocking(
                dirty_vm,
                "set -e; test -d /workspace/phase3-dirty/nested; test ! -e /workspace/before.txt; test -x /workspace/phase3-dirty/run.sh; kill -0 $(cat /tmp/phase3-bg.pid); echo dirty-visible",
                timeout_s=20,
            )
        finally:
            dirty_vm.stop()
        clean_vm, clean_restore = restore_phase3_from_snapshot(
            "phase3-reset-clean-{}".format(count), args, fc, initrd, run_dir, snapshot_path, mem_path
        )
        try:
            clean_hash = workspace_hash(clean_vm)
            clean_check = run_blocking(
                clean_vm,
                "set -e; test -f /workspace/before.txt; test -f /workspace/after.txt; test ! -e /workspace/phase3-dirty; test ! -e /tmp/phase3-bg.pid; test ! -e /tmp/phase3-dirty; echo clean",
                timeout_s=20,
            )
            health = health_survived(clean_vm)
            classification = "pass" if (
                dirty["exit_code"] == 0 and dirty_check["exit_code"] == 0
                and clean_check["exit_code"] == 0
                and clean_hash["stdout"] == baseline["stdout"]
                and health
            ) else "fail"
            row_result = {
                "stdout": b"dirty:\n" + dirty["stdout"] + b"\nclean:\n" + clean_check["stdout"],
                "stderr": dirty["stderr"] + clean_check["stderr"],
                "stdout_bytes": dirty["stdout_bytes"] + clean_check["stdout_bytes"],
                "stderr_bytes": dirty["stderr_bytes"] + clean_check["stderr_bytes"],
                "stdout_sha256": sha256_bytes(dirty["stdout"] + clean_check["stdout"]),
                "stderr_sha256": sha256_bytes(dirty["stderr"] + clean_check["stderr"]),
                "stdout_excerpt": "dirty={} clean={} clean_hash={}".format(
                    dirty["stdout_excerpt"], clean_check["stdout_excerpt"], clean_hash["stdout_excerpt"]
                ),
                "stderr_excerpt": excerpt(dirty["stderr"] + clean_check["stderr"]),
                "exit_code": 0 if classification == "pass" else 1,
                "elapsed_ms": clean_restore["load_ms"],
            }
            rows.append(test_row(
                "reset.snapshot_{}_files".format(count), "filesystem_reset_semantics",
                "snapshot restore after {} dirty files".format(count),
                "serial_console_json_process_api", row_result, classification,
                notes="Snapshot load_ms={:.3f}; mem_bytes={}".format(clean_restore["load_ms"], metadata["mem_bytes"]),
                agent_survived=health, vm_survived=clean_vm.proc.poll() is None,
            ))
        finally:
            clean_vm.stop()
    for count in args.skipped_reset_file_counts:
        rows.append(test_row(
            "reset.snapshot_{}_files".format(count), "filesystem_reset_semantics",
            "snapshot restore after {} dirty files".format(count),
            "serial_console_json_process_api",
            {"stdout": b"", "stderr": b"", "exit_code": None, "elapsed_ms": None},
            "unsupported",
            notes="Skipped by configuration to avoid filling the 512MiB initramfs guest memory.",
        ))
    return {"metadata": metadata, "rows": rows}


def run_guest_fidelity(vm):
    rows = []
    commands = collections.OrderedDict([
        ("proc_1_status", "cat /proc/1/status"),
        ("ps_aux", "ps aux"),
        ("mount", "mount"),
        ("dev_listing", "ls -l /dev"),
        ("python_subprocess", "python3 -c 'import os, signal, subprocess, sys; print(sys.version); print(os.uname()); r=subprocess.run([\"bash\", \"-lc\", \"echo ok\"], capture_output=True, text=True); print(r.returncode, r.stdout.strip())'"),
        ("dynamic_linking", "ldd /usr/bin/python3 || true"),
        ("python_imports", "python3 -c 'import json, hashlib, sqlite3, subprocess; print(\"imports-ok\")'"),
        ("pure_python_package", "python3 -c 'import pytest; print(pytest.__version__)'"),
        ("native_extension_import", "python3 -c 'import _ssl, _sqlite3; print(\"native-ok\")'"),
        ("compiler_available", "gcc --version | head -1"),
        ("process_group_signal", "trap 'echo int; exit 130' INT; sleep 10"),
    ])
    for name, cmd in commands.items():
        if name == "process_group_signal":
            p = vm.process_start(cmd, timeout=10)
            time.sleep(0.2)
            vm.signal_process(p["handle"], "SIGINT")
            r = collect_process(vm, p["handle"], timeout_s=10)
        else:
            r = run_blocking(vm, cmd, timeout_s=30)
        cls = "pass" if r["exit_code"] == 0 else "major_mismatch"
        if name in ("proc_1_status", "mount") and r["exit_code"] != 0:
            cls = "major_mismatch"
        if name == "process_group_signal" and r["exit_code"] == 130 and b"int" in r["stdout"]:
            cls = "pass"
        rows.append(test_row(
            "guest_fidelity.generated_initramfs.{}".format(name),
            "guest_fidelity",
            cmd,
            "serial_console_json_process_api",
            r,
            cls,
            notes="generated_initramfs",
            agent_survived=health_survived(vm), vm_survived=vm.proc.poll() is None,
        ))
    rows.append(test_row(
        "guest_fidelity.full_rootfs", "guest_fidelity", "pinned_full_rootfs_if_available",
        "none",
        {"stdout": b"", "stderr": b"", "exit_code": None, "elapsed_ms": None},
        "unsupported",
        notes="No pinned full rootfs was provided in the handoff or existing project scratch; this run tests generated_initramfs only.",
    ))
    return rows


def run_security_probe(name, cmd, args, fc, kernel, initrd, run_dir, timeout_s=10):
    vm = None
    try:
        vm, boot, ready = boot_phase3_vm("phase3-security-{}".format(name), args, fc, kernel, initrd, run_dir)
        r = run_blocking(vm, cmd, timeout_s=timeout_s)
        survived = health_survived(vm)
        return test_row(
            "security.{}".format(name), "security_resource_semantics", cmd,
            "serial_console_json_process_api", r,
            "pass" if survived else "minor_mismatch",
            agent_survived=survived, vm_survived=vm.proc.poll() is None,
            notes="Disposable VM probe.",
        )
    except Exception as exc:
        return test_row(
            "security.{}".format(name), "security_resource_semantics", cmd,
            "serial_console_json_process_api",
            {"stdout": b"", "stderr": str(exc).encode("utf-8"), "exit_code": None, "elapsed_ms": None},
            "major_mismatch",
            agent_survived=False, vm_survived=False, notes="Probe raised exception.",
        )
    finally:
        if vm is not None:
            vm.stop()


def run_security_resource_semantics(args, fc, kernel, initrd, run_dir):
    probes = collections.OrderedDict([
        ("shadow", "cat /etc/shadow"),
        ("host_paths", "ls /pfs /scratch /mnt /host /home"),
        ("env", "env; python3 -c 'import os; print(os.environ)'"),
        ("network", "python3 -c 'import socket; socket.create_connection((\"example.com\", 80), timeout=2)'"),
        ("memory_pressure", "python3 -c 'x=[]\\nwhile True: x.append(b\"x\"*1000000)'"),
        ("fork_bomb_bounded", "ulimit -u 256; :(){ :|:& };:"),
        ("disk_fill", "python3 -c 'open(\"/tmp/fill\", \"wb\").write(b\"x\" * ({} * 1024 * 1024))'".format(args.security_disk_fill_mib)),
        ("cpu_pressure", "python3 -c 'while True: pass'"),
    ])
    rows = []
    for name, cmd in probes.items():
        timeout_s = 5 if name in ("memory_pressure", "fork_bomb_bounded", "cpu_pressure") else 30
        row = run_security_probe(name, cmd, args, fc, kernel, initrd, run_dir, timeout_s=timeout_s)
        if name in ("shadow", "host_paths", "network"):
            row["classification"] = "pass" if row["exit_code"] != 0 and row["agent_survived"] else "fail"
            row["notes"] += " Expected denial."
        elif name in ("memory_pressure", "fork_bomb_bounded", "cpu_pressure"):
            row["classification"] = "pass" if row["agent_survived"] or row["vm_survived"] is False else "minor_mismatch"
            row["notes"] += " Host-side timeout/disposal is acceptable for hostile disposable workloads."
        rows.append(row)
    return rows


def run_trace_replay_smoke(vm):
    traces = [
        ["pwd", "echo hello", "grep needle file.txt"],
        ["python3 -c 'print(1)'", "python3 -m pytest tests"],
        ["printf 'abc\\n' | sed 's/a/A/'", "awk '{print $1}' table.txt"],
        ["python3 -c 'import sys; print(sys.stdin.read().upper())'"],
        ["python3 -c 'import socket; socket.create_connection((\"example.com\",80), timeout=2)'"],
    ]
    rows = []
    for i, trace in enumerate(traces):
        firecracker_results = []
        for j, cmd in enumerate(trace):
            stdin = b"trace stdin\n" if "sys.stdin.read" in cmd else None
            r = run_blocking(vm, cmd, timeout_s=30, stdin=stdin)
            firecracker_results.append(r)
            cls = "pass"
            div = "exact_match"
            if "socket.create_connection" in cmd:
                cls = "pass" if r["exit_code"] != 0 else "fail"
                div = "network_dependency"
            rows.append(test_row(
                "trace.seed_{}.step_{}".format(i, j), "trace_replay_smoke", cmd,
                "serial_console_json_process_api", r, cls,
                notes="seed trace; divergence_category={}".format(div),
                agent_survived=health_survived(vm), vm_survived=vm.proc.poll() is None,
            ))
    rows.append(test_row(
        "trace.wasix_reference", "trace_replay_smoke", "WASIX current backend if available",
        "none",
        {"stdout": b"", "stderr": b"", "exit_code": None, "elapsed_ms": None},
        "unsupported",
        notes="WASIX backend was not available from this LUMI handoff workspace.",
    ))
    return rows


def summarize_rows(rows):
    counts = collections.Counter(row["classification"] for row in rows)
    elapsed = [row["elapsed_ms"] for row in rows if row.get("elapsed_ms") is not None]
    return {
        "classification_counts": dict(counts),
        "elapsed_ms": summarize(elapsed),
        "n": len(rows),
    }


def json_ready(obj):
    if isinstance(obj, bytes):
        return {
            "bytes": len(obj),
            "sha256": sha256_bytes(obj),
            "excerpt": excerpt(obj),
        }
    if isinstance(obj, dict):
        return {str(k): json_ready(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [json_ready(v) for v in obj]
    if isinstance(obj, tuple):
        return [json_ready(v) for v in obj]
    return obj


def decision_from_results(result):
    transport_rows = result.get("command_transport_semantics", {}).get("rows", [])
    process_rows = result.get("process_api_semantics", {}).get("rows", [])
    workflow_rows = result.get("no_network_workflows", {}).get("rows", [])
    reset_rows = result.get("filesystem_reset_semantics", {}).get("rows", [])
    gate_a = all(r["classification"] == "pass" for r in transport_rows if not r["test_id"].startswith("transport.large_")) and any(
        r["test_id"] == "transport.true_stdin_eof" and r["classification"] == "pass" for r in transport_rows
    )
    gate_b = all(r["classification"] in ("pass", "minor_mismatch") for r in process_rows) and any(
        r["test_id"] == "process.start_read_write_close_status" and r["classification"] == "pass" for r in process_rows
    )
    offline_positive = [r for r in workflow_rows if r["test_id"].startswith("offline.") and ".denied." not in r["test_id"]]
    offline_denied = [r for r in workflow_rows if ".denied." in r["test_id"]]
    offline_failures = sorted(r["test_id"] for r in offline_positive if r["classification"] != "pass")
    gate_c = all(r["classification"] == "pass" for r in offline_positive) and all(r["classification"] == "pass" for r in offline_denied)
    gate_d = all(r["classification"] == "pass" for r in reset_rows if r["classification"] != "unsupported")
    gate_e = result.get("operational_lumi_checks", {}).get("paths", {}).get("/dev/kvm", {}).get("writable", False)
    full_rootfs = any(r["test_id"] == "guest_fidelity.full_rootfs" and r["classification"] == "pass"
                      for r in result.get("guest_fidelity", {}).get("rows", []))
    if gate_a and gate_b and gate_c and gate_d and gate_e and full_rootfs:
        rec = "pursue as rollout backend"
    elif gate_a and gate_b and gate_c and gate_d and gate_e:
        rec = "pursue only with vsock/full-rootfs work"
    elif gate_a and gate_b and gate_d and gate_e and set(offline_failures).issubset({"offline.gcc_build"}):
        rec = "pursue only with vsock/full-rootfs work"
    elif gate_c and gate_d and gate_e:
        rec = "pursue as validation tier only"
    else:
        rec = "kill for LUMI no-network rollout execution"
    return {
        "gate_a_no_network_command_channel": gate_a,
        "gate_b_process_api": gate_b,
        "gate_c_offline_workflows": gate_c,
        "offline_workflow_failures": offline_failures,
        "gate_d_reset_correctness": gate_d,
        "gate_e_lumi_operations": bool(gate_e),
        "full_rootfs_available": full_rootfs,
        "recommendation": rec,
    }


def markdown_report(result, analysis=False):
    lines = []
    title = "Firecracker LUMI Phase 3 Analysis" if analysis else "Firecracker LUMI Phase 3 Semantics Report"
    lines.append("# {}".format(title))
    lines.append("")
    lines.append("Generated: {}".format(time.strftime("%Y-%m-%d %H:%M:%S %Z")))
    lines.append("")
    decision = result.get("decision", {})
    lines.append("## Recommendation")
    lines.append("")
    lines.append("- `{}`".format(decision.get("recommendation")))
    for key in (
        "gate_a_no_network_command_channel",
        "gate_b_process_api",
        "gate_c_offline_workflows",
        "gate_d_reset_correctness",
        "gate_e_lumi_operations",
        "full_rootfs_available",
    ):
        lines.append("- `{}`: `{}`".format(key, decision.get(key)))
    lines.append("")
    host = result.get("host_before", {})
    lines.append("## Host")
    lines.append("")
    lines.append("- Node: `{}`".format(host.get("hostname")))
    lines.append("- Kernel: `{}`".format(host.get("uname")))
    lines.append("- CPU: `{}`; logical CPUs: `{}`".format(host.get("cpuinfo_model"), host.get("cpu_count_logical")))
    lines.append("- SLURM: `{}`".format(json.dumps(host.get("slurm", {}), sort_keys=True)))
    lines.append("")
    lines.append("## Guest Image")
    lines.append("")
    guest = result.get("guest_image", {})
    lines.append("- Initramfs: `{:.1f} MiB`; Python pytest installed: `{}` `{}`".format(
        guest.get("image_bytes", 0) / 1024.0 / 1024.0,
        guest.get("pytest", {}).get("installed"),
        guest.get("pytest", {}).get("package"),
    ))
    lines.append("- Agent protocol: `{}`".format(guest.get("phase3_agent", {}).get("protocol")))
    lines.append("")
    for section in (
        "transport_capability",
        "command_transport_semantics",
        "process_api_semantics",
        "no_network_workflows",
        "filesystem_reset_semantics",
        "guest_fidelity",
        "security_resource_semantics",
        "trace_replay_smoke",
    ):
        payload = result.get(section, {})
        rows = payload.get("rows", []) if isinstance(payload, dict) else []
        lines.append("## {}".format(section.replace("_", " ").title()))
        lines.append("")
        if section == "transport_capability":
            lines.append("```json")
            lines.append(json.dumps(payload, indent=2, sort_keys=True)[:4000])
            lines.append("```")
            lines.append("")
            continue
        lines.append("- Summary: `{}`".format(json.dumps(summarize_rows(rows), sort_keys=True)))
        if section == "filesystem_reset_semantics" and payload.get("metadata"):
            meta = payload["metadata"]
            lines.append("- Snapshot memory image: `{:.1f} MiB`; create `{:.3f} ms`.".format(
                (meta.get("mem_bytes") or 0) / 1024.0 / 1024.0,
                meta.get("snapshot_create_ms") or 0.0,
            ))
        lines.append("")
        lines.append("| test | class | exit | ms | stdout bytes | stderr bytes | notes |")
        lines.append("|---|---|---:|---:|---:|---:|---|")
        display_rows = rows if not analysis else rows[:80]
        for row in display_rows:
            lines.append("| `{}` | `{}` | {} | {} | {} | {} | `{}` |".format(
                row.get("test_id"),
                row.get("classification"),
                row.get("exit_code"),
                "{:.3f}".format(row["elapsed_ms"]) if row.get("elapsed_ms") is not None else "",
                row.get("stdout_bytes"),
                row.get("stderr_bytes"),
                (row.get("notes") or "").replace("\n", " ")[:220],
            ))
        if analysis and len(rows) > len(display_rows):
            lines.append("")
            lines.append("_{} additional rows omitted from analysis table; see full report/JSON._".format(len(rows) - len(display_rows)))
        lines.append("")
    lines.append("## Operational Lumi Checks")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(result.get("operational_lumi_checks", {}), indent=2, sort_keys=True)[:6000])
    lines.append("```")
    if result.get("errors"):
        lines.append("")
        lines.append("## Errors")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(result["errors"], indent=2, sort_keys=True))
        lines.append("```")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", default=None)
    ap.add_argument("--mem-mib", type=int, default=512)
    ap.add_argument("--vcpus", type=int, default=1)
    ap.add_argument("--boot-timeout", type=float, default=45.0)
    ap.add_argument("--command-timeout", type=float, default=300.0)
    ap.add_argument("--large-output-sizes", type=int, nargs="+", default=[65536, 1048576, 10485760])
    ap.add_argument("--reset-file-counts", type=int, nargs="+", default=[1000, 10000])
    ap.add_argument("--skipped-reset-file-counts", type=int, nargs="+", default=[100000])
    ap.add_argument("--security-disk-fill-mib", type=int, default=1024)
    ap.add_argument("--with-pytest", action="store_true")
    ap.add_argument("--with-compiler-support", action="store_true")
    ap.add_argument("--skip-security", action="store_true")
    args = ap.parse_args()

    run_dir = Path(args.run_dir or tempfile.mkdtemp(prefix="fc-phase3-"))
    mkdir(run_dir)
    job_id = os.environ.get("SLURM_JOB_ID", "local")
    result = {
        "host_before": host_snapshot(),
        "args": vars(args),
        "errors": [],
    }
    vm = None
    try:
        cache = run_dir / "cache"
        log("resolving Firecracker/kernel")
        fc = download_firecracker(cache)
        kernel = download_kernel(cache)
        log("building phase3 initramfs")
        initrd = build_phase3_initramfs(
            run_dir / "build",
            with_pytest=args.with_pytest,
            with_compiler_support=args.with_compiler_support,
        )
        result["firecracker"] = fc
        result["kernel"] = kernel
        result["guest_image"] = initrd
        result["operational_lumi_checks"] = operational_lumi_checks(fc, run_dir)
        result["transport_capability"] = {
            "serial_console": {
                "classification": "pass",
                "protocol": "json lines over Firecracker stdout/stdin serial console",
            },
            "vsock_if_available": {
                "classification": "unsupported",
                "host_dev_vhost_vsock": result["operational_lumi_checks"]["paths"].get("/dev/vhost-vsock"),
                "notes": "Vsock was probed for host availability only. This harness does not yet implement a vsock guest agent.",
            },
        }

        log("booting phase3 VM")
        vm, boot, ready = boot_phase3_vm("phase3-main", args, fc, kernel, initrd, run_dir)
        result["main_vm_boot"] = boot
        result["main_vm_ready"] = ready
        log("running command transport semantics")
        rows = run_command_transport_semantics(vm, args)
        result["command_transport_semantics"] = {"rows": rows}
        log("running process API semantics")
        rows = run_process_api_semantics(vm, args)
        result["process_api_semantics"] = {"rows": rows}
        log("running no-network workflows")
        rows = run_no_network_workflows(vm, args)
        result["no_network_workflows"] = {"rows": rows}
        log("running guest fidelity probes")
        rows = run_guest_fidelity(vm)
        result["guest_fidelity"] = {"rows": rows}
        log("running trace replay smoke")
        rows = run_trace_replay_smoke(vm)
        result["trace_replay_smoke"] = {"rows": rows}
        vm.stop()
        vm = None
        log("running filesystem reset semantics")
        result["filesystem_reset_semantics"] = run_filesystem_reset_semantics(args, fc, kernel, initrd, run_dir)
        if args.skip_security:
            result["security_resource_semantics"] = {"rows": []}
        else:
            log("running security/resource semantics")
            result["security_resource_semantics"] = {
                "rows": run_security_resource_semantics(args, fc, kernel, initrd, run_dir)
            }
    except Exception as exc:
        result["errors"].append(compact_error(exc))
        log("phase3 error: {}".format(exc))
    finally:
        if vm is not None:
            vm.stop()
        result["host_after"] = host_snapshot()
        result["decision"] = decision_from_results(result)
        safe_result = json_ready(result)
        report_json = run_dir / "firecracker-lumi-phase3-{}.json".format(job_id)
        report_md = run_dir / "firecracker-lumi-phase3-{}.md".format(job_id)
        report_analysis = run_dir / "firecracker-lumi-phase3-{}-analysis.md".format(job_id)
        report_json.write_text(json.dumps(safe_result, indent=2, sort_keys=True))
        report_md.write_text(markdown_report(safe_result, analysis=False))
        report_analysis.write_text(markdown_report(safe_result, analysis=True))
        print("RESULT_JSON={}".format(report_json), flush=True)
        print("RESULT_MD={}".format(report_md), flush=True)
        print("RESULT_ANALYSIS={}".format(report_analysis), flush=True)


if __name__ == "__main__":
    main()
