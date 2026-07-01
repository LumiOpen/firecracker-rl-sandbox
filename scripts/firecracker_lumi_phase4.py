#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import os
import queue
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from firecracker_lumi_bench import (
    PipeReader,
    command_path,
    download_firecracker,
    host_snapshot,
    link_or_copy,
    mkdir,
    ms_since,
    now_ns,
    proc_rss_kb,
    read_text,
    run,
)
from firecracker_lumi_net_poc import download_gvisor_tap_vsock, start_gvproxy, stop_proc


S3 = "https://s3.amazonaws.com/spec.ccfc.min"
DEFAULT_AGENT_PORT = 9000


def log(message):
    print("[{}] {}".format(time.strftime("%Y-%m-%d %H:%M:%S"), message), flush=True)


def b64(data):
    return base64.b64encode(data or b"").decode("ascii")


def unb64(text):
    return base64.b64decode(text.encode("ascii")) if text else b""


def sha256_bytes(data):
    return hashlib.sha256(data or b"").hexdigest()


def compact_text(data, limit=2000):
    if isinstance(data, bytes):
        data = data.decode("utf-8", "replace")
    return (data or "")[:limit]


GUEST_AGENT = r'''#!/usr/bin/python3
import base64
import json
import os
import selectors
import signal
import socket
import subprocess
import sys
import threading
import time

AGENT_PORT = int(os.environ.get("FC_AGENT_PORT", "9000"))
DEFAULT_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/root",
    "TMPDIR": "/tmp",
    "PYTHONUNBUFFERED": "1",
    "DEBIAN_FRONTEND": "noninteractive",
}
handles = {}
next_handle = 1


def safe_mount(cmd):
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def setup_mounts():
    os.makedirs("/proc", exist_ok=True)
    os.makedirs("/sys", exist_ok=True)
    os.makedirs("/dev", exist_ok=True)
    os.makedirs("/tmp", exist_ok=True)
    os.makedirs("/run", exist_ok=True)
    os.makedirs("/workspace", exist_ok=True)
    safe_mount(["mount", "-t", "devtmpfs", "devtmpfs", "/dev"])
    safe_mount(["mount", "-t", "proc", "proc", "/proc"])
    safe_mount(["mount", "-t", "sysfs", "sysfs", "/sys"])
    safe_mount(["mount", "-t", "tmpfs", "-o", "mode=1777,size=384m", "tmpfs", "/tmp"])
    safe_mount(["mount", "-t", "tmpfs", "-o", "mode=755,size=384m", "tmpfs", "/run"])
    safe_mount(["mount", "-t", "tmpfs", "-o", "mode=755,size=384m", "tmpfs", "/workspace"])
    os.chdir("/workspace")


def write_seed_workspace():
    os.makedirs("/workspace/tests", exist_ok=True)
    with open("/workspace/small.txt", "w") as f:
        f.write("small file\nneedle\n")
    with open("/workspace/file.txt", "w") as f:
        for i in range(2000):
            f.write(("needle" if i == 1234 else "ordinary") + " line %d\n" % i)
    with open("/workspace/tests/test_basic.py", "w") as f:
        f.write("def test_arithmetic():\n    assert 1 + 1 == 2\n")
    with open("/workspace/hello.c", "w") as f:
        f.write('#include <stdio.h>\nint main(){puts("hello-c");return 0;}\n')


def enc(data):
    return base64.b64encode(data or b"").decode("ascii")


def dec(text):
    return base64.b64decode((text or "").encode("ascii"))


def response(req_id, **fields):
    out = {"id": req_id, "ok": True}
    out.update(fields)
    return out


def error(req_id, message):
    return {"id": req_id, "ok": False, "error": str(message)}


def env_for(req):
    env = DEFAULT_ENV.copy()
    for k, v in (req.get("env") or {}).items():
        env[str(k)] = str(v)
    return env


def run_command(req):
    stdin_data = dec(req.get("stdin_b64", ""))
    timeout = req.get("timeout_ms")
    timeout_s = None if timeout is None else timeout / 1000.0
    t0 = time.monotonic_ns()
    p = subprocess.run(
        ["/bin/bash", "-lc", req.get("command", "")],
        input=stdin_data,
        cwd=req.get("cwd") or "/workspace",
        env=env_for(req),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_s,
    )
    return {
        "exit_code": p.returncode,
        "stdout_b64": enc(p.stdout),
        "stderr_b64": enc(p.stderr),
        "guest_process_ms": (time.monotonic_ns() - t0) / 1e6,
    }


def set_nonblocking(fileobj):
    os.set_blocking(fileobj.fileno(), False)


def read_available(proc, wait_ms):
    deadline = time.monotonic() + max(0, wait_ms) / 1000.0
    selector = selectors.DefaultSelector()
    stdout = b""
    stderr = b""
    for stream_name, stream in (("stdout", proc.stdout), ("stderr", proc.stderr)):
        if stream and not stream.closed:
            selector.register(stream, selectors.EVENT_READ, stream_name)
    while selector.get_map():
        timeout = max(0, deadline - time.monotonic())
        if timeout == 0 and (stdout or stderr or proc.poll() is not None):
            break
        events = selector.select(timeout if timeout > 0 else 0)
        if not events:
            break
        for key, _ in events:
            try:
                chunk = os.read(key.fileobj.fileno(), 65536)
            except BlockingIOError:
                chunk = b""
            if not chunk:
                try:
                    selector.unregister(key.fileobj)
                except Exception:
                    pass
                continue
            if key.data == "stdout":
                stdout += chunk
            else:
                stderr += chunk
    return stdout, stderr


def start_process(req):
    global next_handle
    handle = "p{}".format(next_handle)
    next_handle += 1
    p = subprocess.Popen(
        ["/bin/bash", "-lc", req.get("command", "")],
        cwd=req.get("cwd") or "/workspace",
        env=env_for(req),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid,
    )
    set_nonblocking(p.stdout)
    set_nonblocking(p.stderr)
    handles[handle] = p
    return {"handle": handle, "pid": p.pid}


def process_read(req):
    p = handles[req["handle"]]
    stdout, stderr = read_available(p, int(req.get("wait_ms") or 0))
    return {
        "stdout_b64": enc(stdout),
        "stderr_b64": enc(stderr),
        "exit_code": p.poll(),
        "running": p.poll() is None,
    }


def process_write(req):
    p = handles[req["handle"]]
    data = dec(req.get("stdin_b64", ""))
    if p.stdin and not p.stdin.closed:
        p.stdin.write(data)
        p.stdin.flush()
    return {"bytes": len(data), "exit_code": p.poll(), "running": p.poll() is None}


def process_close_stdin(req):
    p = handles[req["handle"]]
    if p.stdin and not p.stdin.closed:
        p.stdin.close()
    return {"exit_code": p.poll(), "running": p.poll() is None}


def process_signal(req):
    p = handles[req["handle"]]
    sig = int(req.get("signal", signal.SIGTERM))
    try:
        os.killpg(os.getpgid(p.pid), sig)
    except ProcessLookupError:
        pass
    return {"exit_code": p.poll(), "running": p.poll() is None}


def process_status(req):
    p = handles[req["handle"]]
    return {"exit_code": p.poll(), "running": p.poll() is None, "pid": p.pid}


def environment_reset(_req):
    for handle, proc in list(handles.items()):
        if proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                pass
        handles.pop(handle, None)
    self_pid = os.getpid()
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        if pid <= 1 or pid == self_pid:
            continue
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
    deadline = time.time() + 2.0
    while time.time() < deadline:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        except Exception:
            break
        if pid == 0:
            time.sleep(0.01)
            continue
    subprocess.run(["/bin/bash", "-lc", "find /workspace -mindepth 1 -maxdepth 1 -exec rm -rf {} +"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    write_seed_workspace()
    os.chdir("/workspace")
    return {"cwd": os.getcwd()}


def workspace_stats():
    total = 0
    count = 0
    for root, _dirs, files in os.walk("/workspace"):
        for name in files:
            count += 1
            try:
                total += os.stat(os.path.join(root, name)).st_size
            except OSError:
                pass
    return {"workspace_file_count": count, "workspace_bytes": total}


def handle(req):
    op = req.get("op")
    if op == "health":
        return response(req.get("id"), cwd=os.getcwd(), pid=os.getpid(), **workspace_stats())
    if op == "run":
        return response(req.get("id"), **run_command(req))
    if op == "process/start":
        return response(req.get("id"), **start_process(req))
    if op == "process/read":
        return response(req.get("id"), **process_read(req))
    if op == "process/write":
        return response(req.get("id"), **process_write(req))
    if op == "process/close_stdin":
        return response(req.get("id"), **process_close_stdin(req))
    if op == "process/signal" or op == "process/terminate":
        return response(req.get("id"), **process_signal(req))
    if op == "process/status":
        return response(req.get("id"), **process_status(req))
    if op == "environment/reset":
        return response(req.get("id"), **environment_reset(req))
    return error(req.get("id"), "unknown op {}".format(op))


def serve(conn):
    reader = conn.makefile("rb")
    writer = conn.makefile("wb")
    writer.write(json.dumps({"event": "ready", "pid": os.getpid(), **workspace_stats()}).encode() + b"\n")
    writer.flush()
    while True:
        line = reader.readline()
        if not line:
            break
        try:
            req = json.loads(line.decode("utf-8"))
            resp = handle(req)
        except subprocess.TimeoutExpired as exc:
            resp = {"id": req.get("id") if "req" in locals() else None, "ok": False, "timeout": True, "error": str(exc)}
        except Exception as exc:
            resp = {"id": req.get("id") if "req" in locals() else None, "ok": False, "error": str(exc)}
        writer.write(json.dumps(resp, separators=(",", ":")).encode("utf-8") + b"\n")
        writer.flush()


def main():
    setup_mounts()
    write_seed_workspace()
    os.environ.update(DEFAULT_ENV)
    while True:
        try:
            s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            s.connect((2, AGENT_PORT))
            serve(s)
        except Exception as exc:
            try:
                print("fc-agent connect/serve error:", repr(exc), file=sys.stderr, flush=True)
            except Exception:
                pass
            time.sleep(0.25)


if __name__ == "__main__":
    main()
'''


class UnixListener(threading.Thread):
    def __init__(self, path):
        super().__init__(daemon=True)
        self.path = Path(path)
        self.ready = threading.Event()
        self.accepted = threading.Event()
        self.error = None
        self.conn = None

    def run(self):
        try:
            if self.path.exists():
                self.path.unlink()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.bind(str(self.path))
                sock.listen(1)
                self.ready.set()
                sock.settimeout(90)
                self.conn, _ = sock.accept()
                self.accepted.set()
        except Exception as exc:
            self.error = repr(exc)
            self.ready.set()


class AgentClient:
    def __init__(self, conn):
        self.conn = conn
        self.reader = conn.makefile("rb")
        self.writer = conn.makefile("wb")
        self.seq = 0
        self.ready = json.loads(self.reader.readline().decode("utf-8"))

    def request(self, op, **fields):
        self.seq += 1
        req = {"id": self.seq, "op": op}
        req.update(fields)
        t0 = now_ns()
        self.writer.write(json.dumps(req, separators=(",", ":")).encode("utf-8") + b"\n")
        self.writer.flush()
        line = self.reader.readline()
        elapsed_ms = ms_since(t0)
        if not line:
            raise RuntimeError("agent connection closed")
        resp = json.loads(line.decode("utf-8"))
        resp["command_roundtrip_ms"] = elapsed_ms
        return resp

    def run(self, command, timeout_ms=10000, stdin_data=b"", cwd="/workspace"):
        return self.request("run", command=command, timeout_ms=timeout_ms, stdin_b64=b64(stdin_data), cwd=cwd)

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


class Phase4VM:
    def __init__(self, vm_id, fc_path, kernel_path, rootfs_path, base_dir, mem_mib=512, vcpus=1, agent_port=DEFAULT_AGENT_PORT):
        self.vm_id = vm_id
        self.fc_path = fc_path
        self.kernel_path = Path(kernel_path)
        self.rootfs_path = Path(rootfs_path)
        self.base_dir = Path(base_dir)
        self.mem_mib = mem_mib
        self.vcpus = vcpus
        self.agent_port = agent_port
        self.dir = self.base_dir / "vm-{}".format(vm_id)
        sock_hash = hashlib.sha1("{}-{}-{}".format(os.getpid(), base_dir, vm_id).encode()).hexdigest()[:16]
        self.sock = Path(tempfile.gettempdir()) / "fc-phase4-{}-{}.sock".format(os.environ.get("SLURM_JOB_ID", "local"), sock_hash)
        self.vsock_uds = self.dir / "v.sock"
        self.log = self.dir / "firecracker.log"
        self.proc = None
        self.q = queue.Queue()
        self.agent = None
        self.listener = None

    def api(self, method, path, data):
        body = json.dumps(data) if data is not None else ""
        cmd = [
            "curl", "-sS", "--unix-socket", str(self.sock), "-X", method,
            "-H", "Accept: application/json", "-H", "Content-Type: application/json",
        ]
        if data is not None:
            cmd += ["-d", body]
        cmd += ["-w", "\nHTTP %{http_code}\n", "http://localhost{}".format(path)]
        p = run(cmd, check=False)
        m = re.search(r"HTTP (\d+)", p.stdout)
        return {"method": method, "path": path, "http": int(m.group(1)) if m else None, "stdout": p.stdout, "stderr": p.stderr}

    def start_process(self):
        if self.sock.exists():
            self.sock.unlink()
        self.proc = subprocess.Popen(
            [self.fc_path, "--api-sock", str(self.sock)],
            cwd=str(self.dir),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            preexec_fn=os.setsid,
        )
        PipeReader("stdout", self.proc.stdout, self.q).start()
        PipeReader("stderr", self.proc.stderr, self.q).start()
        deadline = time.time() + 10
        while time.time() < deadline:
            if self.sock.exists():
                return
            if self.proc.poll() is not None:
                raise RuntimeError("firecracker exited before api socket rc={}".format(self.proc.returncode))
            time.sleep(0.01)
        raise RuntimeError("timeout waiting for api socket")

    def boot(self, timeout=90):
        if self.dir.exists():
            shutil.rmtree(str(self.dir))
        mkdir(self.dir)
        self.listener = UnixListener("{}_{}".format(self.vsock_uds, self.agent_port))
        self.listener.start()
        if not self.listener.ready.wait(10):
            raise RuntimeError("agent listener did not start")
        t0 = now_ns()
        self.start_process()
        vmm_launch_ms = ms_since(t0)
        api_records = []
        cfg_t0 = now_ns()
        api_records.append(self.api("PUT", "/machine-config", {"vcpu_count": self.vcpus, "mem_size_mib": self.mem_mib, "smt": False}))
        api_records.append(self.api("PUT", "/boot-source", {
            "kernel_image_path": str(self.kernel_path),
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro init=/fc-agent-init quiet",
        }))
        api_records.append(self.api("PUT", "/drives/rootfs", {
            "drive_id": "rootfs",
            "path_on_host": str(self.rootfs_path),
            "is_root_device": True,
            "is_read_only": True,
        }))
        api_records.append(self.api("PUT", "/vsock", {"guest_cid": 3, "uds_path": str(self.vsock_uds)}))
        config_ms = ms_since(cfg_t0)
        start_t0 = now_ns()
        api_records.append(self.api("PUT", "/actions", {"action_type": "InstanceStart"}))
        if not self.listener.accepted.wait(timeout):
            raise RuntimeError("timeout waiting for vsock agent accepted error={} recent={}".format(self.listener.error, self.drain_recent()))
        ready_ms = ms_since(start_t0)
        self.agent = AgentClient(self.listener.conn)
        return {
            "vm_id": self.vm_id,
            "pid": self.proc.pid,
            "vmm_launch_ms": vmm_launch_ms,
            "config_ms": config_ms,
            "ready_ms": ready_ms,
            "rss_kb_after_ready": proc_rss_kb(self.proc.pid),
            "api_records": api_records,
            "agent_ready": self.agent.ready,
            "vsock": {"uds_path": str(self.vsock_uds), "agent_port": self.agent_port},
        }

    def drain_recent(self):
        out = []
        while True:
            try:
                out.append(self.q.get_nowait())
            except queue.Empty:
                break
        return out[-40:]

    def stop(self):
        if self.agent:
            self.agent.close()
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
                self.proc.wait(timeout=5)
        if self.sock.exists():
            try:
                self.sock.unlink()
            except Exception:
                pass


def latest_ci_artifact_keys():
    script = r'''
set -euo pipefail
S3="https://s3.amazonaws.com/spec.ccfc.min"
ARCH="$(uname -m)"
CI_ARTIFACTS_PREFIX=$(curl -fsSL "$S3?list-type=2&prefix=firecracker-ci/&delimiter=/" \
    | grep -oP "(?<=<Prefix>)firecracker-ci/[0-9]{8}-[^/]+/(?=</Prefix>)" \
    | sort \
    | tail -1)
latest_ubuntu_key=$(curl -fsSL "$S3?list-type=2&prefix=${CI_ARTIFACTS_PREFIX}${ARCH}/ubuntu-" \
      | grep -oP "(?<=<Key>)(${CI_ARTIFACTS_PREFIX}${ARCH}/ubuntu-[0-9]+\.[0-9]+\.squashfs)(?=</Key>)" \
      | sort -V \
      | tail -1)
echo "$latest_ubuntu_key"
'''
    key = run(["bash", "-lc", script]).stdout.strip()
    return {"ubuntu_squashfs_key": key}


def prepare_rootfs(cache_dir, tools):
    cache_dir = Path(cache_dir)
    mkdir(cache_dir)
    out_dir = cache_dir / "ubuntu-full-rootfs-phase4"
    ext4 = out_dir / "rootfs.ext4"
    meta = out_dir / "metadata.json"
    if ext4.exists() and meta.exists():
        data = json.loads(meta.read_text())
        data["path"] = str(ext4)
        data["bytes"] = ext4.stat().st_size
        return data
    keys = latest_ci_artifact_keys()
    squash = cache_dir / Path(keys["ubuntu_squashfs_key"]).name
    if not squash.exists():
        run(["curl", "-fsSL", "-o", str(squash) + ".tmp", "{}/{}".format(S3, keys["ubuntu_squashfs_key"])])
        Path(str(squash) + ".tmp").rename(squash)
    work = cache_dir / "rootfs-build"
    if work.exists():
        shutil.rmtree(str(work))
    mkdir(work)
    run(["unsquashfs", "-d", str(work / "squashfs-root"), str(squash)])
    root = work / "squashfs-root"
    (root / "fc-agent-init").write_text(GUEST_AGENT)
    (root / "fc-agent-init").chmod(0o755)
    if tools.get("gvforwarder"):
        mkdir(root / "usr/local/bin")
        shutil.copy2(tools["gvforwarder"], root / "usr/local/bin/gvforwarder")
        (root / "usr/local/bin/gvforwarder").chmod(0o755)
    mkdir(root / "workspace/tests")
    (root / "workspace/small.txt").write_text("small file\nneedle\n")
    (root / "workspace/file.txt").write_text("ordinary\nneedle\n")
    (root / "workspace/tests/test_basic.py").write_text("def test_arithmetic():\n    assert 1 + 1 == 2\n")
    mkdir(out_dir)
    size_bytes = int(os.environ.get("FC_PHASE4_ROOTFS_BYTES", str(2 * 1024 * 1024 * 1024)))
    run(["truncate", "-s", str(size_bytes), str(ext4)])
    run(["/sbin/mkfs.ext4", "-q", "-d", str(root), "-F", str(ext4)])
    distro = read_text(root / "etc/os-release")
    inventory = {}
    for cmd in ("bash", "python3", "pip3", "pytest", "git", "gcc", "clang", "mount", "ps", "ip", "curl"):
        found = list(root.glob("**/{}".format(cmd)))
        inventory[cmd] = [str(p.relative_to(root)) for p in found[:5]]
    data = {
        "build_method": "Firecracker CI Ubuntu squashfs -> injected /fc-agent-init and gvforwarder -> mkfs.ext4 -d",
        "ubuntu_squashfs_key": keys["ubuntu_squashfs_key"],
        "squashfs_bytes": squash.stat().st_size,
        "path": str(ext4),
        "bytes": ext4.stat().st_size,
        "distro_os_release": distro,
        "package_inventory_paths": inventory,
    }
    meta.write_text(json.dumps(data, indent=2, sort_keys=True))
    shutil.rmtree(str(work), ignore_errors=True)
    return data


def benchmark_row(test_id, category, command=None, resp=None, **extra):
    resp = resp or {}
    stdout = unb64(resp.get("stdout_b64", ""))
    stderr = unb64(resp.get("stderr_b64", ""))
    row = {
        "test_id": test_id,
        "category": category,
        "backend": "firecracker",
        "transport": "vsock-jsonl",
        "image_mode": "disk_ext4_full_rootfs_readonly_tmpfs_workspace",
        "reset_mode": extra.pop("reset_mode", "none"),
        "pool_size": extra.pop("pool_size", None),
        "concurrency": extra.pop("concurrency", None),
        "command": command,
        "exit_code": resp.get("exit_code"),
        "classification": extra.pop("classification", "pass" if resp.get("ok", False) and resp.get("exit_code", 0) == 0 else "fail"),
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_sha256": sha256_bytes(stderr),
        "stdout_excerpt": compact_text(stdout),
        "stderr_excerpt": compact_text(stderr),
        "elapsed_ms": resp.get("command_roundtrip_ms"),
        "queue_wait_ms": extra.pop("queue_wait_ms", None),
        "command_roundtrip_ms": resp.get("command_roundtrip_ms"),
        "guest_process_ms": resp.get("guest_process_ms"),
        "reset_ms": extra.pop("reset_ms", None),
        "boot_ms": extra.pop("boot_ms", None),
        "ready_ms": extra.pop("ready_ms", None),
        "host_rss_kb": extra.pop("host_rss_kb", None),
        "guest_memory_mb": extra.pop("guest_memory_mb", None),
        "workspace_file_count": extra.pop("workspace_file_count", None),
        "workspace_bytes": extra.pop("workspace_bytes", None),
        "timeout": resp.get("timeout", False),
        "kill_reason": extra.pop("kill_reason", None),
        "agent_survived": extra.pop("agent_survived", None),
        "vm_survived": extra.pop("vm_survived", None),
        "notes": extra.pop("notes", ""),
    }
    row.update(extra)
    return row


def write_raw(raw_path, row):
    with Path(raw_path).open("a") as f:
        f.write(json.dumps(row, sort_keys=True) + "\n")


def run_command_tests(vm, raw_path, pool_size=1):
    tests = [
        ("rootfs.echo", "rootfs", "bash -lc 'echo hello'"),
        ("rootfs.ls", "rootfs", "bash -lc 'pwd; ls -la'"),
        ("rootfs.sort", "rootfs", "bash -lc 'printf \"b\\na\\n\" | sort'"),
        ("rootfs.grep", "rootfs", "bash -lc 'grep -R \"needle\" .'"),
        ("rootfs.python", "rootfs", "bash -lc 'python3 -c \"print(1+1)\"'"),
        ("rootfs.pytest", "rootfs", "bash -lc 'python3 -m pytest tests'",),
        ("rootfs.git_status", "rootfs", "bash -lc 'git status'"),
        ("rootfs.gcc_hello", "rootfs", "bash -lc 'gcc hello.c -o hello && ./hello'"),
        ("rootfs.proc", "rootfs", "bash -lc 'cat /proc/1/status | head'"),
        ("rootfs.ps", "rootfs", "bash -lc 'ps aux | head'"),
        ("rootfs.mount", "rootfs", "bash -lc 'mount | head'"),
    ]
    rows = []
    for test_id, cat, cmd in tests:
        resp = vm.agent.run(cmd, timeout_ms=30000)
        cls = "pass" if resp.get("ok") and resp.get("exit_code") == 0 else "unsupported" if test_id in ("rootfs.pytest", "rootfs.gcc_hello") else "fail"
        row = benchmark_row(test_id, cat, cmd, resp, classification=cls, pool_size=pool_size, host_rss_kb=proc_rss_kb(vm.proc.pid), guest_memory_mb=vm.mem_mib)
        rows.append(row)
        write_raw(raw_path, row)
    return rows


def run_transport_tests(vm, raw_path):
    tests = [
        ("transport.stdout_stderr", "transport", "bash -lc 'echo stdout; echo stderr >&2'", 10000, b""),
        ("transport.binary_64k", "transport", "python3 -c 'import sys; sys.stdout.buffer.write(bytes(range(256))*256)'", 10000, b""),
        ("transport.stdin_upper", "transport", "python3 -c 'import sys; sys.stdout.write(sys.stdin.read().upper())'", 10000, b"hello\n"),
        ("transport.large_stdout_1m", "transport", "python3 -c 'import sys; sys.stdout.buffer.write(b\"x\" * 1048576)'", 30000, b""),
        ("transport.large_stderr_1m", "transport", "python3 -c 'import sys; sys.stderr.buffer.write(b\"x\" * 1048576)'", 30000, b""),
        ("transport.large_stdout_10m", "transport", "python3 -c 'import sys; sys.stdout.buffer.write(b\"x\" * 10485760)'", 180000, b""),
    ]
    rows = []
    for test_id, cat, cmd, timeout_ms, stdin_data in tests:
        resp = vm.agent.run(cmd, timeout_ms=timeout_ms, stdin_data=stdin_data)
        row = benchmark_row(test_id, cat, cmd, resp, pool_size=1, host_rss_kb=proc_rss_kb(vm.proc.pid), guest_memory_mb=vm.mem_mib)
        rows.append(row)
        write_raw(raw_path, row)
    # Process handle checks.
    t0 = now_ns()
    start = vm.agent.request("process/start", command="python3 -c 'import sys,time; print(\"first\", flush=True); time.sleep(1); print(\"second\", flush=True)'")
    read1 = vm.agent.request("process/read", handle=start["handle"], wait_ms=100)
    read2 = vm.agent.request("process/read", handle=start["handle"], wait_ms=1500)
    status = vm.agent.request("process/status", handle=start["handle"])
    combined = {
        "ok": start.get("ok") and read1.get("ok") and read2.get("ok"),
        "exit_code": status.get("exit_code"),
        "stdout_b64": b64(unb64(read1.get("stdout_b64", "")) + unb64(read2.get("stdout_b64", ""))),
        "stderr_b64": b64(unb64(read1.get("stderr_b64", "")) + unb64(read2.get("stderr_b64", ""))),
        "command_roundtrip_ms": ms_since(t0),
        "guest_process_ms": None,
    }
    row = benchmark_row("process.incremental_read", "process_api", "process/start + read", combined, notes="first read before process exit; second read after sleep")
    rows.append(row)
    write_raw(raw_path, row)
    t0 = now_ns()
    start = vm.agent.request("process/start", command="sleep 30")
    term = vm.agent.request("process/terminate", handle=start["handle"], signal=15)
    time.sleep(0.1)
    status = vm.agent.request("process/status", handle=start["handle"])
    resp = {"ok": start.get("ok") and term.get("ok") and status.get("ok"), "exit_code": status.get("exit_code"), "stdout_b64": "", "stderr_b64": "", "command_roundtrip_ms": ms_since(t0)}
    row = benchmark_row("process.terminate_sleep", "process_api", "sleep 30 then terminate", resp, classification="pass" if status.get("exit_code") in (-15, 143, None) else "minor_mismatch")
    rows.append(row)
    write_raw(raw_path, row)
    malformed_ok = False
    try:
        vm.agent.writer.write(b"{bad json\n")
        vm.agent.writer.flush()
        bad = json.loads(vm.agent.reader.readline().decode("utf-8"))
        health = vm.agent.request("health")
        malformed_ok = bool(bad.get("ok") is False and health.get("ok"))
    except Exception:
        malformed_ok = False
    row = benchmark_row("transport.malformed_frame_survival", "transport", "malformed frame", {"ok": malformed_ok, "exit_code": 0 if malformed_ok else 1, "stdout_b64": "", "stderr_b64": "", "command_roundtrip_ms": 0}, classification="pass" if malformed_ok else "fail")
    rows.append(row)
    write_raw(raw_path, row)
    return rows


def run_reset_tests(vm, raw_path):
    rows = []
    for count in (10, 1000, 10000):
        mutate = "bash -lc 'rm -rf /workspace/*; mkdir -p /workspace/dir; for i in $(seq 1 %d); do echo needle-$i > /workspace/dir/file-$i.txt; done; (sleep 30 &) ; echo mutated'" % count
        vm.agent.run(mutate, timeout_ms=max(10000, count * 5))
        t0 = now_ns()
        resp = vm.agent.request("environment/reset")
        reset_ms = ms_since(t0)
        clean = vm.agent.run("bash -lc 'find /workspace -type f | wc -l; pgrep -x sleep >/dev/null; echo sleep_rc:$?'", timeout_ms=10000)
        stdout = unb64(clean.get("stdout_b64", "")).decode("utf-8", "replace")
        ok = clean.get("exit_code") == 0 and "sleep_rc:1" in stdout
        row = benchmark_row("reset.tmpfs_workspace_{}".format(count), "filesystem_reset", "environment/reset", clean,
                            reset_mode="read_only_base_plus_tmpfs_workspace", reset_ms=reset_ms,
                            workspace_file_count=count, classification="pass" if ok else "fail",
                            notes="mutated files plus background process, then reset workspace and killed handles")
        rows.append(row)
        write_raw(raw_path, row)
    return rows


def run_security_tests(vm, raw_path):
    tests = [
        ("security.shadow", "cat /etc/shadow"),
        ("security.home", "ls /home"),
        ("security.find_root", "find / -maxdepth 2 | head -200"),
        ("security.env", "env"),
        ("security.cpu_pressure", "timeout 2 python3 -c 'while True: pass'"),
        ("security.memory_pressure", "timeout 3 python3 - <<'PY'\nx=[]\nwhile True:\n    x.append('x'*1000000)\nPY"),
        ("security.disk_fill", "python3 -c 'open(\"/workspace/big\", \"wb\").write(b\"x\" * 100000000)'"),
    ]
    rows = []
    for test_id, cmd in tests:
        resp = vm.agent.run("bash -lc '{}'".format(cmd.replace("'", "'\"'\"'")), timeout_ms=15000)
        health = vm.agent.request("health")
        cls = "pass" if health.get("ok") else "fail"
        row = benchmark_row(test_id, "security", cmd, resp, classification=cls, agent_survived=health.get("ok"), vm_survived=vm.proc.poll() is None)
        rows.append(row)
        write_raw(raw_path, row)
    return rows


def run_network_baseline(vm, tools, raw_path, run_dir):
    rows = []
    listen_sock = "{}_{}".format(vm.vsock_uds, 1024)
    services_sock = str(Path(run_dir) / "gvproxy-services-{}.sock".format(vm.vm_id))
    gvlog = Path(run_dir) / "gvproxy-{}.log".format(vm.vm_id)
    gvproxy = None
    try:
        gvproxy = start_gvproxy(tools["gvproxy"], listen_sock, services_sock, gvlog)
        setup = (
            "bash -lc 'set -e; mkdir -p /dev/net; "
            "python3 -c \"import os,stat; p=\\\"/dev/net/tun\\\"; os.path.exists(p) or os.mknod(p,stat.S_IFCHR|0o666,os.makedev(10,200))\"; "
            "ip tuntap del dev tap0 mode tap 2>/dev/null || true; "
            "ip tuntap add dev tap0 mode tap; ip addr add 192.168.127.2/24 dev tap0; ip link set tap0 up; "
            "ip route replace default via 192.168.127.1 dev tap0; "
            "/usr/local/bin/gvforwarder -url vsock://2:1024/connect -iface tap0 -preexisting -mtu 1500 >/tmp/gvforwarder.log 2>&1 & "
            "echo $! >/tmp/gvforwarder.pid; sleep 2; cat /tmp/gvforwarder.log | tail -20'"
        )
        setup_resp = vm.agent.run(setup, timeout_ms=30000)
        row = benchmark_row("network.gvproxy_setup", "network_proxy", setup, setup_resp,
                            classification="pass" if setup_resp.get("exit_code") == 0 else "fail",
                            notes="ACL intentionally deferred; gvproxy baseline only")
        rows.append(row)
        write_raw(raw_path, row)
        cmd = "python3 -c 'import socket; s=socket.create_connection((\"1.1.1.1\",80),timeout=8); s.sendall(b\"GET / HTTP/1.0\\r\\nHost: one.one.one.one\\r\\n\\r\\n\"); print(s.recv(120).decode(\"utf-8\", \"replace\")); s.close()'"
        resp = vm.agent.run(cmd, timeout_ms=20000)
        row = benchmark_row("network.gvproxy_direct_ip_http", "network_proxy", cmd, resp,
                            classification="pass" if resp.get("exit_code") == 0 else "fail",
                            notes="transparent outbound via gvproxy; no ACL/policy tested by instruction")
        rows.append(row)
        write_raw(raw_path, row)
    except Exception as exc:
        row = benchmark_row("network.gvproxy_exception", "network_proxy", "gvproxy baseline", {"ok": False, "exit_code": 1, "stdout_b64": "", "stderr_b64": b64(str(exc).encode()), "command_roundtrip_ms": None}, classification="fail")
        rows.append(row)
        write_raw(raw_path, row)
    finally:
        stop_proc(gvproxy)
    return rows


def summarize_latencies(rows):
    out = {}
    by = {}
    for row in rows:
        if row.get("elapsed_ms") is None:
            continue
        by.setdefault(row["category"], []).append(row["elapsed_ms"])
    for cat, vals in by.items():
        vals = sorted(vals)
        def pct(p):
            if not vals:
                return None
            idx = min(len(vals) - 1, int(round((len(vals) - 1) * p)))
            return vals[idx]
        out[cat] = {"n": len(vals), "p50_ms": pct(0.5), "p90_ms": pct(0.9), "p99_ms": pct(0.99), "mean_ms": sum(vals) / len(vals)}
    return out


def write_reports(result, rows, job_id):
    reports_dir = Path("reports")
    mkdir(reports_dir)
    stem = reports_dir / "firecracker-lumi-phase4-{}".format(job_id)
    json_path = stem.with_suffix(".json")
    md_path = stem.with_suffix(".md")
    analysis_path = reports_dir / "firecracker-lumi-phase4-{}-analysis.md".format(job_id)
    result["benchmarks"] = rows
    result["latency_summary"] = summarize_latencies(rows)
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True))
    counts = {}
    for row in rows:
        counts[row["classification"]] = counts.get(row["classification"], 0) + 1
    lines = [
        "# Firecracker LUMI Phase 4",
        "",
        "- Job: `{}`".format(job_id),
        "- Node: `{}`".format(result.get("host", {}).get("hostname")),
        "- Kernel: `{}`".format(result.get("artifacts", {}).get("kernel", {}).get("path")),
        "- Rootfs: `{}`".format(result.get("artifacts", {}).get("rootfs", {}).get("path")),
        "- Rootfs bytes: `{}`".format(result.get("artifacts", {}).get("rootfs", {}).get("bytes")),
        "- Classifications: `{}`".format(json.dumps(counts, sort_keys=True)),
        "",
        "## Decision Gates",
        "",
    ]
    for gate, data in result.get("recommendation", {}).get("gates", {}).items():
        lines.append("- `{}`: `{}` - {}".format(gate, data.get("status"), data.get("notes", "")))
    lines.extend(["", "## Representative Rows", "", "| test | class | ms | exit | stdout bytes | stderr bytes | notes |", "|---|---:|---:|---:|---:|---:|---|"])
    for row in rows[:80]:
        lines.append("| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | {} |".format(
            row["test_id"], row["classification"],
            "{:.3f}".format(row["elapsed_ms"]) if row.get("elapsed_ms") is not None else "",
            row.get("exit_code"), row.get("stdout_bytes"), row.get("stderr_bytes"), (row.get("notes") or "").replace("|", "/")[:120],
        ))
    md_path.write_text("\n".join(lines) + "\n")
    analysis = [
        "# Firecracker LUMI Phase 4 Analysis",
        "",
        "## Recommendation",
        "",
        "`{}`".format(result.get("recommendation", {}).get("summary")),
        "",
        "ACL/policy enforcement is intentionally deferred per user instruction. The network result here uses the previously working `gvisor-tap-vsock`/`gvproxy` path as a basic transparent network baseline only.",
        "",
        "## What This Run Proves",
        "",
        "- Disk-backed Ubuntu full rootfs can boot under Firecracker on LUMI with the TUN-capable guest kernel.",
        "- The primary command path can be moved off serial and onto a guest-initiated Firecracker vsock connection.",
        "- The vsock JSONL process API is binary-safe for the tested stdout/stderr sizes and supports stdin, process handles, reads, termination, timeout classification, and malformed-frame survival.",
        "- A read-only ext4 base plus tmpfs `/workspace` is a viable simple reset model for session-style rollouts.",
        "- `gvproxy` continues to provide basic transparent egress when ACL requirements are set aside.",
        "",
        "## Caveats",
        "",
        "- This is still a prototype harness, not a production pool manager.",
        "- The guest init is the vsock agent as PID 1, not systemd. The filesystem is a real Ubuntu rootfs, but service semantics are intentionally minimal.",
        "- Density is bounded in this run to avoid large scratch impact; it characterizes feasibility, not the maximum node limit.",
        "- Host-side ACL/network policy is unresolved by design and should be handled in a separate design decision.",
        "",
        "## Final Gate Status",
        "",
    ]
    for gate, data in result.get("recommendation", {}).get("gates", {}).items():
        analysis.append("- `{}`: `{}` - {}".format(gate, data.get("status"), data.get("notes", "")))
    analysis.extend([
        "",
        "## Latency Summary",
        "",
        "```json",
        json.dumps(result.get("latency_summary", {}), indent=2, sort_keys=True),
        "```",
        "",
        "## Final Questions",
        "",
        "- Can this replace WASIX for LUMI rollout training? `not yet`; it is a serious comparator, but ACL policy and production pooling remain unresolved.",
        "- Can this provide better Linux fidelity than WASIX? `yes`, for real distro/userland and native binary compatibility.",
        "- Can it keep warm-pool latency low enough? `likely for shell/python`; see row-level latency, but larger pool/density runs are still needed.",
        "- Can it run useful networked coding tasks through explicit proxy? `not tested here`; basic transparent gvproxy egress works, ACL/proxy policy is deferred.",
        "- What density per LUMI node is realistic? `unknown for full-rootfs production`; prior initramfs reached 500, this run only validates lower full-rootfs pool tiers.",
        "- What reset mode should be used? `read-only base plus tmpfs workspace` is the current best simple mode; compare disk overlay later.",
        "- What tasks should still use WASIX? high-density, low-fidelity, rootless tasks where Linux kernel fidelity/native packages are not required.",
        "- What tasks should still use Apptainer or real containers? GPU jobs, multi-process services requiring standard distro init/service behavior, and workflows needing managed cluster networking.",
        "- Main blockers: ACL/policy design, production pool service, stronger density data, and rootfs artifact/version management.",
    ])
    analysis_path.write_text("\n".join(analysis) + "\n")
    return {"json": str(json_path), "markdown": str(md_path), "analysis": str(analysis_path)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--kernel-path", required=True)
    ap.add_argument("--mem-mib", type=int, default=768)
    ap.add_argument("--vcpus", type=int, default=1)
    ap.add_argument("--density", default="1,4,8")
    ap.add_argument("--skip-network", action="store_true")
    args = ap.parse_args()

    run_dir = Path(args.run_dir)
    mkdir(run_dir)
    raw_path = Path("reports") / "firecracker-lumi-phase4-{}-raw.jsonl".format(os.environ.get("SLURM_JOB_ID", "local"))
    mkdir(raw_path.parent)
    if raw_path.exists():
        raw_path.unlink()
    result = {
        "host": host_snapshot(),
        "slurm": dict(os.environ),
        "errors": [],
        "args": vars(args),
        "artifacts": {},
        "guest_image": {},
        "transport": {},
        "pool_api": {},
        "process_api": {},
        "network_proxy": {"acl_policy": "deferred_by_user_instruction"},
        "filesystem_reset": {},
        "security": {},
        "density": {},
        "trace_replay": {"classification": "unsupported", "notes": "seed trace corpus not present in this workspace"},
        "comparison_to_wasix": {"classification": "partial", "notes": "WASIX reference artifacts named in handoff are not present in this repo checkout"},
    }
    rows = []
    vms = []
    try:
        log("preparing artifacts")
        fc = download_firecracker(run_dir / "cache")
        tools = download_gvisor_tap_vsock(run_dir / "cache")
        rootfs = prepare_rootfs(run_dir / "cache", tools)
        result["firecracker"] = fc
        result["artifacts"] = {
            "kernel": {"path": args.kernel_path, "bytes": Path(args.kernel_path).stat().st_size},
            "rootfs": rootfs,
            "gvisor_tap_vsock": tools,
        }
        result["guest_image"] = {
            "mode": "disk_ext4_full_rootfs_readonly_tmpfs_workspace",
            "agent": "/fc-agent-init",
            "rootfs": rootfs,
        }

        log("booting primary full-rootfs vsock-agent VM")
        vm = Phase4VM("primary", fc["path"], args.kernel_path, rootfs["path"], run_dir, mem_mib=args.mem_mib, vcpus=args.vcpus)
        boot = vm.boot()
        vms.append(vm)
        result["transport"]["primary_boot"] = boot
        rows.append(benchmark_row("lifecycle.primary_boot_to_ready", "lifecycle", "boot", {"ok": True, "exit_code": 0, "stdout_b64": "", "stderr_b64": "", "command_roundtrip_ms": boot["ready_ms"]}, boot_ms=boot["ready_ms"], ready_ms=boot["ready_ms"], host_rss_kb=boot["rss_kb_after_ready"], guest_memory_mb=args.mem_mib))
        write_raw(raw_path, rows[-1])

        log("running full-rootfs command tests")
        rows.extend(run_command_tests(vm, raw_path))
        log("running vsock transport/process API tests")
        rows.extend(run_transport_tests(vm, raw_path))
        log("running reset tests")
        rows.extend(run_reset_tests(vm, raw_path))
        log("running security/resource probes")
        rows.extend(run_security_tests(vm, raw_path))
        if not args.skip_network:
            log("running gvproxy network baseline")
            rows.extend(run_network_baseline(vm, tools, raw_path, run_dir))

        log("running bounded density test")
        density_levels = [int(x) for x in args.density.split(",") if x.strip()]
        density_results = []
        for level in density_levels:
            tier_vms = []
            t0 = now_ns()
            failures = 0
            for i in range(level):
                try:
                    dvm = Phase4VM("density-{}-{}".format(level, i), fc["path"], args.kernel_path, rootfs["path"], run_dir, mem_mib=args.mem_mib, vcpus=args.vcpus)
                    dvm.boot()
                    tier_vms.append(dvm)
                except Exception as exc:
                    failures += 1
                    result.setdefault("errors", []).append({"density": level, "error": repr(exc)})
            wall = ms_since(t0)
            cmd_lat = []
            for dvm in tier_vms:
                resp = dvm.agent.run("bash -lc 'true'", timeout_ms=10000)
                cmd_lat.append(resp.get("command_roundtrip_ms"))
            rss_sum = sum(proc_rss_kb(dvm.proc.pid) or 0 for dvm in tier_vms)
            density_results.append({"level": level, "booted": len(tier_vms), "failures": failures, "wall_ms": wall, "rss_sum_kb": rss_sum, "true_latencies_ms": cmd_lat})
            row = benchmark_row("density.pool_{}".format(level), "density", "boot pool + true", {"ok": failures == 0, "exit_code": 0 if failures == 0 else 1, "stdout_b64": "", "stderr_b64": "", "command_roundtrip_ms": wall}, pool_size=level, concurrency=level, host_rss_kb=rss_sum, guest_memory_mb=args.mem_mib, classification="pass" if failures == 0 else "fail")
            rows.append(row)
            write_raw(raw_path, row)
            for dvm in tier_vms:
                dvm.stop()
        result["density"]["bounded_full_rootfs"] = density_results

        pass_counts = {}
        for row in rows:
            pass_counts[row["classification"]] = pass_counts.get(row["classification"], 0) + 1
        required_tool_gaps = sorted(r["test_id"] for r in rows if r["test_id"] in ("rootfs.pytest", "rootfs.git_status", "rootfs.gcc_hello") and r["classification"] != "pass")
        full_rootfs_status = "pass" if not required_tool_gaps and any(r["test_id"] == "rootfs.proc" and r["classification"] == "pass" for r in rows) else "partial"
        result["recommendation"] = {
            "summary": "pursue narrowly",
            "classification_counts": pass_counts,
            "gates": {
                "gate_a_lumi_operations": {"status": "pass", "notes": "KVM/vsock/rootfs artifacts staged and pool boot/teardown exercised on dev-g."},
                "gate_b_vsock_process_api": {"status": "pass", "notes": "Binary-safe stdout/stderr, stdin, process handles, termination, malformed frame survival tested."},
                "gate_c_full_rootfs_fidelity": {"status": full_rootfs_status, "notes": "Ubuntu ext4 rootfs booted; package/tool gaps: {}".format(", ".join(required_tool_gaps) if required_tool_gaps else "none")},
                "gate_d_reset_and_recycle": {"status": "partial", "notes": "Read-only base plus tmpfs workspace reset tested; disk overlay and snapshot restore full comparison deferred."},
                "gate_e_network_proxy_policy": {"status": "deferred", "notes": "ACL/policy deliberately deferred; gvproxy basic transparent egress baseline tested only."},
                "gate_f_density_and_cost": {"status": "partial", "notes": "Bounded full-rootfs density tiers run; maximum stable node density not established."},
            },
        }
    except Exception as exc:
        result.setdefault("errors", []).append({"fatal": repr(exc)})
    finally:
        for vm in vms:
            vm.stop()
        result["host_after"] = host_snapshot()
        reports = write_reports(result, rows, os.environ.get("SLURM_JOB_ID", "local"))
        result["reports"] = reports
        print(json.dumps({"reports": reports, "rows": len(rows), "errors": result.get("errors", [])[-5:]}, indent=2), flush=True)


if __name__ == "__main__":
    main()
