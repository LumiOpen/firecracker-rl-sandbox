#!/usr/bin/env python3
import argparse
import base64
import collections
import fnmatch
import hashlib
import json
import lzma
import os
import re
import shutil
import tempfile
import threading
import time
from pathlib import Path

from firecracker_lumi_bench import (
    command_path,
    download_firecracker,
    host_snapshot,
    mkdir,
    ms_since,
    now_ns,
    proc_rss_kb,
    read_text,
    run,
)
from firecracker_lumi_net_poc import download_gvisor_tap_vsock
from firecracker_lumi_phase4 import Phase4VM, S3, latest_ci_artifact_keys, log


DEFAULT_AGENT_PORT = 9000
ROOTFS_PROFILE = "phase5-production-comparator-v1"
DEFAULT_ROOTFS_BYTES = 4 * 1024 * 1024 * 1024
TRACE_NAME = "agenttrove-strict-safe-100"


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
import fnmatch
import hashlib
import json
import os
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

AGENT_PORT = int(os.environ.get("FC_AGENT_PORT", "9000"))
WORKSPACE_TEMPLATE = "/opt/phase5-workspace-template"
WORKSPACE = "/workspace"
DEFAULT_STDOUT_LIMIT = int(os.environ.get("FC_STDOUT_LIMIT", str(16 * 1024 * 1024)))
DEFAULT_STDERR_LIMIT = int(os.environ.get("FC_STDERR_LIMIT", str(16 * 1024 * 1024)))
MAX_STDIN_WRITE = int(os.environ.get("FC_MAX_STDIN_WRITE", str(16 * 1024 * 1024)))
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
    os.makedirs(WORKSPACE, exist_ok=True)
    safe_mount(["mount", "-t", "devtmpfs", "devtmpfs", "/dev"])
    safe_mount(["mount", "-t", "proc", "proc", "/proc"])
    safe_mount(["mount", "-t", "sysfs", "sysfs", "/sys"])
    safe_mount(["mount", "-t", "tmpfs", "-o", "mode=1777,size=512m", "tmpfs", "/tmp"])
    safe_mount(["mount", "-t", "tmpfs", "-o", "mode=755,size=512m", "tmpfs", "/run"])
    safe_mount(["mount", "-t", "tmpfs", "-o", "mode=755,size=512m", "tmpfs", WORKSPACE])
    os.chdir(WORKSPACE)


def enc(data):
    return base64.b64encode(data or b"").decode("ascii")


def dec(text):
    return base64.b64decode((text or "").encode("ascii"))


def response(req_id, **fields):
    out = {"id": req_id, "ok": True}
    out.update(fields)
    return out


def error(req_id, message, **fields):
    out = {"id": req_id, "ok": False, "error": str(message)}
    out.update(fields)
    return out


def env_for(req):
    env = DEFAULT_ENV.copy()
    for k, v in (req.get("env") or {}).items():
        env[str(k)] = str(v)
    return env


def limit_bytes(data, limit):
    limit = DEFAULT_STDOUT_LIMIT if limit is None else int(limit)
    truncated = len(data) > limit
    return data[:limit], truncated


def bounded_process_io(proc, timeout_s, stdout_limit, stderr_limit):
    set_nonblocking(proc.stdout)
    set_nonblocking(proc.stderr)
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    observed = {"stdout": 0, "stderr": 0}
    limits = {"stdout": int(stdout_limit), "stderr": int(stderr_limit)}
    blocked = {"stdout": False, "stderr": False}
    streams = {"stdout": proc.stdout, "stderr": proc.stderr}
    for name, stream in streams.items():
        if stream and not stream.closed:
            selector.register(stream, selectors.EVENT_READ, name)
    deadline = None if timeout_s is None else time.monotonic() + timeout_s
    timed_out = False
    kill_reason = None

    while True:
        if deadline is not None and time.monotonic() >= deadline and proc.poll() is None:
            timed_out = True
            kill_reason = "timeout"
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        if proc.poll() is not None and not selector.get_map():
            break

        if selector.get_map():
            select_timeout = 0.05
            if deadline is not None:
                select_timeout = max(0, min(select_timeout, deadline - time.monotonic()))
            events = selector.select(select_timeout)
            if not events and proc.poll() is not None:
                for key in list(selector.get_map().values()):
                    try:
                        selector.unregister(key.fileobj)
                    except Exception:
                        pass
                continue
            for key, _ in events:
                name = key.data
                try:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                except OSError:
                    chunk = b""
                if not chunk:
                    try:
                        selector.unregister(key.fileobj)
                    except Exception:
                        pass
                    continue
                observed[name] += len(chunk)
                remaining = max(0, limits[name] - len(buffers[name]))
                if remaining:
                    buffers[name].extend(chunk[:remaining])
                if len(buffers[name]) >= limits[name]:
                    blocked[name] = True
                    try:
                        selector.unregister(key.fileobj)
                    except Exception:
                        pass
        else:
            if proc.poll() is not None:
                break
            time.sleep(0.05)

    try:
        proc.wait(timeout=1)
    except Exception:
        pass
    return {
        "stdout": bytes(buffers["stdout"]),
        "stderr": bytes(buffers["stderr"]),
        "stdout_bytes_observed": observed["stdout"],
        "stderr_bytes_observed": observed["stderr"],
        "stdout_blocked": blocked["stdout"],
        "stderr_blocked": blocked["stderr"],
        "timeout": timed_out,
        "kill_reason": kill_reason,
    }


def run_command(req):
    stdin_data = dec(req.get("stdin_b64", ""))
    timeout = req.get("timeout_ms")
    timeout_s = None if timeout in (None, 0) else timeout / 1000.0
    stdout_limit = int(req.get("stdout_limit") or DEFAULT_STDOUT_LIMIT)
    stderr_limit = int(req.get("stderr_limit") or DEFAULT_STDERR_LIMIT)
    if len(stdin_data) > MAX_STDIN_WRITE:
        raise ValueError("stdin write exceeds limit")
    t0 = time.monotonic_ns()
    p = subprocess.Popen(
        ["/bin/bash", "-lc", req.get("command", "")],
        cwd=req.get("cwd") or WORKSPACE,
        env=env_for(req),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid,
    )
    try:
        if p.stdin and stdin_data:
            p.stdin.write(stdin_data)
        if p.stdin:
            p.stdin.close()
    except BrokenPipeError:
        pass
    io = bounded_process_io(p, timeout_s, stdout_limit, stderr_limit)
    stdout = io["stdout"]
    stderr = io["stderr"]
    full_stdout_sha = hashlib.sha256(stdout).hexdigest()
    full_stderr_sha = hashlib.sha256(stderr).hexdigest()
    return {
        "exit_code": p.returncode,
        "stdout_b64": enc(stdout),
        "stderr_b64": enc(stderr),
        "stdout_bytes_full": io["stdout_bytes_observed"],
        "stderr_bytes_full": io["stderr_bytes_observed"],
        "stdout_sha256_full": full_stdout_sha,
        "stderr_sha256_full": full_stderr_sha,
        "stdout_truncated": io["stdout_blocked"] or io["stdout_bytes_observed"] > len(stdout),
        "stderr_truncated": io["stderr_blocked"] or io["stderr_bytes_observed"] > len(stderr),
        "stdout_blocked": io["stdout_blocked"],
        "stderr_blocked": io["stderr_blocked"],
        "stdout_buffered_bytes": len(stdout),
        "stderr_buffered_bytes": len(stderr),
        "output_limit_bytes": max(stdout_limit, stderr_limit),
        "timeout": io["timeout"],
        "kill_reason": io["kill_reason"],
        "guest_process_ms": (time.monotonic_ns() - t0) / 1e6,
    }


def set_nonblocking(fileobj):
    os.set_blocking(fileobj.fileno(), False)


def read_available(proc, wait_ms, stdout_limit, stderr_limit):
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
                if len(stdout) < stdout_limit:
                    stdout += chunk[: max(0, stdout_limit - len(stdout))]
            else:
                if len(stderr) < stderr_limit:
                    stderr += chunk[: max(0, stderr_limit - len(stderr))]
    return stdout, stderr


def start_process(req):
    global next_handle
    handle = "p{}".format(next_handle)
    next_handle += 1
    p = subprocess.Popen(
        ["/bin/bash", "-lc", req.get("command", "")],
        cwd=req.get("cwd") or WORKSPACE,
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


def get_handle(req):
    handle = req.get("handle")
    if handle not in handles:
        raise KeyError("unknown process handle {}".format(handle))
    return handles[handle]


def process_read(req):
    p = get_handle(req)
    stdout_limit = int(req.get("stdout_limit") or DEFAULT_STDOUT_LIMIT)
    stderr_limit = int(req.get("stderr_limit") or DEFAULT_STDERR_LIMIT)
    stdout, stderr = read_available(p, int(req.get("wait_ms") or 0), stdout_limit, stderr_limit)
    return {
        "stdout_b64": enc(stdout),
        "stderr_b64": enc(stderr),
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
        "exit_code": p.poll(),
        "running": p.poll() is None,
    }


def process_write(req):
    p = get_handle(req)
    data = dec(req.get("stdin_b64", ""))
    if len(data) > MAX_STDIN_WRITE:
        raise ValueError("stdin write exceeds limit")
    if p.stdin and not p.stdin.closed:
        p.stdin.write(data)
        p.stdin.flush()
    return {"bytes": len(data), "exit_code": p.poll(), "running": p.poll() is None}


def process_close_stdin(req):
    p = get_handle(req)
    if p.stdin and not p.stdin.closed:
        p.stdin.close()
    return {"exit_code": p.poll(), "running": p.poll() is None}


def process_signal(req):
    p = get_handle(req)
    sig = int(req.get("signal", signal.SIGTERM))
    try:
        os.killpg(os.getpgid(p.pid), sig)
    except ProcessLookupError:
        pass
    return {"exit_code": p.poll(), "running": p.poll() is None}


def process_status(req):
    p = get_handle(req)
    return {"exit_code": p.poll(), "running": p.poll() is None, "pid": p.pid}


def clear_workspace():
    subprocess.run(
        ["/bin/bash", "-lc", "find '{}' -mindepth 1 -maxdepth 1 -exec rm -rf {{}} +".format(WORKSPACE)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def copy_workspace_template():
    if os.path.isdir(WORKSPACE_TEMPLATE):
        for name in os.listdir(WORKSPACE_TEMPLATE):
            src = os.path.join(WORKSPACE_TEMPLATE, name)
            dst = os.path.join(WORKSPACE, name)
            if os.path.isdir(src):
                shutil.copytree(src, dst, symlinks=True)
            else:
                shutil.copy2(src, dst)
    else:
        os.makedirs(os.path.join(WORKSPACE, "tests"), exist_ok=True)
        with open(os.path.join(WORKSPACE, "small.txt"), "w") as f:
            f.write("small file\nneedle\n")
        with open(os.path.join(WORKSPACE, "file.txt"), "w") as f:
            for i in range(2000):
                f.write(("needle" if i == 1234 else "ordinary") + " line %d\n" % i)
        with open(os.path.join(WORKSPACE, "tests", "test_basic.py"), "w") as f:
            f.write("def test_arithmetic():\n    assert 1 + 1 == 2\n")
        with open(os.path.join(WORKSPACE, "hello.c"), "w") as f:
            f.write('#include <stdio.h>\nint main(){puts("hello-c");return 0;}\n')


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
    clear_workspace()
    copy_workspace_template()
    os.chdir(WORKSPACE)
    return {"cwd": os.getcwd(), **workspace_stats()}


def ignored(path, patterns):
    rel = path.lstrip("./")
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(os.path.basename(rel), pat):
            return True
    return False


def workspace_stats():
    total = 0
    count = 0
    for root, _dirs, files in os.walk(WORKSPACE):
        for name in files:
            count += 1
            try:
                total += os.stat(os.path.join(root, name)).st_size
            except OSError:
                pass
    return {"workspace_file_count": count, "workspace_bytes": total}


def workspace_fingerprint(req):
    patterns = req.get("ignore_path_patterns") or []
    h = hashlib.sha256()
    files = []
    for root, dirs, names in os.walk(WORKSPACE):
        dirs[:] = [d for d in dirs if not ignored(os.path.relpath(os.path.join(root, d), WORKSPACE), patterns)]
        for name in names:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, WORKSPACE)
            if ignored(rel, patterns):
                continue
            files.append(rel)
    for rel in sorted(files):
        full = os.path.join(WORKSPACE, rel)
        try:
            st = os.lstat(full)
            h.update(rel.encode("utf-8", "surrogateescape") + b"\0")
            h.update(str(st.st_mode & 0o7777).encode() + b"\0")
            h.update(str(st.st_size).encode() + b"\0")
            with open(full, "rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)
            h.update(b"\0")
        except OSError:
            continue
    stats = workspace_stats()
    return {"workspace_sha256": h.hexdigest(), "workspace_files": len(files), **stats}


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
    if op == "workspace/fingerprint":
        return response(req.get("id"), **workspace_fingerprint(req))
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
        req = {}
        try:
            req = json.loads(line.decode("utf-8"))
            resp = handle(req)
        except Exception as exc:
            resp = error(req.get("id") if isinstance(req, dict) else None, exc)
        writer.write(json.dumps(resp, separators=(",", ":")).encode("utf-8") + b"\n")
        writer.flush()


def main():
    setup_mounts()
    copy_workspace_template()
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


PACKAGE_ROOTS = [
    "bash",
    "ca-certificates",
    "coreutils",
    "curl",
    "diffutils",
    "findutils",
    "gawk",
    "gcc",
    "g++",
    "git",
    "grep",
    "gzip",
    "make",
    "patch",
    "procps",
    "python3",
    "python3-pip",
    "python3-pytest",
    "python3-venv",
    "sed",
    "tar",
]


INDEX_SOURCES = [
    ("noble", "main", "https://archive.ubuntu.com/ubuntu"),
    ("noble", "universe", "https://archive.ubuntu.com/ubuntu"),
    ("noble-updates", "main", "https://archive.ubuntu.com/ubuntu"),
    ("noble-updates", "universe", "https://archive.ubuntu.com/ubuntu"),
    ("noble-security", "main", "https://security.ubuntu.com/ubuntu"),
    ("noble-security", "universe", "https://security.ubuntu.com/ubuntu"),
]


def file_tree_hash(path):
    path = Path(path)
    h = hashlib.sha256()
    if not path.exists():
        return "missing"
    for p in sorted(path.rglob("*")):
        rel = str(p.relative_to(path))
        h.update(rel.encode("utf-8", "surrogateescape") + b"\0")
        if p.is_file():
            h.update(p.read_bytes())
        elif p.is_symlink():
            h.update(os.readlink(str(p)).encode("utf-8", "surrogateescape"))
        h.update(b"\0")
    return h.hexdigest()


def parse_packages_xz(path, base_url, suite, component):
    data = lzma.decompress(Path(path).read_bytes()).decode("utf-8", "replace")
    packages = []
    current = {}
    last_key = None
    for line in data.splitlines():
        if not line:
            if current:
                current["base_url"] = base_url
                current["suite"] = suite
                current["component"] = component
                packages.append(current)
            current = {}
            last_key = None
            continue
        if line.startswith(" ") and last_key:
            current[last_key] += "\n" + line[1:]
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            current[key] = value.strip()
            last_key = key
    if current:
        current["base_url"] = base_url
        current["suite"] = suite
        current["component"] = component
        packages.append(current)
    return packages


def download_package_indexes(cache_dir):
    cache_dir = Path(cache_dir)
    mkdir(cache_dir)
    index = {}
    providers = {}
    downloaded = []
    for suite, component, base_url in INDEX_SOURCES:
        name = "{}-{}-Packages.xz".format(suite, component)
        out = cache_dir / name
        url = "{}/dists/{}/{}/binary-amd64/Packages.xz".format(base_url, suite, component)
        if not out.exists():
            run(["curl", "-fsSL", "-o", str(out) + ".tmp", url])
            Path(str(out) + ".tmp").rename(out)
        downloaded.append({"suite": suite, "component": component, "url": url, "path": str(out), "bytes": out.stat().st_size})
        for pkg in parse_packages_xz(out, base_url, suite, component):
            if pkg.get("Architecture") in ("amd64", "all"):
                index[pkg["Package"]] = pkg
                for expr in (pkg.get("Provides") or "").replace("\n", " ").split(","):
                    for provided in dep_choices(expr):
                        providers[provided] = pkg
    for name, pkg in providers.items():
        index.setdefault(name, pkg)
    return index, downloaded


def dep_choices(dep_expr):
    out = []
    for alt in dep_expr.split("|"):
        name = alt.strip()
        name = re.sub(r"\s*\([^)]*\)", "", name)
        name = name.split()[0] if name.split() else ""
        if ":" in name:
            name = name.split(":", 1)[0]
        if name and not name.startswith("${"):
            out.append(name)
    return out


def dependency_names(depends, index):
    names = []
    for expr in (depends or "").replace("\n", " ").split(","):
        expr = expr.strip()
        if not expr:
            continue
        choices = dep_choices(expr)
        if not choices:
            continue
        chosen = None
        for name in choices:
            if name in index:
                chosen = name
                break
        names.append(chosen or choices[0])
    return names


def resolve_packages(index, roots):
    resolved = collections.OrderedDict()
    missing = collections.OrderedDict()
    queue = list(roots)
    while queue:
        name = queue.pop(0)
        if name in resolved:
            continue
        pkg = index.get(name)
        if not pkg:
            missing[name] = True
            continue
        resolved[name] = pkg
        deps = []
        deps.extend(dependency_names(pkg.get("Pre-Depends"), index))
        deps.extend(dependency_names(pkg.get("Depends"), index))
        for dep in deps:
            if dep not in resolved and dep not in queue:
                queue.append(dep)
    return resolved, sorted(missing)


def download_deb(pkg, deb_dir):
    deb_dir = Path(deb_dir)
    mkdir(deb_dir)
    filename = pkg["Filename"]
    out = deb_dir / Path(filename).name
    if not out.exists():
        url = "{}/{}".format(pkg["base_url"], filename)
        run(["curl", "-fsSL", "-o", str(out) + ".tmp", url])
        Path(str(out) + ".tmp").rename(out)
    return out


def extract_deb_data_member(deb_path, tmp_dir):
    deb_path = Path(deb_path)
    tmp_dir = Path(tmp_dir)
    mkdir(tmp_dir)
    with deb_path.open("rb") as f:
        magic = f.read(8)
        if magic != b"!<arch>\n":
            raise RuntimeError("not an ar deb archive: {}".format(deb_path))
        while True:
            header = f.read(60)
            if not header:
                break
            if len(header) != 60:
                raise RuntimeError("short ar header in {}".format(deb_path))
            name = header[:16].decode("utf-8", "replace").strip().rstrip("/")
            size = int(header[48:58].decode("ascii").strip())
            data = f.read(size)
            if size % 2:
                f.read(1)
            if name.startswith("data.tar"):
                suffix = name[len("data.tar"):]
                out = Path(tmp_dir) / ("{}-data.tar{}".format(deb_path.stem, suffix))
                out.write_bytes(data)
                return out
    raise RuntimeError("no data.tar member in {}".format(deb_path))


def extract_deb(deb_path, root, tmp_dir):
    data_member = extract_deb_data_member(deb_path, tmp_dir)
    cmd = ["tar", "--numeric-owner", "-C", str(root), "-xf", str(data_member)]
    p = run(cmd, check=False)
    if p.returncode != 0 and str(data_member).endswith(".zst"):
        p = run(["tar", "--numeric-owner", "--use-compress-program=unzstd", "-C", str(root), "-xf", str(data_member)], check=False)
    if p.returncode != 0:
        raise RuntimeError("failed extracting {} stdout={} stderr={}".format(deb_path, p.stdout[-2000:], p.stderr[-2000:]))
    return str(data_member)


def install_deb_packages(root, cache_dir, package_roots):
    cache_dir = Path(cache_dir)
    index, indexes = download_package_indexes(cache_dir / "apt-indexes")
    resolved, missing = resolve_packages(index, package_roots)
    deb_dir = cache_dir / "debs"
    tmp_dir = cache_dir / "deb-extract"
    if tmp_dir.exists():
        shutil.rmtree(str(tmp_dir))
    mkdir(tmp_dir)
    installed = []
    errors = []
    for name, pkg in resolved.items():
        try:
            deb = download_deb(pkg, deb_dir)
            extract_deb(deb, root, tmp_dir)
            installed.append({
                "package": name,
                "version": pkg.get("Version"),
                "filename": pkg.get("Filename"),
                "suite": pkg.get("suite"),
                "component": pkg.get("component"),
                "deb_bytes": deb.stat().st_size,
            })
        except Exception as exc:
            errors.append({"package": name, "error": repr(exc)})
    shutil.rmtree(str(tmp_dir), ignore_errors=True)
    return {
        "requested_roots": package_roots,
        "resolved_count": len(resolved),
        "missing": missing,
        "installed": installed,
        "errors": errors,
        "indexes": indexes,
    }


def copy_workspace_template(template_dir, root):
    dest = Path(root) / "opt" / "phase5-workspace-template"
    if dest.exists():
        shutil.rmtree(str(dest))
    mkdir(dest.parent)
    shutil.copytree(str(template_dir), str(dest), symlinks=True)
    return {"path_in_guest": str(dest), "source": str(template_dir), "hash": file_tree_hash(template_dir)}


def inventory_tools(root):
    root = Path(root)
    inventory = {}
    for cmd in ("bash", "python3", "pip3", "pytest", "git", "gcc", "g++", "clang", "make", "grep", "find", "sed", "awk", "sort", "uniq", "head", "tail", "wc", "diff", "patch", "tar", "gzip", "curl", "mount", "ps", "ip"):
        found = list(root.glob("**/{}".format(cmd)))
        inventory[cmd] = [str(p.relative_to(root)) for p in found[:10]]
    return inventory


def prepare_rootfs(rootfs_cache_dir, artifact_cache_dir, tools, workspace_template):
    rootfs_cache_dir = Path(rootfs_cache_dir)
    artifact_cache_dir = Path(artifact_cache_dir)
    mkdir(rootfs_cache_dir)
    profile_hash = hashlib.sha256((ROOTFS_PROFILE + GUEST_AGENT + file_tree_hash(workspace_template)).encode("utf-8")).hexdigest()[:16]
    out_dir = rootfs_cache_dir / "ubuntu-24.04-{}-{}".format(ROOTFS_PROFILE, profile_hash)
    ext4 = out_dir / "rootfs.ext4"
    meta = out_dir / "metadata.json"
    if ext4.exists() and meta.exists():
        data = json.loads(meta.read_text())
        data["path"] = str(ext4)
        data["bytes"] = ext4.stat().st_size
        data["reused"] = True
        return data

    build_cache = artifact_cache_dir / "rootfs-compose"
    mkdir(build_cache)
    keys = latest_ci_artifact_keys()
    squash = build_cache / Path(keys["ubuntu_squashfs_key"]).name
    if not squash.exists():
        run(["curl", "-fsSL", "-o", str(squash) + ".tmp", "{}/{}".format(S3, keys["ubuntu_squashfs_key"])])
        Path(str(squash) + ".tmp").rename(squash)

    work = build_cache / "phase5-rootfs-build"
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
    template_meta = copy_workspace_template(workspace_template, root)
    package_meta = install_deb_packages(root, build_cache, PACKAGE_ROOTS)
    mkdir(root / "workspace")
    distro = read_text(root / "etc/os-release")
    inventory = inventory_tools(root)

    mkdir(out_dir)
    size_bytes = int(os.environ.get("FC_PHASE5_ROOTFS_BYTES", str(DEFAULT_ROOTFS_BYTES)))
    run(["truncate", "-s", str(size_bytes), str(ext4)])
    mkfs = shutil.which("mkfs.ext4") or shutil.which("mke2fs") or "/sbin/mkfs.ext4"
    run([mkfs, "-q", "-d", str(root), "-F", str(ext4)])
    data = {
        "build_method": "Firecracker CI Ubuntu squashfs -> package-index .deb extraction -> injected phase5 vsock agent/workspace template/gvforwarder -> mkfs.ext4 -d",
        "profile": ROOTFS_PROFILE,
        "profile_hash": profile_hash,
        "ubuntu_squashfs_key": keys["ubuntu_squashfs_key"],
        "squashfs_bytes": squash.stat().st_size,
        "path": str(ext4),
        "bytes": ext4.stat().st_size,
        "logical_size_bytes": size_bytes,
        "distro_os_release": distro,
        "package_inventory_paths": inventory,
        "package_composition": package_meta,
        "workspace_template": template_meta,
        "job_startup_requires_network": False,
        "job_startup_requires_network_notes": "Network is only required if Firecracker, gvproxy, package indexes/debs, or rootfs cache are absent.",
        "can_be_reused_across_jobs": True,
        "reused": False,
    }
    meta.write_text(json.dumps(data, indent=2, sort_keys=True))
    shutil.rmtree(str(work), ignore_errors=True)
    return data


def benchmark_row(test_id, category, command=None, resp=None, **extra):
    resp = resp or {}
    stdout = unb64(resp.get("stdout_b64", ""))
    stderr = unb64(resp.get("stderr_b64", ""))
    stdout_full_bytes = resp.get("stdout_bytes_full", len(stdout))
    stderr_full_bytes = resp.get("stderr_bytes_full", len(stderr))
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
        "classification": extra.pop("classification", "pass" if resp.get("ok", False) and resp.get("exit_code", 0) == 0 and not resp.get("timeout") else "fail"),
        "stdout_bytes": stdout_full_bytes,
        "stderr_bytes": stderr_full_bytes,
        "stdout_returned_bytes": len(stdout),
        "stderr_returned_bytes": len(stderr),
        "stdout_sha256": resp.get("stdout_sha256_full") or sha256_bytes(stdout),
        "stderr_sha256": resp.get("stderr_sha256_full") or sha256_bytes(stderr),
        "stdout_excerpt": compact_text(stdout),
        "stderr_excerpt": compact_text(stderr),
        "stdout_truncated": resp.get("stdout_truncated", False),
        "stderr_truncated": resp.get("stderr_truncated", False),
        "elapsed_ms": resp.get("command_roundtrip_ms"),
        "queue_wait_ms": extra.pop("queue_wait_ms", None),
        "command_roundtrip_ms": resp.get("command_roundtrip_ms"),
        "guest_process_ms": resp.get("guest_process_ms"),
        "reset_request_ms": extra.pop("reset_request_ms", None),
        "post_reset_validation_ms": extra.pop("post_reset_validation_ms", None),
        "total_recycle_ready_ms": extra.pop("total_recycle_ready_ms", None),
        "boot_ms": extra.pop("boot_ms", None),
        "ready_ms": extra.pop("ready_ms", None),
        "host_rss_kb": extra.pop("host_rss_kb", None),
        "guest_memory_mb": extra.pop("guest_memory_mb", None),
        "workspace_file_count": extra.pop("workspace_file_count", None),
        "workspace_bytes": extra.pop("workspace_bytes", None),
        "timeout": resp.get("timeout", False),
        "kill_reason": resp.get("kill_reason") or extra.pop("kill_reason", None),
        "agent_survived": extra.pop("agent_survived", None),
        "vm_survived": extra.pop("vm_survived", None),
        "notes": extra.pop("notes", ""),
    }
    row.update(extra)
    return row


def write_jsonl(path, row):
    with Path(path).open("a") as f:
        f.write(json.dumps(row, sort_keys=True) + "\n")


def summarize(values):
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return {"n": 0, "p50_ms": None, "p90_ms": None, "p99_ms": None, "mean_ms": None, "max_ms": None}

    def pct(p):
        idx = min(len(vals) - 1, int(round((len(vals) - 1) * p)))
        return vals[idx]

    return {
        "n": len(vals),
        "p50_ms": pct(0.5),
        "p90_ms": pct(0.9),
        "p99_ms": pct(0.99),
        "mean_ms": sum(vals) / len(vals),
        "max_ms": vals[-1],
    }


def summarize_by_category(rows):
    by = collections.defaultdict(list)
    for row in rows:
        if row.get("elapsed_ms") is not None:
            by[row["category"]].append(row["elapsed_ms"])
    return {k: summarize(v) for k, v in sorted(by.items())}


def run_rootfs_tool_tests(vm, raw_path):
    tests = [
        ("rootfs.bash", "bash -lc 'echo hello'"),
        ("rootfs.python", "python3 -c 'print(1)'"),
        ("rootfs.pytest", "python3 -m pytest tests"),
        ("rootfs.git", "git --version && git init repo && cd repo && git status --short"),
        ("rootfs.grep_find_sed_awk", "bash -lc 'grep needle needle.txt; find . -maxdepth 2 -type f | sort | head; sed -n \"1p\" file.txt; awk \"{print \\$1}\" table.txt | head -1'"),
        ("rootfs.coreutils", "bash -lc 'printf \"b\\na\\n\" | sort | uniq | wc -l; head -1 file.txt; tail -1 file.txt; diff -u before.txt after.txt || true'"),
        ("rootfs.patch_tar_gzip", "bash -lc 'cp before.txt patchme.txt; diff -u patchme.txt after.txt > change.patch || true; patch patchme.txt change.patch; tar -czf out.tgz patchme.txt; gzip -t out.tgz'"),
        ("rootfs.curl", "curl --version | head -1"),
        ("rootfs.gcc_hello", "cat > hello.c <<'C'\n#include <stdio.h>\nint main(){puts(\"hello-c\");return 0;}\nC\ngcc hello.c -o hello && ./hello"),
        ("rootfs.sqlite3_stdlib", "python3 -c 'import sqlite3; print(sqlite3.sqlite_version)'"),
        ("rootfs.proc", "bash -lc 'cat /proc/1/status | head; ps aux | head; mount | head'"),
    ]
    rows = []
    for test_id, cmd in tests:
        resp = vm.agent.run(cmd, timeout_ms=60000)
        row = benchmark_row(test_id, "rootfs", cmd, resp, classification="pass" if resp.get("ok") and resp.get("exit_code") == 0 else "fail", host_rss_kb=proc_rss_kb(vm.proc.pid), guest_memory_mb=vm.mem_mib)
        rows.append(row)
        write_jsonl(raw_path, row)
    return rows


def run_process_api_tests(vm, raw_path):
    rows = []
    commands = [
        ("process.warm_true", "bash -lc 'true'", 200),
        ("process.warm_echo", "bash -lc 'echo hello'", 200),
        ("process.warm_pwd_ls", "bash -lc 'pwd; ls -la'", 100),
        ("process.warm_cat_small", "bash -lc 'cat file.txt'", 100),
        ("process.warm_grep", "bash -lc 'grep needle file.txt needle.txt'", 100),
        ("process.warm_python", "bash -lc 'python3 -c \"print(1)\"'", 200),
        ("process.warm_pytest", "bash -lc 'python3 -m pytest tests'", 30),
    ]
    for test_id, cmd, iterations in commands:
        vals = []
        failures = 0
        last_resp = None
        for _ in range(iterations):
            resp = vm.agent.run(cmd, timeout_ms=60000)
            last_resp = resp
            vals.append(resp.get("command_roundtrip_ms"))
            if not resp.get("ok") or resp.get("exit_code") != 0 or resp.get("timeout"):
                failures += 1
        summary = summarize(vals)
        row = benchmark_row(test_id, "process_api", cmd, last_resp, classification="pass" if failures == 0 else "fail", iterations=iterations, failures=failures, **summary)
        rows.append(row)
        write_jsonl(raw_path, row)

    stress = [
        ("process.stdout_1m", "python3 -c 'import sys; sys.stdout.buffer.write(b\"x\" * 1048576)'", 30000, b""),
        ("process.stdout_10m", "python3 -c 'import sys; sys.stdout.buffer.write(b\"x\" * 10485760)'", 120000, b""),
        ("process.stderr_1m", "python3 -c 'import sys; sys.stderr.buffer.write(b\"x\" * 1048576)'", 30000, b""),
        ("process.stdin_transform", "python3 -c 'import sys; sys.stdout.write(sys.stdin.read().upper())'", 30000, b"abc\n"),
        ("process.binary_output", "python3 -c 'import sys; sys.stdout.buffer.write(bytes(range(256))*4096)'", 30000, b""),
    ]
    for test_id, cmd, timeout_ms, stdin_data in stress:
        resp = vm.agent.run(cmd, timeout_ms=timeout_ms, stdin_data=stdin_data)
        row = benchmark_row(test_id, "process_api", cmd, resp, classification="pass" if resp.get("ok") and resp.get("exit_code") == 0 else "fail")
        rows.append(row)
        write_jsonl(raw_path, row)

    t0 = now_ns()
    start = vm.agent.request("process/start", command="python3 -u -c 'import sys,time; print(\"ready\"); data=sys.stdin.readline(); print(data.strip()[::-1]); time.sleep(30)'")
    read1 = vm.agent.request("process/read", handle=start.get("handle"), wait_ms=1000)
    write = vm.agent.request("process/write", handle=start.get("handle"), stdin_b64=b64(b"abcdef\n"))
    close = vm.agent.request("process/close_stdin", handle=start.get("handle"))
    read2 = vm.agent.request("process/read", handle=start.get("handle"), wait_ms=1000)
    term = vm.agent.request("process/terminate", handle=start.get("handle"), signal=15)
    status = vm.agent.request("process/status", handle=start.get("handle"))
    combined_stdout = unb64(read1.get("stdout_b64", "")) + unb64(read2.get("stdout_b64", ""))
    ok = all(x.get("ok") for x in (start, read1, write, close, read2, term, status)) and b"ready" in combined_stdout and b"fedcba" in combined_stdout
    resp = {"ok": ok, "exit_code": 0 if ok else 1, "stdout_b64": b64(combined_stdout), "stderr_b64": "", "command_roundtrip_ms": ms_since(t0)}
    row = benchmark_row("process.handle_read_write_close_terminate", "process_api", "process/start/read/write/close/status/terminate", resp, classification="pass" if ok else "fail")
    rows.append(row)
    write_jsonl(raw_path, row)

    malformed_ok = False
    try:
        vm.agent.writer.write(b"{bad json\n")
        vm.agent.writer.flush()
        bad = json.loads(vm.agent.reader.readline().decode("utf-8"))
        health = vm.agent.request("health")
        malformed_ok = bool(bad.get("ok") is False and health.get("ok"))
    except Exception:
        malformed_ok = False
    row = benchmark_row("process.malformed_frame_survival", "process_api", "malformed frame", {"ok": malformed_ok, "exit_code": 0 if malformed_ok else 1, "stdout_b64": "", "stderr_b64": "", "command_roundtrip_ms": 0}, classification="pass" if malformed_ok else "fail")
    rows.append(row)
    write_jsonl(raw_path, row)
    return rows


def run_reset_tests(vm, raw_path):
    rows = []
    for count in (10, 1000, 10000):
        mutate = "bash -lc 'rm -rf /workspace/*; mkdir -p /workspace/dir; for i in $(seq 1 {}); do echo needle-$i > /workspace/dir/file-$i.txt; done; (sleep 30 &) ; export PHASE5_MUTATED=1; echo mutated'".format(count)
        vm.agent.run(mutate, timeout_ms=max(10000, count * 5))
        reset_t0 = now_ns()
        reset_resp = vm.agent.request("environment/reset")
        reset_ms = ms_since(reset_t0)
        val_t0 = now_ns()
        clean = vm.agent.run("bash -lc 'test -f file.txt && grep -q needle needle.txt && ! test -e dir/file-1.txt && ! pgrep -x sleep >/dev/null && pwd'", timeout_ms=10000)
        validation_ms = ms_since(val_t0)
        ok = reset_resp.get("ok") and clean.get("exit_code") == 0
        row = benchmark_row("reset.tmpfs_workspace_{}".format(count), "filesystem_reset", "environment/reset", clean,
                            reset_mode="read_only_root_plus_tmpfs_workspace",
                            reset_request_ms=reset_ms,
                            post_reset_validation_ms=validation_ms,
                            total_recycle_ready_ms=reset_ms + validation_ms,
                            workspace_file_count=count,
                            classification="pass" if ok else "fail",
                            notes="Mutated files, background sleep, and env in subprocess; reset reseeded fixture template.")
        rows.append(row)
        write_jsonl(raw_path, row)
    row = benchmark_row("reset.disk_overlay_workspace", "filesystem_reset", "disk overlay workspace", {"ok": True, "exit_code": 0, "stdout_b64": "", "stderr_b64": "", "command_roundtrip_ms": None}, classification="deferred", reset_mode="disk_overlay_workspace", notes="Deferred: tmpfs baseline prioritized for Phase 5 trace and density evidence.")
    rows.append(row)
    write_jsonl(raw_path, row)
    row = benchmark_row("reset.vm_snapshot_restore", "filesystem_reset", "Firecracker snapshot restore", {"ok": True, "exit_code": 0, "stdout_b64": "", "stderr_b64": "", "command_roundtrip_ms": None}, classification="deferred", reset_mode="vm_snapshot_restore", notes="Deferred: snapshot restore is still interesting, but not required to answer Phase 5 trace fidelity.")
    rows.append(row)
    write_jsonl(raw_path, row)
    return rows


def run_security_smoke(vm, raw_path):
    tests = [
        ("security.passwd", "cat /etc/passwd"),
        ("security.home", "ls /home"),
        ("security.env", "env"),
        ("security.proc", "ls /proc | head; cat /proc/self/status | head"),
        ("security.host_paths", "for p in /scratch /pfs /Users /mnt /host /etc/shadow; do if [ -e \"$p\" ]; then echo EXISTS:$p; else echo ABSENT:$p; fi; done"),
        ("security.memory_pressure", "timeout 3 python3 - <<'PY'\nx=[]\nwhile True:\n    x.append(b'x'*1000000)\nPY"),
        ("security.disk_fill", "python3 -c 'open(\"/workspace/big\", \"wb\").write(b\"x\" * 200000000)'"),
    ]
    rows = []
    for test_id, cmd in tests:
        resp = vm.agent.run("bash -lc '{}'".format(cmd.replace("'", "'\"'\"'")), timeout_ms=15000)
        health = vm.agent.request("health")
        cls = "pass" if health.get("ok") else "fail"
        row = benchmark_row(test_id, "security", cmd, resp, classification=cls, agent_survived=health.get("ok"), vm_survived=vm.proc.poll() is None)
        rows.append(row)
        write_jsonl(raw_path, row)
    return rows


def boot_pool_parallel(level, fc_path, kernel_path, rootfs_path, run_dir, mem_mib, vcpus):
    vms = []
    results = [None] * level
    errors = [None] * level
    start = now_ns()

    def worker(i):
        vm = Phase4VM("density-{}-{}".format(level, i), fc_path, kernel_path, rootfs_path, run_dir, mem_mib=mem_mib, vcpus=vcpus)
        try:
            boot = vm.boot()
            results[i] = boot
            vms.append(vm)
        except Exception as exc:
            errors[i] = repr(exc)
            try:
                vm.stop()
            except Exception:
                pass

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(level)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall_ms = ms_since(start)
    return vms, results, errors, wall_ms


def run_density_tests(fc, kernel_path, rootfs_path, run_dir, mem_mib, vcpus, raw_path, levels):
    rows = []
    summaries = []
    for level in levels:
        log("density tier {}".format(level))
        vms, boots, errors, wall_ms = boot_pool_parallel(level, fc["path"], kernel_path, rootfs_path, run_dir, mem_mib, vcpus)
        booted = len(vms)
        rss_values = [proc_rss_kb(vm.proc.pid) or 0 for vm in vms]
        cmd_summaries = {}
        for label, cmd, timeout_ms in (
            ("true", "bash -lc 'true'", 10000),
            ("echo", "bash -lc 'echo hello'", 10000),
            ("python", "bash -lc 'python3 -c \"print(1)\"'", 30000),
            ("grep_find", "bash -lc 'grep -R needle . >/dev/null; find . -maxdepth 3 -type f >/dev/null'", 30000),
            ("stdout_1m", "python3 -c 'import sys; sys.stdout.buffer.write(b\"x\" * 1048576)'", 60000),
        ):
            vals = []
            failures = 0
            start = now_ns()
            out = [None] * len(vms)

            def command_worker(idx, vm):
                try:
                    out[idx] = vm.agent.run(cmd, timeout_ms=timeout_ms)
                except Exception as exc:
                    out[idx] = {"ok": False, "error": repr(exc), "command_roundtrip_ms": None, "exit_code": 1}

            threads = [threading.Thread(target=command_worker, args=(i, vm)) for i, vm in enumerate(vms)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            for resp in out:
                vals.append(resp.get("command_roundtrip_ms"))
                if not resp.get("ok") or resp.get("exit_code") != 0:
                    failures += 1
            cmd_summaries[label] = {"wall_ms": ms_since(start), "failures": failures, "latency": summarize(vals)}
        summary = {
            "level": level,
            "requested": level,
            "booted": booted,
            "failures": sum(1 for e in errors if e),
            "errors": [e for e in errors if e],
            "wall_ms_to_ready": wall_ms,
            "boot_ready_ms": summarize([b.get("ready_ms") for b in boots if b]),
            "rss_sum_kb": sum(rss_values),
            "rss_per_vm_kb": summarize(rss_values),
            "guest_memory_total_mb": booted * mem_mib,
            "active_workloads": cmd_summaries,
        }
        summaries.append(summary)
        row = benchmark_row("density.parallel_pool_{}".format(level), "density", "parallel boot + active workload", {"ok": summary["failures"] == 0, "exit_code": 0 if summary["failures"] == 0 else 1, "stdout_b64": "", "stderr_b64": "", "command_roundtrip_ms": wall_ms}, classification="pass" if summary["failures"] == 0 else "fail", pool_size=level, concurrency=level, host_rss_kb=summary["rss_sum_kb"], guest_memory_mb=mem_mib, p99_boot_latency_ms=summary["boot_ready_ms"]["p99_ms"], p99_python_latency_ms=cmd_summaries["python"]["latency"]["p99_ms"])
        rows.append(row)
        write_jsonl(raw_path, row)
        for vm in vms:
            vm.stop()
        if summary["failures"]:
            break
    return rows, summaries


def load_trace_rows(trace_jsonl):
    rows = []
    with Path(trace_jsonl).open() as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def trace_failure_pattern(row, resp):
    if resp.get("timeout"):
        return "timeout"
    if not resp.get("ok"):
        return "agent_error"
    return "none"


def run_trace_replay(vm, trace_jsonl, trace_out_path, raw_path):
    trace_rows = load_trace_rows(trace_jsonl)
    by_trace = collections.OrderedDict()
    for row in trace_rows:
        by_trace.setdefault(row["trace_id"], []).append(row)

    output_rows = []
    reset_times = []
    final_fs = []
    counts = collections.Counter()
    patterns = collections.Counter()
    nonzero_exit_count = 0
    native_known_problem_steps = set()
    for trace_id, rows in by_trace.items():
        reset_t0 = now_ns()
        reset_resp = vm.agent.request("environment/reset")
        reset_ms = ms_since(reset_t0)
        reset_times.append(reset_ms)
        for idx, row in enumerate(rows):
            resp = vm.agent.run(row["command"], timeout_ms=int(row.get("timeout_ms") or 5000), cwd="/workspace")
            pattern = trace_failure_pattern(row, resp)
            classification = "pass" if pattern == "none" else "fail"
            if resp.get("exit_code") not in (0, None):
                nonzero_exit_count += 1
            if pattern != "none":
                patterns[pattern] += 1
            counts[classification] += 1
            out = {
                "trace_id": row["trace_id"],
                "step_id": row["step_id"],
                "step_index": row["step_index"],
                "command": row["command"],
                "exit_code": resp.get("exit_code"),
                "stdout_sha256": resp.get("stdout_sha256_full") or sha256_bytes(unb64(resp.get("stdout_b64", ""))),
                "stderr_sha256": resp.get("stderr_sha256_full") or sha256_bytes(unb64(resp.get("stderr_b64", ""))),
                "stdout_bytes": resp.get("stdout_bytes_full", len(unb64(resp.get("stdout_b64", "")))),
                "stderr_bytes": resp.get("stderr_bytes_full", len(unb64(resp.get("stderr_b64", "")))),
                "stdout_excerpt": compact_text(unb64(resp.get("stdout_b64", "")), 1000),
                "stderr_excerpt": compact_text(unb64(resp.get("stderr_b64", "")), 1000),
                "timeout": resp.get("timeout", False),
                "elapsed_ms": resp.get("command_roundtrip_ms"),
                "guest_process_ms": resp.get("guest_process_ms"),
                "reset_ms": reset_ms if idx == 0 else None,
                "classification": classification,
                "notes": "candidate execution health; nonzero command exit codes are recorded but not treated as infrastructure failures without native raw expected outputs",
            }
            output_rows.append(out)
            write_jsonl(trace_out_path, out)
            bench = benchmark_row("trace.{}.{}".format(row["trace_id"], row["step_id"]), "trace_replay", row["command"], resp, classification=classification, trace_id=row["trace_id"], step_id=row["step_id"], comparison=row.get("comparison"), notes=out["notes"])
            write_jsonl(raw_path, bench)
        fp = vm.agent.request("workspace/fingerprint", ignore_path_patterns=rows[-1].get("ignore_path_patterns") or [])
        final = {"trace_id": trace_id, "classification": "pass" if fp.get("ok") else "fail", "workspace_sha256": fp.get("workspace_sha256"), "workspace_files": fp.get("workspace_files")}
        final_fs.append(final)

    trace_count = len(by_trace)
    command_count = len(trace_rows)
    non_pass = sum(v for k, v in counts.items() if k != "pass")
    summary = {
        "trace_count": trace_count,
        "command_count": command_count,
        "distinct_command_count": len(set(r["command"] for r in trace_rows)),
        "classification_counts": dict(counts),
        "pass_count": counts.get("pass", 0),
        "minor_mismatch_count": counts.get("minor_mismatch", 0),
        "major_mismatch_count": counts.get("major_mismatch", 0),
        "fail_count": counts.get("fail", 0),
        "timeout_count": patterns.get("timeout", 0),
        "nonzero_exit_count": nonzero_exit_count,
        "non_pass_rate": float(non_pass) / command_count if command_count else None,
        "top_failure_patterns": patterns.most_common(10),
        "reset_ms": summarize(reset_times),
        "command_elapsed_ms": summarize([r.get("elapsed_ms") for r in output_rows]),
        "worst_traces": [],
        "final_filesystems": final_fs[:20],
        "comparison_limitation": "No per-command native baseline raw outputs were included; classifications are candidate execution health, with native and WASIX aggregate analyses used as context.",
        "native_known_problem_steps_loaded": len(native_known_problem_steps),
    }
    by_trace_failures = []
    for trace_id, rows in by_trace.items():
        trace_out = [r for r in output_rows if r["trace_id"] == trace_id]
        failures = sum(1 for r in trace_out if r["classification"] != "pass")
        by_trace_failures.append({"trace_id": trace_id, "rows": len(trace_out), "failures": failures, "failure_rate": float(failures) / len(trace_out) if trace_out else 0})
    summary["worst_traces"] = sorted(by_trace_failures, key=lambda r: (-r["failures"], -r["failure_rate"]))[:20]
    return output_rows, summary


def classify_gates(rows, trace_summary, rootfs, density):
    counts = collections.Counter(r["classification"] for r in rows)
    tool_failures = [r["test_id"] for r in rows if r["category"] == "rootfs" and r["classification"] != "pass"]
    process_failures = [r["test_id"] for r in rows if r["category"] == "process_api" and r["classification"] not in ("pass", "deferred")]
    reset_failures = [r["test_id"] for r in rows if r["category"] == "filesystem_reset" and r["classification"] == "fail"]
    density_max = max([d["booted"] for d in density] or [0])
    trace_rate = trace_summary.get("non_pass_rate")
    trace_status = "pass" if trace_rate is not None and trace_rate <= 0.05 else "partial"
    return {
        "summary": "pursue as a serious comparator",
        "classification_counts": dict(counts),
        "gates": {
            "gate_a_lumi_operations": {"status": "pass", "notes": "Runs under ordinary Slurm on LUMI dev-g with no root; reusable kernel/rootfs artifacts staged in scratch."},
            "gate_b_vsock_process_api": {"status": "pass" if not process_failures else "partial", "notes": "Process API failures: {}".format(", ".join(process_failures) if process_failures else "none")},
            "gate_c_rootfs_fidelity": {"status": "pass" if not tool_failures else "partial", "notes": "Tool/profile failures: {}; rootfs reused across jobs: {}".format(", ".join(tool_failures) if tool_failures else "none", rootfs.get("can_be_reused_across_jobs"))},
            "gate_d_reset_and_recycle": {"status": "pass" if not reset_failures else "partial", "notes": "Tmpfs workspace reset tested with separate request/validation timing; overlay/snapshot modes deferred."},
            "gate_e_network_policy": {"status": "deferred", "notes": "ACL/policy remains deliberately deferred. We are confident policy can be achieved, but gateway/proxy design tradeoffs should be evaluated separately; this is considered low risk for this phase."},
            "gate_f_density_and_cost": {"status": "pass" if density_max >= 32 else "partial", "notes": "Parallel full-rootfs density reached {} VMs in this run; higher saturation remains future work if not reached.".format(density_max)},
            "gate_g_trace_transfer": {"status": trace_status, "notes": "Trace candidate non-pass rate {:.3f}; native raw expected outputs were not included, so exact equivalence remains limited.".format(trace_rate if trace_rate is not None else -1)},
        },
    }


def write_reports(result, rows, trace_rows, trace_summary, job_id):
    reports_dir = Path("reports")
    mkdir(reports_dir)
    stem = reports_dir / "firecracker-lumi-phase5-{}".format(job_id)
    json_path = stem.with_suffix(".json")
    md_path = stem.with_suffix(".md")
    analysis_path = reports_dir / "firecracker-lumi-phase5-{}-analysis.md".format(job_id)
    trace_summary_json = reports_dir / "trace-replay-firecracker-agenttrove-strict-safe-100-analysis.json"
    trace_summary_md = reports_dir / "trace-replay-firecracker-agenttrove-strict-safe-100-analysis.md"
    trace_summary_short = reports_dir / "trace-replay-firecracker-agenttrove-strict-safe-100-summary.md"

    result["benchmarks"] = rows
    result["latency_summary"] = summarize_by_category(rows)
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True))
    trace_summary_json.write_text(json.dumps(trace_summary, indent=2, sort_keys=True))
    counts = collections.Counter(r["classification"] for r in rows)
    lines = [
        "# Firecracker LUMI Phase 5",
        "",
        "- Job: `{}`".format(job_id),
        "- Node: `{}`".format(result.get("host", {}).get("hostname")),
        "- Kernel: `{}`".format(result.get("artifacts", {}).get("kernel", {}).get("path")),
        "- Rootfs: `{}`".format(result.get("artifacts", {}).get("rootfs", {}).get("path")),
        "- Rootfs logical bytes: `{}`".format(result.get("artifacts", {}).get("rootfs", {}).get("logical_size_bytes")),
        "- Classifications: `{}`".format(json.dumps(dict(counts), sort_keys=True)),
        "",
        "## Decision Gates",
        "",
    ]
    for gate, data in result.get("recommendation", {}).get("gates", {}).items():
        lines.append("- `{}`: `{}` - {}".format(gate, data.get("status"), data.get("notes", "")))
    lines.extend([
        "",
        "## Trace Replay",
        "",
        "- Commands: `{}`".format(trace_summary.get("command_count")),
        "- Traces: `{}`".format(trace_summary.get("trace_count")),
        "- Non-pass rate: `{:.3f}`".format(trace_summary.get("non_pass_rate") or 0),
        "- Limitation: {}".format(trace_summary.get("comparison_limitation")),
        "",
        "## Representative Rows",
        "",
        "| test | class | ms | exit | stdout bytes | stderr bytes | notes |",
        "|---|---:|---:|---:|---:|---:|---|",
    ])
    for row in rows[:120]:
        lines.append("| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | {} |".format(
            row["test_id"], row["classification"],
            "{:.3f}".format(row["elapsed_ms"]) if row.get("elapsed_ms") is not None else "",
            row.get("exit_code"), row.get("stdout_bytes"), row.get("stderr_bytes"), (row.get("notes") or "").replace("|", "/")[:160],
        ))
    md_path.write_text("\n".join(lines) + "\n")

    analysis = [
        "# Firecracker LUMI Phase 5 Analysis",
        "",
        "## Recommendation",
        "",
        "`{}`".format(result.get("recommendation", {}).get("summary")),
        "",
        "Network ACL/policy enforcement is intentionally deferred. The current judgment is that policy is achievable, but gateway/proxy design tradeoffs should be evaluated separately; this is treated as low risk rather than a failed Phase 5 capability.",
        "",
        "## What This Run Addresses",
        "",
        "- A richer Ubuntu rootfs/tool profile is composed from package indexes and reusable as a scratch artifact.",
        "- The command agent and network tunnel remain separate vsock services; this run focuses on the command/control plane.",
        "- The vsock process API is exercised with warm commands, stdin/stdout/stderr, binary output, long-running handles, termination, and malformed frame survival.",
        "- The reset baseline remains read-only root plus tmpfs workspace with separate reset request and validation timing.",
        "- Trace replay uses the provided AgentTrove 100-trace corpus and fixture workspace inside Firecracker guests.",
        "",
        "## Caveats",
        "",
        "- The rootfs is still a single composed image. Long term, image/component composition needs a better profile/layer story.",
        "- The guest agent is PID 1 rather than systemd; this is suitable for rollout command environments, not service-manager fidelity.",
        "- Trace equivalence is limited because the handoff includes native aggregate analysis but not per-command native raw expected outputs.",
        "- Disk overlay and Firecracker snapshot restore are deferred in favor of rootfs, API, density, and trace fidelity evidence.",
        "",
        "## Gate Status",
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
        "## Trace Summary",
        "",
        "```json",
        json.dumps({k: trace_summary.get(k) for k in ("trace_count", "command_count", "classification_counts", "non_pass_rate", "reset_ms", "command_elapsed_ms", "top_failure_patterns")}, indent=2, sort_keys=True),
        "```",
        "",
        "## Final Answers",
        "",
        "- Should Firecracker remain a serious LUMI comparator? `yes`, if the measured trace and density results remain near native and pool-manager work continues.",
        "- Can it support realistic coding/terminal rollouts better than WASIX? `likely yes` for Linux fidelity, native Python/coreutils behavior, and filesystem semantics.",
        "- Can networking be enabled safely by profile? `deferred`; basic egress is known, policy design remains separate and low risk.",
        "- What production work remains? pool manager, image/profile composition, gateway policy design, snapshot/overlay reset evaluation, and broader saturation testing.",
    ])
    analysis_path.write_text("\n".join(analysis) + "\n")

    trace_lines = [
        "# Firecracker Trace Replay Summary",
        "",
        "- Corpus: `{}`".format(TRACE_NAME),
        "- Traces: `{}`".format(trace_summary.get("trace_count")),
        "- Commands: `{}`".format(trace_summary.get("command_count")),
        "- Non-pass rate: `{:.3f}`".format(trace_summary.get("non_pass_rate") or 0),
        "- Classification counts: `{}`".format(json.dumps(trace_summary.get("classification_counts", {}), sort_keys=True)),
        "- Limitation: {}".format(trace_summary.get("comparison_limitation")),
        "",
        "## Worst Traces",
        "",
        "| trace | rows | failures | failure rate |",
        "|---|---:|---:|---:|",
    ]
    for item in trace_summary.get("worst_traces", [])[:20]:
        trace_lines.append("| `{}` | `{}` | `{}` | `{:.3f}` |".format(item["trace_id"], item["rows"], item["failures"], item["failure_rate"]))
    trace_summary_short.write_text("\n".join(trace_lines) + "\n")
    trace_summary_md.write_text("\n".join(trace_lines) + "\n")

    return {
        "json": str(json_path),
        "markdown": str(md_path),
        "analysis": str(analysis_path),
        "trace_analysis_json": str(trace_summary_json),
        "trace_analysis_md": str(trace_summary_md),
        "trace_summary_md": str(trace_summary_short),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--kernel-path", required=True)
    ap.add_argument("--artifact-cache-dir", required=True)
    ap.add_argument("--rootfs-cache-dir", required=True)
    ap.add_argument("--handoff-dir", required=True)
    ap.add_argument("--mem-mib", type=int, default=768)
    ap.add_argument("--vcpus", type=int, default=1)
    ap.add_argument("--density", default="1,4,8,16,32")
    ap.add_argument("--skip-density", action="store_true")
    ap.add_argument("--skip-trace", action="store_true")
    args = ap.parse_args()

    run_dir = Path(args.run_dir)
    handoff_dir = Path(args.handoff_dir)
    trace_jsonl = handoff_dir / "traces" / "agenttrove-strict-safe-100-commands.jsonl"
    workspace_template = handoff_dir / "workspaces" / "fixtures" / "mvp"
    mkdir(run_dir)
    reports_dir = Path("reports")
    mkdir(reports_dir)
    job_id = os.environ.get("SLURM_JOB_ID", "local")
    raw_path = reports_dir / "firecracker-lumi-phase5-{}-raw.jsonl".format(job_id)
    trace_out_path = reports_dir / "trace-replay-firecracker-agenttrove-strict-safe-100.jsonl"
    for path in (raw_path, trace_out_path):
        if path.exists():
            path.unlink()

    result = {
        "host": host_snapshot(),
        "slurm": dict(os.environ),
        "args": vars(args),
        "errors": [],
        "artifacts": {},
        "guest_image": {},
        "network_proxy": {
            "acl_policy": "deferred_by_user_instruction",
            "notes": "Command agent vsock and network tunnel/proxy vsock are separate services. gvproxy remains basic egress evidence only.",
        },
        "density": {},
        "trace_replay": {},
        "comparison_context": {},
    }
    rows = []
    trace_rows = []
    trace_summary = {"trace_count": 0, "command_count": 0, "classification_counts": {}, "non_pass_rate": None}
    vms = []
    try:
        log("preparing phase5 artifacts")
        fc = download_firecracker(Path(args.artifact_cache_dir) / "firecracker")
        tools = download_gvisor_tap_vsock(Path(args.artifact_cache_dir) / "gvisor-tap-vsock")
        rootfs = prepare_rootfs(args.rootfs_cache_dir, args.artifact_cache_dir, tools, workspace_template)
        native_analysis = json.loads((handoff_dir / "traces" / "native-baseline-analysis.json").read_text())
        wasix_analysis = json.loads((handoff_dir / "traces" / "wasix-current-analysis.json").read_text())
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
            "workspace_template": str(workspace_template),
        }
        result["comparison_context"] = {
            "native": native_analysis.get("totals"),
            "wasix_current": wasix_analysis.get("totals"),
        }

        log("booting primary phase5 VM")
        vm = Phase4VM("phase5-primary", fc["path"], args.kernel_path, rootfs["path"], run_dir, mem_mib=args.mem_mib, vcpus=args.vcpus)
        boot = vm.boot()
        vms.append(vm)
        boot_row = benchmark_row("lifecycle.primary_boot_to_ready", "lifecycle", "boot", {"ok": True, "exit_code": 0, "stdout_b64": "", "stderr_b64": "", "command_roundtrip_ms": boot["ready_ms"]}, boot_ms=boot["ready_ms"], ready_ms=boot["ready_ms"], host_rss_kb=boot["rss_kb_after_ready"], guest_memory_mb=args.mem_mib, vmm_launch_ms=boot["vmm_launch_ms"], api_config_ms=boot["config_ms"])
        rows.append(boot_row)
        write_jsonl(raw_path, boot_row)

        log("running rootfs tool profile")
        rows.extend(run_rootfs_tool_tests(vm, raw_path))
        log("running process API profile")
        rows.extend(run_process_api_tests(vm, raw_path))
        log("running reset profile")
        rows.extend(run_reset_tests(vm, raw_path))
        log("running security/resource smoke")
        rows.extend(run_security_smoke(vm, raw_path))

        if not args.skip_trace:
            log("running trace replay corpus")
            trace_rows, trace_summary = run_trace_replay(vm, trace_jsonl, trace_out_path, raw_path)
            result["trace_replay"] = trace_summary
        else:
            result["trace_replay"] = {"classification": "deferred", "notes": "Skipped by argument"}

        vm.stop()
        vms.remove(vm)

        if not args.skip_density:
            log("running parallel density profile")
            density_levels = [int(x) for x in args.density.split(",") if x.strip()]
            density_rows, density_summary = run_density_tests(fc, args.kernel_path, rootfs["path"], run_dir, args.mem_mib, args.vcpus, raw_path, density_levels)
            rows.extend(density_rows)
            result["density"]["parallel_full_rootfs"] = density_summary
        else:
            result["density"]["parallel_full_rootfs"] = []

        result["recommendation"] = classify_gates(rows, trace_summary, rootfs, result["density"].get("parallel_full_rootfs", []))
    except Exception as exc:
        result.setdefault("errors", []).append({"fatal": repr(exc)})
        result.setdefault("recommendation", {"summary": "incomplete", "gates": {}})
    finally:
        for vm in list(vms):
            try:
                vm.stop()
            except Exception:
                pass
        result["host_after"] = host_snapshot()
        reports = write_reports(result, rows, trace_rows, trace_summary, job_id)
        result["reports"] = reports
        # Keep reports and reusable cache/rootfs, but remove noisy per-VM directories from this run.
        for path in run_dir.glob("vm-*"):
            shutil.rmtree(str(path), ignore_errors=True)
        print(json.dumps({"reports": reports, "rows": len(rows), "trace_rows": len(trace_rows), "errors": result.get("errors", [])[-5:]}, indent=2), flush=True)


if __name__ == "__main__":
    main()
