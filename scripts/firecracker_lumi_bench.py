#!/usr/bin/env python3
import argparse
import collections
import hashlib
import json
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import sysconfig
import tempfile
import threading
import time
from pathlib import Path


FC_RELEASE_URL = "https://github.com/firecracker-microvm/firecracker/releases"
FC_ARTIFACT_S3 = "https://s3.amazonaws.com/spec.ccfc.min"


def now_ns():
    monotonic_ns = getattr(time, "monotonic_ns", None)
    if monotonic_ns is not None:
        return monotonic_ns()
    return int(time.monotonic() * 1e9)


def ms_since(start_ns):
    return (now_ns() - start_ns) / 1e6


def run(cmd, cwd=None, check=True, env=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
    p = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        stdout=stdout,
        stderr=stderr,
        universal_newlines=True,
    )
    if check and p.returncode != 0:
        raise RuntimeError("command failed rc={} cmd={} stdout={} stderr={}".format(
            p.returncode, cmd, p.stdout, p.stderr
        ))
    return p


def mkdir(path):
    Path(path).mkdir(parents=True, exist_ok=True)


def read_text(path, default=""):
    try:
        return Path(path).read_text()
    except Exception:
        return default


def command_path(name):
    p = shutil.which(name)
    if not p:
        for prefix in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
            candidate = Path(prefix) / name
            if candidate.exists():
                return str(candidate)
    if not p:
        raise RuntimeError("missing required command: {}".format(name))
    return p


def host_snapshot():
    snap = {}
    snap["timestamp_unix"] = time.time()
    snap["hostname"] = run(["hostname"], check=False).stdout.strip()
    snap["uname"] = run(["uname", "-a"], check=False).stdout.strip()
    snap["cpuinfo_model"] = ""
    for line in read_text("/proc/cpuinfo").splitlines():
        if line.startswith("model name"):
            snap["cpuinfo_model"] = line.split(":", 1)[1].strip()
            break
    snap["cpu_count_logical"] = os.cpu_count()
    snap["meminfo"] = {}
    for line in read_text("/proc/meminfo").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            snap["meminfo"][parts[0].rstrip(":")] = int(parts[1])
    snap["loadavg"] = read_text("/proc/loadavg").strip()
    snap["cgroup_memory"] = {
        "memory_max": read_text("/sys/fs/cgroup/memory.max").strip(),
        "memory_current": read_text("/sys/fs/cgroup/memory.current").strip(),
    }
    snap["slurm"] = {
        "job_id": os.environ.get("SLURM_JOB_ID"),
        "job_nodelist": os.environ.get("SLURM_JOB_NODELIST"),
        "cpus_on_node": os.environ.get("SLURM_CPUS_ON_NODE"),
        "cpus_per_task": os.environ.get("SLURM_CPUS_PER_TASK"),
        "mem_per_node": os.environ.get("SLURM_MEM_PER_NODE"),
    }
    return snap


def proc_rss_kb(pid):
    status = read_text("/proc/{}/status".format(pid))
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return None


def proc_cpu_seconds(pid):
    stat = read_text("/proc/{}/stat".format(pid))
    if not stat:
        return None
    # comm can contain spaces inside parentheses; fields after the final ") ".
    try:
        rest = stat.rsplit(") ", 1)[1].split()
        utime_ticks = int(rest[11])
        stime_ticks = int(rest[12])
        hz = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
        return (utime_ticks + stime_ticks) / float(hz)
    except Exception:
        return None


def copy_preserve(src, root):
    src = Path(src)
    dest = Path(root) / str(src).lstrip("/")
    mkdir(dest.parent)
    if src.is_symlink():
        target = os.readlink(str(src))
        if dest.exists() or dest.is_symlink():
            dest.unlink()
        os.symlink(target, str(dest))
        target_path = Path(target) if os.path.isabs(target) else src.parent / target
        if target_path.exists():
            copy_preserve(target_path, root)
        real = src.resolve()
        if real.exists():
            copy_preserve(real, root)
    else:
        shutil.copy2(str(src), str(dest))


def ldd_paths(binary):
    p = run(["ldd", binary], check=False)
    paths = []
    for line in (p.stdout + "\n" + p.stderr).splitlines():
        line = line.strip()
        if "=>" in line:
            rhs = line.split("=>", 1)[1].strip().split()[0]
            if rhs.startswith("/"):
                paths.append(rhs)
        else:
            first = line.split()[0] if line.split() else ""
            if first.startswith("/"):
                paths.append(first)
    return sorted(set(paths))


def copy_binary_with_libs(binary, root):
    binary = command_path(binary) if not str(binary).startswith("/") else str(binary)
    copy_preserve(binary, root)
    for lib in ldd_paths(binary):
        copy_preserve(lib, root)
    return binary


def link_or_copy(src, dest):
    src = Path(src)
    dest = Path(dest)
    if dest.exists():
        dest.unlink()
    try:
        os.link(str(src), str(dest))
        return "hardlink"
    except OSError:
        shutil.copy2(str(src), str(dest))
        return "copy"


def copy_shared_library_deps_under(src_dir, root):
    src_dir = Path(src_dir)
    if not src_dir.exists():
        return []
    copied = []
    for dirpath, _, filenames in os.walk(str(src_dir)):
        for filename in filenames:
            if not filename.endswith(".so") and ".so." not in filename:
                continue
            host_path = str(Path(dirpath) / filename)
            try:
                for lib in ldd_paths(host_path):
                    copy_preserve(lib, root)
                    copied.append(lib)
            except Exception as exc:
                copied.append("MISSING_DEPS {}: {}".format(host_path, exc))
    return sorted(set(copied))


def copy_tree_filtered(src, dst):
    src = Path(src)
    dst = Path(dst)
    if not src.exists():
        return
    def ignore(dirpath, names):
        ignored = []
        for name in names:
            if name in ("__pycache__", "test", "tests", "tkinter", "idlelib", "ensurepip", "site-packages", "pydoc_data"):
                ignored.append(name)
            elif name.startswith("config-"):
                ignored.append(name)
            elif name.endswith((".pyc", ".pyo")):
                ignored.append(name)
            elif name.endswith((".a", ".la")):
                ignored.append(name)
            elif name.startswith("_test") and (name.endswith(".so") or ".so." in name):
                ignored.append(name)
        return ignored
    if dst.exists():
        shutil.rmtree(str(dst))
    shutil.copytree(str(src), str(dst), ignore=ignore, symlinks=True)


def install_pytest(root, enabled):
    result = {"requested": bool(enabled), "installed": False, "seconds": 0.0, "stdout": "", "stderr": ""}
    if not enabled:
        return result
    pytest_package = "pytest==7.4.4" if sys.version_info >= (3, 7) else "pytest==6.2.5"
    paths = sysconfig.get_paths()
    purelib = paths.get("purelib") or paths.get("platlib")
    if purelib:
        target = Path(root) / str(Path(purelib).relative_to("/"))
    else:
        target = Path(root) / "usr/lib/python{}.{}".format(sys.version_info[0], sys.version_info[1]) / "site-packages"
    mkdir(target)
    cmd = [
        command_path("python3"), "-m", "pip", "install",
        "--disable-pip-version-check",
        "--no-input",
        "--target", str(target),
        pytest_package,
    ]
    t0 = now_ns()
    p = run(cmd, check=False)
    result["seconds"] = ms_since(t0) / 1000.0
    result["stdout"] = p.stdout[-4000:]
    result["stderr"] = p.stderr[-4000:]
    result["installed"] = p.returncode == 0
    result["returncode"] = p.returncode
    result["package"] = pytest_package
    return result


def build_initramfs(build_dir, with_pytest):
    build_dir = Path(build_dir)
    root = build_dir / "agent-root"
    if root.exists():
        shutil.rmtree(str(root))
    mkdir(root)
    for d in ("bin", "usr/bin", "usr/lib", "usr/lib64", "lib", "lib64", "proc", "sys", "dev", "tmp", "root", "workspace", "workspace/tests", "etc", "home"):
        mkdir(root / d)

    bins = [
        "awk", "base64", "basename",
        "bash", "cat", "chmod", "cp", "date", "echo", "env", "find", "free", "grep",
        "git", "gzip", "head", "id", "kill", "ls", "mkdir", "mount", "patch", "poweroff",
        "ps", "pwd", "reboot", "rm", "sed", "seq", "sh", "sleep", "sort", "stty", "sync",
        "tar", "timeout", "touch", "tr", "true", "uname", "uniq", "wc", "xargs",
        "diff", "dirname", "dd", "df", "du", "ln", "mv", "od", "printf", "sha256sum",
        "stat", "tail", "which", "gcc", "clang", "make",
        "python3",
    ]
    copied = []
    for b in bins:
        try:
            copied.append(copy_binary_with_libs(b, root))
        except Exception as exc:
            copied.append("MISSING {}: {}".format(b, exc))

    # Ensure common aliases exist even if the host keeps binaries in /usr/bin.
    for name in ("bash", "cat", "cp", "echo", "grep", "ls", "pwd", "rm", "sh", "true", "python3"):
        src = shutil.which(name)
        if src:
            dest = root / "bin" / name
            if not dest.exists():
                try:
                    os.symlink(src, str(dest))
                except Exception:
                    pass
    py = shutil.which("python3")
    if py:
        py_dest = root / str(Path(py).relative_to("/"))
        py_alias = root / "usr/bin/python"
        if py_dest.exists() and not py_alias.exists():
            os.symlink("python3", str(py_alias))

    paths = sysconfig.get_paths()
    python_dirs = []
    for key in ("stdlib", "platstdlib"):
        value = paths.get(key)
        if value and value not in python_dirs:
            python_dirs.append(value)
    for value in list(python_dirs):
        parent = str(Path(value).parent)
        if parent not in python_dirs and Path(parent).name.startswith("python"):
            python_dirs.append(parent)
    for py_dir in python_dirs:
        try:
            copy_tree_filtered(py_dir, root / str(Path(py_dir).relative_to("/")))
        except Exception:
            pass
    python_shared_deps = []
    for py_dir in python_dirs:
        python_shared_deps.extend(copy_shared_library_deps_under(py_dir, root))
    pytest_result = install_pytest(root, with_pytest)
    for key in ("purelib", "platlib"):
        value = paths.get(key)
        if value:
            python_shared_deps.extend(copy_shared_library_deps_under(root / str(Path(value).relative_to("/")), root))
    pruned = []
    for pattern in ("**/*.a", "**/*.la", "**/_test*.so", "**/_test*.so.*"):
        for path in root.glob(pattern):
            try:
                size = path.stat().st_size
                path.unlink()
                pruned.append({"path": str(path.relative_to(root)), "bytes": size})
            except Exception:
                pass
    for rel in (
        "opt/cray/pe/libsci",
        "opt/cray/pe/mpich",
        "opt/cray/libfabric",
        "opt/cray/pe/pmi",
        "opt/cray/pe/cce",
    ):
        path = root / rel
        if path.exists():
            try:
                size = sum(p.stat().st_size for p in path.rglob("*") if p.is_file())
                shutil.rmtree(str(path))
                pruned.append({"path": rel, "bytes": size})
            except Exception:
                pass

    small_txt = root / "workspace/small.txt"
    small_txt.write_text("small file\nneedle\n")
    file_txt = root / "workspace/file.txt"
    with file_txt.open("w") as f:
        for i in range(2000):
            if i == 1234:
                f.write("needle line {}\n".format(i))
            else:
                f.write("ordinary line {}\n".format(i))
    (root / "workspace/tests/test_basic.py").write_text(
        "def test_arithmetic():\n"
        "    assert 1 + 1 == 2\n\n"
        "def test_file_exists():\n"
        "    import os\n"
        "    assert os.path.exists('/workspace/small.txt')\n"
    )
    (root / "etc/passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "agent:x:1000:1000:agent:/home/agent:/bin/bash\n"
    )
    (root / "etc/group").write_text(
        "root:x:0:\n"
        "agent:x:1000:\n"
    )

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
seq=0
while IFS= read -r cmd; do
    seq=$((seq + 1))
    if [ "$cmd" = "__NOOP__" ]; then
        echo "__FC_NOOP_BEGIN__:${seq}"
        echo "__FC_NOOP_END__:${seq}:0"
        continue
    fi
    if [ "$cmd" = "__POWEROFF__" ]; then
        echo "__FC_BYE__:${seq}"
        sync || true
        poweroff -f || reboot -f || exit 0
    fi
    out="/tmp/fc-out-${seq}"
    err="/tmp/fc-err-${seq}"
    echo "__FC_CMD_BEGIN__:${seq}"
    /bin/bash -lc "$cmd" >"$out" 2>"$err"
    rc=$?
    echo "__FC_STDOUT_BEGIN__:${seq}"
    cat "$out" 2>/dev/null || true
    echo "__FC_STDOUT_END__:${seq}"
    echo "__FC_STDERR_BEGIN__:${seq}"
    cat "$err" 2>/dev/null || true
    echo "__FC_STDERR_END__:${seq}"
    echo "__FC_CMD_END__:${seq}:${rc}"
    rm -f "$out" "$err"
done
""")
    init.chmod(0o755)

    image = build_dir / "agent-initramfs.cpio.gz"
    if image.exists():
        image.unlink()
    t0 = now_ns()
    cmd = "cd '{}' && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1 > '{}'".format(
        str(root), str(image)
    )
    run(["bash", "-lc", cmd])
    build_ms = ms_since(t0)
    return {
        "root": str(root),
        "image": str(image),
        "image_bytes": image.stat().st_size,
        "build_ms": build_ms,
        "copied_binaries": copied,
        "python_shared_library_deps": sorted(set(python_shared_deps)),
        "pruned_from_guest_root": pruned,
        "pytest": pytest_result,
    }


def download_firecracker(cache_dir):
    cache_dir = Path(cache_dir)
    mkdir(cache_dir)
    arch = run(["uname", "-m"]).stdout.strip()
    latest = run([
        "bash", "-lc",
        "basename $(curl -fsSLI -o /dev/null -w '%{{url_effective}}' {}/latest)".format(FC_RELEASE_URL)
    ]).stdout.strip()
    out = cache_dir / "firecracker-{}-{}".format(latest, arch)
    if not out.exists():
        tmp = cache_dir / "firecracker.tgz"
        run(["curl", "-fsSL", "-o", str(tmp), "{}/download/{}/firecracker-{}-{}.tgz".format(
            FC_RELEASE_URL, latest, latest, arch
        )])
        run(["tar", "-xzf", str(tmp), "-C", str(cache_dir)])
        src = cache_dir / "release-{}-{}/firecracker-{}-{}".format(latest, arch, latest, arch)
        shutil.copy2(str(src), str(out))
        out.chmod(0o755)
    version_lines = run([str(out), "--version"], check=False).stdout.splitlines()
    version = version_lines[0].strip() if version_lines else ""
    return {"path": str(out), "release": latest, "arch": arch, "version": version}


def download_kernel(cache_dir):
    cache_dir = Path(cache_dir)
    mkdir(cache_dir)
    arch = run(["uname", "-m"]).stdout.strip()
    script = r'''
set -euo pipefail
S3="https://s3.amazonaws.com/spec.ccfc.min"
ARCH="$(uname -m)"
CI_ARTIFACTS_PREFIX=$(curl -fsSL "$S3?list-type=2&prefix=firecracker-ci/&delimiter=/" \
    | grep -oP "(?<=<Prefix>)firecracker-ci/[0-9]{8}-[^/]+/(?=</Prefix>)" \
    | sort \
    | tail -1)
latest_kernel_key=$(curl -fsSL "$S3?list-type=2&prefix=${CI_ARTIFACTS_PREFIX}${ARCH}/vmlinux-" \
      | grep -oP "(?<=<Key>)(${CI_ARTIFACTS_PREFIX}${ARCH}/vmlinux-[0-9]+\.[0-9]+\.[0-9]{1,3})(?=</Key>)" \
      | sort -V \
      | tail -1)
echo "$latest_kernel_key"
'''
    key = run(["bash", "-lc", script]).stdout.strip()
    out = cache_dir / Path(key).name
    if not out.exists():
        run(["curl", "-fsSL", "-o", str(out), "{}/{}".format(FC_ARTIFACT_S3, key)])
    return {"path": str(out), "key": key, "bytes": out.stat().st_size}


class PipeReader(threading.Thread):
    def __init__(self, name, pipe, q):
        super(PipeReader, self).__init__()
        self.daemon = True
        self.name = name
        self.pipe = pipe
        self.q = q

    def run(self):
        while True:
            data = self.pipe.readline()
            if not data:
                break
            try:
                text = data.decode("utf-8", "replace").rstrip("\n").rstrip("\r")
            except AttributeError:
                text = data.rstrip("\n").rstrip("\r")
            self.q.put((now_ns(), self.name, text))
        self.q.put((now_ns(), self.name, None))


class FirecrackerVM(object):
    def __init__(self, vm_id, fc_path, kernel_path, initrd_path, base_dir, mem_mib=512, vcpus=1):
        self.vm_id = vm_id
        self.fc_path = fc_path
        self.kernel_path = kernel_path
        self.initrd_path = initrd_path
        self.base_dir = Path(base_dir)
        self.mem_mib = mem_mib
        self.vcpus = vcpus
        self.dir = self.base_dir / "vm-{}".format(vm_id)
        sock_hash = hashlib.sha1("{}-{}-{}".format(os.getpid(), base_dir, vm_id).encode("utf-8")).hexdigest()[:16]
        self.sock = Path(tempfile.gettempdir()) / "fc-{}-{}.sock".format(
            os.environ.get("SLURM_JOB_ID", "local"), sock_hash
        )
        self.log = self.dir / "firecracker.log"
        self.proc = None
        self.q = queue.Queue()
        self.seq = 0
        self.boot_records = {}

    def prepare_files(self):
        if self.dir.exists():
            shutil.rmtree(str(self.dir))
        mkdir(self.dir)
        t0 = now_ns()
        self.vm_initrd = self.dir / "initrd.cpio.gz"
        initrd_method = link_or_copy(self.initrd_path, self.vm_initrd)
        initrd_copy_ms = ms_since(t0)
        t1 = now_ns()
        self.rootfs = self.dir / "dummy-rootfs.raw"
        with self.rootfs.open("wb") as f:
            f.truncate(1024 * 1024)
        rootfs_setup_ms = ms_since(t1)
        return {
            "initrd_copy_ms": initrd_copy_ms,
            "initrd_materialize_method": initrd_method,
            "rootfs_setup_ms": rootfs_setup_ms,
            "initrd_bytes": self.vm_initrd.stat().st_size,
            "dummy_rootfs_bytes": self.rootfs.stat().st_size,
        }

    def api(self, method, path, data):
        body = json.dumps(data) if data is not None else ""
        cmd = [
            "curl", "-sS", "--unix-socket", str(self.sock),
            "-X", method,
            "-H", "Accept: application/json",
            "-H", "Content-Type: application/json",
        ]
        if data is not None:
            cmd += ["-d", body]
        cmd += ["-w", "\nHTTP %{http_code}\n", "http://localhost{}".format(path)]
        p = run(cmd, check=False)
        http = None
        m = re.search(r"HTTP (\d+)", p.stdout)
        if m:
            http = int(m.group(1))
        return {
            "method": method,
            "path": path,
            "http": http,
            "stdout": p.stdout,
            "stderr": p.stderr,
            "returncode": p.returncode,
        }

    def start_process(self):
        if self.sock.exists():
            self.sock.unlink()
        t0 = now_ns()
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
        deadline = time.time() + 10.0
        while time.time() < deadline:
            if self.sock.exists():
                return ms_since(t0)
            if self.proc.poll() is not None:
                time.sleep(0.1)
                recent = []
                while True:
                    try:
                        recent.append(self.q.get_nowait())
                    except queue.Empty:
                        break
                raise RuntimeError("Firecracker exited before API socket was ready rc={} recent={}".format(
                    self.proc.returncode, recent[-40:]
                ))
            time.sleep(0.005)
        raise RuntimeError("timeout waiting for API socket")

    def configure_and_boot(self, timeout=30.0):
        api_records = []
        t_cfg = now_ns()
        api_records.append(self.api("PUT", "/machine-config", {
            "vcpu_count": self.vcpus,
            "mem_size_mib": self.mem_mib,
            "smt": False,
        }))
        api_records.append(self.api("PUT", "/boot-source", {
            "kernel_image_path": str(self.vm_kernel),
            "initrd_path": str(self.vm_initrd),
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off quiet",
        }))
        api_records.append(self.api("PUT", "/drives/rootfs", {
            "drive_id": "rootfs",
            "path_on_host": str(self.rootfs),
            "is_root_device": False,
            "is_read_only": False,
        }))
        config_ms = ms_since(t_cfg)
        t_start = now_ns()
        start_resp = self.api("PUT", "/actions", {"action_type": "InstanceStart"})
        instance_start_api_ms = ms_since(t_start)
        ready = self.wait_for_marker("__FC_AGENT_READY__", timeout=timeout)
        boot_to_ready_ms = (ready["time_ns"] - t_start) / 1e6
        return {
            "api_records": api_records,
            "config_ms": config_ms,
            "instance_start": start_resp,
            "instance_start_api_ms": instance_start_api_ms,
            "boot_to_ready_ms": boot_to_ready_ms,
        }

    def boot(self, timeout=30.0):
        prep = self.prepare_files()
        self.vm_kernel = self.dir / "vmlinux"
        prep["kernel_materialize_method"] = link_or_copy(self.kernel_path, self.vm_kernel)
        vmm_launch_ms = self.start_process()
        boot = self.configure_and_boot(timeout=timeout)
        self.boot_records = {
            "file_setup": prep,
            "vmm_launch_ms": vmm_launch_ms,
        }
        self.boot_records.update(boot)
        self.boot_records["pid"] = self.proc.pid
        self.boot_records["rss_kb_after_ready"] = proc_rss_kb(self.proc.pid)
        return self.boot_records

    def wait_for_marker(self, marker, timeout=10.0):
        deadline = time.time() + timeout
        lines = []
        while time.time() < deadline:
            if self.proc and self.proc.poll() is not None:
                # keep draining briefly, then fail.
                pass
            try:
                t, src, line = self.q.get(timeout=0.1)
            except queue.Empty:
                continue
            if line is None:
                continue
            lines.append({"t_ns": t, "src": src, "line": line})
            if marker in line:
                return {"time_ns": t, "src": src, "line": line, "recent_lines": lines[-80:]}
        raise RuntimeError("timeout waiting for marker {} recent={}".format(marker, lines[-40:]))

    def send_line(self, line):
        if self.proc.poll() is not None:
            raise RuntimeError("VM process is not running")
        self.proc.stdin.write((line + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def command(self, cmd, timeout=20.0, noop=False):
        self.seq += 1
        seq = self.seq
        rss_before = proc_rss_kb(self.proc.pid)
        cpu_before = proc_cpu_seconds(self.proc.pid)
        t0 = now_ns()
        self.send_line("__NOOP__" if noop else cmd)
        stdout_lines = []
        stderr_lines = []
        recent = []
        section = None
        rc = None
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                t, src, line = self.q.get(timeout=0.1)
            except queue.Empty:
                continue
            if line is None:
                continue
            recent.append({"t_ns": t, "src": src, "line": line})
            if noop:
                if line.startswith("__FC_NOOP_END__:"):
                    parts = line.split(":")
                    rc = int(parts[-1])
                    elapsed_ms = (t - t0) / 1e6
                    break
                continue
            if line.startswith("__FC_STDOUT_BEGIN__:"):
                section = "stdout"
                continue
            if line.startswith("__FC_STDOUT_END__:"):
                section = None
                continue
            if line.startswith("__FC_STDERR_BEGIN__:"):
                section = "stderr"
                continue
            if line.startswith("__FC_STDERR_END__:"):
                section = None
                continue
            if line.startswith("__FC_CMD_END__:"):
                parts = line.split(":")
                rc = int(parts[-1])
                elapsed_ms = (t - t0) / 1e6
                break
            if section == "stdout":
                stdout_lines.append(line)
            elif section == "stderr":
                stderr_lines.append(line)
        else:
            raise RuntimeError("timeout waiting for command {} recent={}".format(cmd, recent[-80:]))

        rss_after = proc_rss_kb(self.proc.pid)
        cpu_after = proc_cpu_seconds(self.proc.pid)
        cpu_delta = None
        if cpu_before is not None and cpu_after is not None:
            cpu_delta = cpu_after - cpu_before
        return {
            "cmd": "__NOOP__" if noop else cmd,
            "elapsed_ms": elapsed_ms,
            "exit_code": rc,
            "stdout": "\n".join(stdout_lines),
            "stderr": "\n".join(stderr_lines),
            "rss_kb_before": rss_before,
            "rss_kb_after": rss_after,
            "host_cpu_seconds_delta": cpu_delta,
        }

    def pause(self):
        return self.api("PATCH", "/vm", {"state": "Paused"})

    def resume(self):
        return self.api("PATCH", "/vm", {"state": "Resumed"})

    def snapshot(self, snapshot_path, mem_path):
        return self.api("PUT", "/snapshot/create", {
            "snapshot_type": "Full",
            "snapshot_path": str(snapshot_path),
            "mem_file_path": str(mem_path),
        })

    def load_snapshot(self, snapshot_path, mem_path, resume=True):
        return self.api("PUT", "/snapshot/load", {
            "snapshot_path": str(snapshot_path),
            "mem_file_path": str(mem_path),
            "resume_vm": bool(resume),
        })

    def stop(self):
        if not self.proc:
            return
        if self.proc.poll() is None:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            except Exception:
                try:
                    self.proc.terminate()
                except Exception:
                    pass
            try:
                self.proc.wait(timeout=5)
            except Exception:
                try:
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
                except Exception:
                    pass
                try:
                    self.proc.wait(timeout=5)
                except Exception:
                    pass
        try:
            if self.sock.exists():
                self.sock.unlink()
        except Exception:
            pass

    def request_guest_poweroff(self, timeout=5.0):
        t0 = now_ns()
        self.send_line("__POWEROFF__")
        marker = self.wait_for_marker("__FC_BYE__", timeout=timeout)
        self.stop()
        return {
            "ack_ms": ms_since(t0),
            "marker": marker,
            "note": "Guest agent acknowledged shutdown request; Firecracker process was then terminated by the harness.",
        }


def summarize(samples):
    vals = sorted(float(x) for x in samples)
    if not vals:
        return {"n": 0}
    def pct(p):
        if len(vals) == 1:
            return vals[0]
        idx = int(round((p / 100.0) * (len(vals) - 1)))
        idx = max(0, min(idx, len(vals) - 1))
        return vals[idx]
    return {
        "n": len(vals),
        "mean": sum(vals) / len(vals),
        "min": vals[0],
        "p50": pct(50),
        "p90": pct(90),
        "p99": pct(99),
        "max": vals[-1],
    }


def summarize_command_results(results):
    return {
        "latency_ms": summarize([r["elapsed_ms"] for r in results]),
        "exit_codes": dict(collections.Counter(str(r["exit_code"]) for r in results)),
        "rss_kb_after": summarize([r["rss_kb_after"] for r in results if r["rss_kb_after"] is not None]),
        "host_cpu_seconds_delta": summarize([
            r["host_cpu_seconds_delta"] for r in results if r["host_cpu_seconds_delta"] is not None
        ]),
        "first_stdout": results[0]["stdout"] if results else "",
        "first_stderr": results[0]["stderr"] if results else "",
    }


def run_cold_bench(args, fc, kernel, initrd, run_dir):
    records = []
    first_vm = None
    for i in range(args.cold_iters):
        vm = FirecrackerVM("cold-{}".format(i), fc["path"], kernel["path"], initrd["image"], run_dir,
                           mem_mib=args.mem_mib, vcpus=args.vcpus)
        rec = {"iteration": i}
        try:
            boot = vm.boot(timeout=args.boot_timeout)
            t_first = now_ns()
            cmd = vm.command("bash -lc 'echo ready'", timeout=20)
            rec.update(boot)
            rec["first_command"] = cmd
            rec["ready_to_first_command_ms"] = cmd["elapsed_ms"]
            rec["instance_start_to_first_command_done_ms"] = (
                boot["boot_to_ready_ms"] + ((now_ns() - t_first) / 1e6)
            )
            records.append(rec)
            if first_vm is None:
                first_vm = vm
                vm = None
        finally:
            if vm is not None:
                vm.stop()
    return records, first_vm


def run_warm_bench(vm, args):
    commands = [
        "bash -lc 'true'",
        "bash -lc 'echo hello'",
        "bash -lc 'pwd; ls -la'",
        "bash -lc 'cat small.txt'",
        "bash -lc 'grep needle file.txt'",
        "bash -lc 'python -c \"print(1)\"'",
        "bash -lc 'python -m pytest tests'",
    ]
    out = {}
    for cmd in commands:
        results = []
        for _ in range(args.warm_iters):
            results.append(vm.command(cmd, timeout=args.command_timeout))
        out[cmd] = {
            "summary": summarize_command_results(results),
            "samples": results,
        }
    noop = []
    for _ in range(args.noop_iters):
        noop.append(vm.command("", timeout=5, noop=True))
    out["__NOOP_TRANSPORT__"] = {
        "summary": summarize_command_results(noop),
        "samples": noop,
    }
    return out


def run_security_smoke(vm, args):
    commands = [
        "bash -lc 'cat /etc/passwd'",
        "bash -lc 'ls /home'",
        "bash -lc 'env'",
        "bash -lc 'python -c '\\''import socket; socket.create_connection((\"example.com\",80), timeout=2)'\\'''",
        "bash -lc 'ls -la /; mount; env | grep -Ei \"token|secret|key|password|credential\" || true'",
    ]
    out = {}
    for cmd in commands:
        out[cmd] = vm.command(cmd, timeout=args.command_timeout)
    return out


def guest_workspace_setup(vm, count):
    cmd = (
        "rm -rf /workspace/template_{n} /workspace/run_{n}; "
        "mkdir -p /workspace/template_{n}; "
        "for i in $(seq 1 {n}); do echo needle-$i > /workspace/template_{n}/file_$i.txt; done; "
        "echo setup-{n}"
    ).format(n=count)
    return vm.command(cmd, timeout=max(20, count / 250.0))


def run_reset_bench(vm, args, fc=None, kernel=None, initrd=None, run_dir=None):
    out = {"guest_workspace_reset": {}, "reboot_existing_vm": {}, "kill_restore_reboot": {}}
    for n in args.workspace_sizes:
        setup = guest_workspace_setup(vm, n)
        samples = []
        clean = []
        reset_cmd = (
            "rm -rf /workspace/run_{n}; "
            "cp -a /workspace/template_{n} /workspace/run_{n}; "
            "test $(find /workspace/run_{n} -type f | wc -l) -eq {n}; "
            "grep -q needle-{n} /workspace/run_{n}/file_{n}.txt"
        ).format(n=n)
        for _ in range(args.reset_iters):
            r = vm.command(reset_cmd, timeout=max(20, n / 200.0))
            samples.append(r)
            clean.append(r["exit_code"] == 0)
        out["guest_workspace_reset"][str(n)] = {
            "setup": setup,
            "summary": summarize_command_results(samples),
            "clean_all_iterations": all(clean),
            "samples": samples,
        }
        if fc and kernel and initrd and run_dir:
            boot_samples = []
            for i in range(args.reset_iters):
                reset_vm = FirecrackerVM(
                    "reset-{}-{}".format(n, i), fc["path"], kernel["path"], initrd["image"],
                    run_dir, mem_mib=args.mem_mib, vcpus=args.vcpus
                )
                try:
                    t0 = now_ns()
                    boot = reset_vm.boot(timeout=args.boot_timeout)
                    clean = reset_vm.command(
                        "bash -lc 'test ! -e /workspace/run_{n}; test -f /workspace/small.txt; echo clean'".format(n=n),
                        timeout=args.command_timeout,
                    )
                    boot_samples.append({
                        "boot": boot,
                        "clean_check": clean,
                        "reset_to_clean_ready_ms": ms_since(t0),
                    })
                finally:
                    reset_vm.stop()
            out["kill_restore_reboot"][str(n)] = {
                "note": "Fresh Firecracker process plus fresh initramfs/root setup; validates clean guest state after previous VM dirtied a same-sized workspace.",
                "summary_ms": summarize([s["reset_to_clean_ready_ms"] for s in boot_samples]),
                "clean_all_iterations": all(s["clean_check"]["exit_code"] == 0 for s in boot_samples),
                "samples": boot_samples,
            }
    # A true in-place reboot exits Firecracker in this minimal harness.
    try:
        t0 = now_ns()
        r = vm.request_guest_poweroff(timeout=5)
        out["reboot_existing_vm"] = {
            "note": "In this minimal initramfs harness, in-place reboot-to-ready is not available. The measured value is guest shutdown acknowledgement plus harness termination.",
            "command_result": r,
            "elapsed_ms": ms_since(t0),
        }
    except Exception as exc:
        out["reboot_existing_vm"] = {"error": str(exc)}
    return out


def run_density(args, fc, kernel, initrd, run_dir):
    results = {}
    for count in args.density_counts:
        vms = []
        started = []
        failed = []
        t0 = now_ns()
        try:
            for i in range(count):
                vm = FirecrackerVM("density-{}-{}".format(count, i), fc["path"], kernel["path"],
                                   initrd["image"], run_dir, mem_mib=args.mem_mib, vcpus=args.vcpus)
                try:
                    boot = vm.boot(timeout=args.boot_timeout)
                    vms.append(vm)
                    started.append(boot)
                except Exception as exc:
                    failed.append({"index": i, "error": str(exc)})
                    vm.stop()
            startup_ms = ms_since(t0)
            rss_idle = [proc_rss_kb(vm.proc.pid) for vm in vms]
            command_samples = []
            for vm in vms:
                try:
                    command_samples.append(vm.command("bash -lc 'true'", timeout=args.command_timeout))
                except Exception as exc:
                    failed.append({"vm_id": vm.vm_id, "command_error": str(exc)})
            rss_active = [proc_rss_kb(vm.proc.pid) for vm in vms]
            results[str(count)] = {
                "requested_vms": count,
                "booted_vms": len(vms),
                "failed": failed,
                "boot_success_rate": len(vms) / float(count) if count else 0.0,
                "total_startup_ms": startup_ms,
                "rss_idle_kb": summarize([x for x in rss_idle if x is not None]),
                "rss_active_kb": summarize([x for x in rss_active if x is not None]),
                "warm_true_under_load": summarize_command_results(command_samples),
                "boot_to_ready_ms": summarize([b["boot_to_ready_ms"] for b in started]),
                "vmm_launch_ms": summarize([b["vmm_launch_ms"] for b in started]),
            }
            if failed:
                break
        finally:
            for vm in vms:
                vm.stop()
    return results


def run_snapshot_bench(args, fc, kernel, initrd, run_dir):
    out = {"attempted": True}
    vm = FirecrackerVM("snapshot-source", fc["path"], kernel["path"], initrd["image"], run_dir,
                       mem_mib=args.mem_mib, vcpus=args.vcpus)
    try:
        boot = vm.boot(timeout=args.boot_timeout)
        pause_t0 = now_ns()
        pause_resp = vm.pause()
        pause_ms = ms_since(pause_t0)
        snap_path = Path(run_dir) / "snapshot.vmstate"
        mem_path = Path(run_dir) / "snapshot.mem"
        snap_t0 = now_ns()
        snap_resp = vm.snapshot(snap_path, mem_path)
        snap_ms = ms_since(snap_t0)
        out.update({
            "source_boot": boot,
            "pause": pause_resp,
            "pause_ms": pause_ms,
            "snapshot": snap_resp,
            "snapshot_create_ms": snap_ms,
            "snapshot_path": str(snap_path),
            "snapshot_bytes": snap_path.stat().st_size if snap_path.exists() else None,
            "mem_path": str(mem_path),
            "mem_bytes": mem_path.stat().st_size if mem_path.exists() else None,
        })
        vm.stop()
        samples = []
        if snap_resp.get("http") == 204:
            for i in range(args.snapshot_iters):
                rvm = FirecrackerVM("snapshot-restore-{}".format(i), fc["path"], kernel["path"],
                                    initrd["image"], run_dir, mem_mib=args.mem_mib, vcpus=args.vcpus)
                try:
                    rvm.prepare_files()
                    # Snapshot load is pre-boot; only the process and API socket are needed.
                    launch_ms = rvm.start_process()
                    t_load = now_ns()
                    load_resp = rvm.load_snapshot(snap_path, mem_path, resume=True)
                    load_ms = ms_since(t_load)
                    cmd = rvm.command("bash -lc 'echo ready'", timeout=args.command_timeout)
                    samples.append({
                        "launch_ms": launch_ms,
                        "load_ms": load_ms,
                        "echo_ready": cmd,
                        "restore_to_command_done_ms": load_ms + cmd["elapsed_ms"],
                        "load_response": load_resp,
                    })
                finally:
                    rvm.stop()
        out["restore_samples"] = samples
        out["restore_to_command_done_ms"] = summarize([s["restore_to_command_done_ms"] for s in samples])
        out["load_ms"] = summarize([s["load_ms"] for s in samples])
    except Exception as exc:
        out["error"] = str(exc)
        try:
            vm.stop()
        except Exception:
            pass
    return out


def markdown_report(result):
    lines = []
    lines.append("# Firecracker LUMI Benchmark Report")
    lines.append("")
    lines.append("Generated: {}".format(time.strftime("%Y-%m-%d %H:%M:%S %Z")))
    lines.append("")
    host = result.get("host_before", {})
    lines.append("## Host")
    lines.append("")
    lines.append("- Node: `{}`".format(host.get("hostname")))
    lines.append("- Kernel: `{}`".format(host.get("uname")))
    lines.append("- CPU: `{}`".format(host.get("cpuinfo_model")))
    lines.append("- Logical CPUs visible: `{}`".format(host.get("cpu_count_logical")))
    mem = host.get("meminfo", {})
    if mem:
        lines.append("- MemTotal: `{:.1f} GiB`; MemAvailable before run: `{:.1f} GiB`".format(
            mem.get("MemTotal", 0) / 1024.0 / 1024.0,
            mem.get("MemAvailable", 0) / 1024.0 / 1024.0,
        ))
    lines.append("- SLURM: `{}`".format(json.dumps(host.get("slurm", {}), sort_keys=True)))
    lines.append("")
    lines.append("## Artifacts")
    lines.append("")
    fc = result.get("firecracker", {})
    kernel = result.get("kernel", {})
    initrd = result.get("initramfs", {})
    lines.append("- Firecracker: `{}` `{}`".format(fc.get("release"), fc.get("version")))
    lines.append("- Kernel: `{}` ({:.1f} MiB)".format(kernel.get("key"), kernel.get("bytes", 0) / 1024.0 / 1024.0))
    lines.append("- Guest root/initramfs: `{}` ({:.1f} MiB), build `{:.1f} ms`".format(
        initrd.get("image"), initrd.get("image_bytes", 0) / 1024.0 / 1024.0, initrd.get("build_ms", 0.0)
    ))
    lines.append("- Guest memory configured: `{} MiB`; vCPUs: `{}`".format(
        result.get("args", {}).get("mem_mib"), result.get("args", {}).get("vcpus")
    ))
    py = initrd.get("pytest", {})
    lines.append("- Pytest install in guest image: requested `{}`, installed `{}`, seconds `{}`".format(
        py.get("requested"), py.get("installed"), py.get("seconds")
    ))
    lines.append("")
    lines.append("## Cold VM Startup")
    lines.append("")
    cold = result.get("cold", [])
    if cold:
        lines.append("| metric | summary ms |")
        lines.append("|---|---:|")
        for key in ("vmm_launch_ms", "config_ms", "boot_to_ready_ms", "ready_to_first_command_ms", "instance_start_to_first_command_done_ms"):
            vals = [c.get(key) for c in cold if c.get(key) is not None]
            lines.append("| `{}` | `{}` |".format(key, json.dumps(summarize(vals), sort_keys=True)))
        rss = [c.get("rss_kb_after_ready") for c in cold if c.get("rss_kb_after_ready") is not None]
        lines.append("| `host_rss_after_ready_kb` | `{}` |".format(json.dumps(summarize(rss), sort_keys=True)))
        setup = [c.get("file_setup", {}).get("initrd_copy_ms") for c in cold]
        rootfs_setup = [c.get("file_setup", {}).get("rootfs_setup_ms") for c in cold]
        lines.append("| `initrd_copy_ms` | `{}` |".format(json.dumps(summarize(setup), sort_keys=True)))
        lines.append("| `dummy_rootfs_setup_ms` | `{}` |".format(json.dumps(summarize(rootfs_setup), sort_keys=True)))
        first_setup = cold[0].get("file_setup", {})
        lines.append("")
        lines.append("Root/initrd setup from first cold iteration: initrd `{}` bytes, dummy rootfs `{}` bytes.".format(
            first_setup.get("initrd_bytes"), first_setup.get("dummy_rootfs_bytes")
        ))
    lines.append("")
    lines.append("## Warm Command Latency")
    lines.append("")
    warm = result.get("warm", {})
    if warm:
        lines.append("| command | n | mean ms | p50 | p90 | p99 | RSS KB p50 | host CPU s mean | exits | first stdout | first stderr |")
        lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---|---|---|")
        for cmd, payload in warm.items():
            s = payload["summary"]["latency_ms"]
            rss = payload["summary"].get("rss_kb_after", {})
            cpu = payload["summary"].get("host_cpu_seconds_delta", {})
            lines.append("| `{}` | {} | {:.3f} | {:.3f} | {:.3f} | {:.3f} | {:.1f} | {:.6f} | `{}` | `{}` | `{}` |".format(
                cmd.replace("|", "\\|"),
                s.get("n", 0), s.get("mean", 0.0), s.get("p50", 0.0), s.get("p90", 0.0), s.get("p99", 0.0),
                rss.get("p50", 0.0), cpu.get("mean", 0.0),
                json.dumps(payload["summary"].get("exit_codes", {}), sort_keys=True),
                payload["summary"].get("first_stdout", "").replace("\n", "\\n")[:120],
                payload["summary"].get("first_stderr", "").replace("\n", "\\n")[:120],
            ))
    lines.append("")
    lines.append("## Security/Isolation Smoke")
    lines.append("")
    security = result.get("security", {})
    if security:
        lines.append("| command | exit | stdout excerpt | stderr excerpt |")
        lines.append("|---|---:|---|---|")
        for cmd, payload in security.items():
            lines.append("| `{}` | {} | `{}` | `{}` |".format(
                cmd.replace("|", "\\|"),
                payload.get("exit_code"),
                payload.get("stdout", "").replace("\n", "\\n")[:220],
                payload.get("stderr", "").replace("\n", "\\n")[:220],
            ))
    lines.append("")
    lines.append("## Reset")
    lines.append("")
    reset = result.get("reset", {})
    gwr = reset.get("guest_workspace_reset", {})
    if gwr:
        lines.append("| workspace files | n | mean ms | p50 | p90 | p99 | clean |")
        lines.append("|---:|---:|---:|---:|---:|---:|---|")
        for n, payload in sorted(gwr.items(), key=lambda kv: int(kv[0])):
            s = payload["summary"]["latency_ms"]
            lines.append("| {} | {} | {:.3f} | {:.3f} | {:.3f} | {:.3f} | `{}` |".format(
                n, s.get("n", 0), s.get("mean", 0.0), s.get("p50", 0.0), s.get("p90", 0.0), s.get("p99", 0.0),
                payload.get("clean_all_iterations"),
            ))
    if reset.get("reboot_existing_vm"):
        lines.append("")
        lines.append("Reboot existing VM: `{}`".format(json.dumps(reset.get("reboot_existing_vm"), sort_keys=True)[:1000]))
    krr = reset.get("kill_restore_reboot", {})
    if krr:
        lines.append("")
        lines.append("Kill VM + fresh restore/reboot:")
        lines.append("")
        lines.append("| workspace files | n | mean ms | p50 | p90 | p99 | clean |")
        lines.append("|---:|---:|---:|---:|---:|---:|---|")
        for n, payload in sorted(krr.items(), key=lambda kv: int(kv[0])):
            s = payload["summary_ms"]
            lines.append("| {} | {} | {:.3f} | {:.3f} | {:.3f} | {:.3f} | `{}` |".format(
                n, s.get("n", 0), s.get("mean", 0.0), s.get("p50", 0.0), s.get("p90", 0.0), s.get("p99", 0.0),
                payload.get("clean_all_iterations"),
            ))
    lines.append("")
    lines.append("## Parallel Density")
    lines.append("")
    density = result.get("density", {})
    if density:
        lines.append("| requested VMs | booted | success | total startup ms | idle RSS KB p50 | active RSS KB p50 | warm true p50/p99 ms |")
        lines.append("|---:|---:|---:|---:|---:|---:|---|")
        for count, payload in sorted(density.items(), key=lambda kv: int(kv[0])):
            idle = payload.get("rss_idle_kb", {})
            active = payload.get("rss_active_kb", {})
            warm_s = payload.get("warm_true_under_load", {}).get("latency_ms", {})
            lines.append("| {} | {} | {:.3f} | {:.1f} | {:.1f} | {:.1f} | {:.3f}/{:.3f} |".format(
                count, payload.get("booted_vms"), payload.get("boot_success_rate", 0.0),
                payload.get("total_startup_ms", 0.0), idle.get("p50", 0.0), active.get("p50", 0.0),
                warm_s.get("p50", 0.0), warm_s.get("p99", 0.0),
            ))
    lines.append("")
    lines.append("## Snapshot/Restore")
    lines.append("")
    snap = result.get("snapshot", {})
    if snap:
        lines.append("- Snapshot create HTTP: `{}`; create ms: `{}`".format(
            snap.get("snapshot", {}).get("http"), snap.get("snapshot_create_ms")
        ))
        lines.append("- Snapshot state bytes: `{}`; memory bytes: `{}`".format(
            snap.get("snapshot_bytes"), snap.get("mem_bytes")
        ))
        lines.append("- Restore load ms: `{}`".format(json.dumps(snap.get("load_ms", {}), sort_keys=True)))
        lines.append("- Restore to echo-ready command done ms: `{}`".format(
            json.dumps(snap.get("restore_to_command_done_ms", {}), sort_keys=True)
        ))
        if snap.get("error"):
            lines.append("- Error: `{}`".format(snap.get("error")))
    lines.append("")
    lines.append("## Limitations")
    lines.append("")
    lines.append("- Command channel is the emulated serial console. TUN/TAP was unavailable in the earlier LUMI probe, so SSH/network measurements are intentionally excluded.")
    lines.append("- The guest environment is a generated initramfs, not a full Ubuntu ext4 rootfs. Treat filesystem and pytest numbers as first-pass control-plane figures, not full distro boot figures.")
    lines.append("- Per-command CPU/RSS is host Firecracker-process CPU/RSS. Guest per-process CPU/RSS is not available from this serial-only harness.")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", default=None)
    ap.add_argument("--mem-mib", type=int, default=512)
    ap.add_argument("--vcpus", type=int, default=1)
    ap.add_argument("--cold-iters", type=int, default=5)
    ap.add_argument("--warm-iters", type=int, default=100)
    ap.add_argument("--noop-iters", type=int, default=1000)
    ap.add_argument("--reset-iters", type=int, default=20)
    ap.add_argument("--workspace-sizes", type=int, nargs="+", default=[10, 1000, 10000])
    ap.add_argument("--density-counts", type=int, nargs="+", default=[1, 10, 50, 100])
    ap.add_argument("--snapshot-iters", type=int, default=20)
    ap.add_argument("--boot-timeout", type=float, default=30.0)
    ap.add_argument("--command-timeout", type=float, default=30.0)
    ap.add_argument("--with-pytest", action="store_true")
    ap.add_argument("--skip-density", action="store_true")
    ap.add_argument("--skip-snapshot", action="store_true")
    args = ap.parse_args()

    run_dir = Path(args.run_dir or tempfile.mkdtemp(prefix="fc-bench-"))
    mkdir(run_dir)
    result = {"run_dir": str(run_dir), "args": vars(args), "host_before": host_snapshot()}
    cache = run_dir / "cache"
    try:
        fc = download_firecracker(cache)
        kernel = download_kernel(cache)
        initrd = build_initramfs(run_dir / "build", args.with_pytest)
        result["firecracker"] = fc
        result["kernel"] = kernel
        result["initramfs"] = initrd

        cold, warm_vm = run_cold_bench(args, fc, kernel, initrd, run_dir)
        result["cold"] = cold
        if warm_vm is None:
            raise RuntimeError("no warm VM was available after cold benchmark")
        result["warm"] = run_warm_bench(warm_vm, args)
        result["security"] = run_security_smoke(warm_vm, args)
        result["reset"] = run_reset_bench(warm_vm, args, fc=fc, kernel=kernel, initrd=initrd, run_dir=run_dir)
        warm_vm.stop()

        if not args.skip_density:
            result["density"] = run_density(args, fc, kernel, initrd, run_dir)
        if not args.skip_snapshot:
            result["snapshot"] = run_snapshot_bench(args, fc, kernel, initrd, run_dir)
    finally:
        result["host_after"] = host_snapshot()
        report_json = run_dir / "firecracker_lumi_bench_results.json"
        report_md = run_dir / "firecracker_lumi_bench_report.md"
        report_json.write_text(json.dumps(result, indent=2, sort_keys=True))
        report_md.write_text(markdown_report(result))
        print("RESULT_JSON={}".format(report_json))
        print("RESULT_MD={}".format(report_md))
        print(markdown_report(result))


if __name__ == "__main__":
    main()
