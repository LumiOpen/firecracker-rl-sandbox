#!/usr/bin/env python3
import argparse
import json
import os
import queue
import shlex
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from firecracker_lumi_bench import (
    FirecrackerVM,
    build_initramfs,
    copy_binary_with_libs,
    download_firecracker,
    download_kernel,
    host_snapshot,
    link_or_copy,
    mkdir,
    ms_since,
    now_ns,
    proc_rss_kb,
    read_text,
    run,
)


GVTAP_VERSION = "v0.8.9"
GVTAP_BASE = "https://github.com/containers/gvisor-tap-vsock/releases/download"


def log(message):
    print("[{}] {}".format(time.strftime("%Y-%m-%d %H:%M:%S"), message), flush=True)


def compact_command(result, max_excerpt=4000):
    out = {}
    for key in ("cmd", "elapsed_ms", "exit_code", "rss_kb_before", "rss_kb_after", "host_cpu_seconds_delta"):
        out[key] = result.get(key)
    stdout = result.get("stdout", "") or ""
    stderr = result.get("stderr", "") or ""
    out.update({
        "stdout_chars": len(stdout),
        "stderr_chars": len(stderr),
        "stdout_excerpt": stdout[:max_excerpt],
        "stderr_excerpt": stderr[:max_excerpt],
    })
    if len(stdout) > max_excerpt:
        out["stdout_suffix"] = stdout[-max_excerpt:]
    if len(stderr) > max_excerpt:
        out["stderr_suffix"] = stderr[-max_excerpt:]
    return out


def compact_error(exc):
    return {
        "type": exc.__class__.__name__,
        "error": str(exc),
    }


def download_file(url, path):
    path = Path(path)
    if not path.exists():
        tmp = path.with_suffix(path.suffix + ".tmp")
        run(["curl", "-fsSL", "-o", str(tmp), url])
        tmp.rename(path)
    path.chmod(0o755)
    return str(path)


def download_gvisor_tap_vsock(cache_dir, version=GVTAP_VERSION):
    cache_dir = Path(cache_dir)
    mkdir(cache_dir)
    gvproxy = cache_dir / "gvproxy-linux-amd64-{}".format(version)
    gvforwarder = cache_dir / "gvforwarder-{}".format(version)
    download_file("{}/{}/gvproxy-linux-amd64".format(GVTAP_BASE, version), gvproxy)
    download_file("{}/{}/gvforwarder".format(GVTAP_BASE, version), gvforwarder)
    return {
        "version": version,
        "gvproxy": str(gvproxy),
        "gvforwarder": str(gvforwarder),
    }


def repack_initramfs(initrd, extra_guest_binaries):
    root = Path(initrd["root"])
    copied = []
    for name in ("ip", "ss"):
        path = shutil.which(name)
        if path:
            try:
                copied.append(copy_binary_with_libs(path, root))
            except Exception as exc:
                copied.append("MISSING {}: {}".format(name, exc))
    for src, dest in extra_guest_binaries:
        dest_path = root / dest.lstrip("/")
        mkdir(dest_path.parent)
        shutil.copy2(str(src), str(dest_path))
        dest_path.chmod(0o755)
        copied.append("{} -> /{}".format(src, dest_path.relative_to(root)))

    image = Path(initrd["image"])
    if image.exists():
        image.unlink()
    t0 = now_ns()
    cmd = "cd '{}' && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1 > '{}'".format(
        str(root), str(image)
    )
    run(["bash", "-lc", cmd])
    initrd["image_bytes"] = image.stat().st_size
    initrd["net_poc_repack_ms"] = ms_since(t0)
    initrd["net_poc_extra_binaries"] = copied
    return initrd


class VsockFirecrackerVM(FirecrackerVM):
    def __init__(self, *args, guest_cid=3, **kwargs):
        super(VsockFirecrackerVM, self).__init__(*args, **kwargs)
        self.guest_cid = guest_cid
        self.vsock_uds = self.dir / "v.sock"

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
        api_records.append(self.api("PUT", "/vsock", {
            "guest_cid": self.guest_cid,
            "uds_path": str(self.vsock_uds),
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
            "vsock": {
                "guest_cid": self.guest_cid,
                "uds_path": str(self.vsock_uds),
            },
        }


class OneShotHTTPServer(threading.Thread):
    def __init__(self, host="127.0.0.1", port=18080):
        super(OneShotHTTPServer, self).__init__()
        self.daemon = True
        self.host = host
        self.port = port
        self.ready = threading.Event()
        self.done = threading.Event()
        self.error = None
        self.request = b""

    def run(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((self.host, self.port))
                s.listen(1)
                self.ready.set()
                s.settimeout(20)
                conn, _ = s.accept()
                with conn:
                    conn.settimeout(5)
                    try:
                        self.request = conn.recv(4096)
                    except socket.timeout:
                        self.request = b""
                    body = b"gvisor-tap-vsock-host-ok\n"
                    conn.sendall(
                        b"HTTP/1.0 200 OK\r\nContent-Length: "
                        + str(len(body)).encode("ascii")
                        + b"\r\nConnection: close\r\n\r\n"
                        + body
                    )
        except Exception as exc:
            self.error = compact_error(exc)
        finally:
            self.done.set()


class HostVsockEcho(threading.Thread):
    def __init__(self, path):
        super(HostVsockEcho, self).__init__()
        self.daemon = True
        self.path = Path(path)
        self.ready = threading.Event()
        self.done = threading.Event()
        self.error = None
        self.received = b""

    def run(self):
        try:
            if self.path.exists():
                self.path.unlink()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.bind(str(self.path))
                s.listen(1)
                self.ready.set()
                s.settimeout(20)
                conn, _ = s.accept()
                with conn:
                    self.received = conn.recv(4096)
                    conn.sendall(b"host-echo:" + self.received)
        except Exception as exc:
            self.error = compact_error(exc)
        finally:
            self.done.set()


def start_gvproxy(gvproxy_path, listen_sock, services_sock, log_path):
    for path in (listen_sock, services_sock):
        p = Path(path)
        if p.exists():
            p.unlink()
    cmd = [
        gvproxy_path,
        "-debug",
        "-mtu", "1500",
        "-listen", "unix://{}".format(listen_sock),
        "-services", "unix://{}".format(services_sock),
        "-log-file", str(log_path),
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    deadline = time.time() + 10
    while time.time() < deadline:
        if Path(listen_sock).exists():
            return proc
        if proc.poll() is not None:
            out, err = proc.communicate(timeout=2)
            raise RuntimeError("gvproxy exited rc={} stdout={} stderr={} log={}".format(
                proc.returncode, out, err, read_text(log_path)[-4000:]
            ))
        time.sleep(0.05)
    raise RuntimeError("timed out waiting for gvproxy listener {}".format(listen_sock))


def stop_proc(proc):
    if proc is None:
        return
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
            proc.wait(timeout=5)


def run_guest_to_host_vsock_test(vm):
    host_sock = "{}_{}".format(vm.vsock_uds, 2020)
    echo = HostVsockEcho(host_sock)
    echo.start()
    if not echo.ready.wait(timeout=10):
        return {"status": "fail", "error": "host echo listener did not become ready"}
    cmd = (
        "python3 -c 'import socket; "
        "s=socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM); "
        "s.settimeout(5); s.connect((2,2020)); "
        "s.sendall(b\"guest-ping\"); "
        "print(s.recv(200).decode(\"utf-8\", \"replace\")); s.close()'"
    )
    result = compact_command(vm.command(cmd, timeout=10))
    echo.done.wait(timeout=5)
    return {
        "status": "pass" if result.get("exit_code") == 0 and "host-echo:guest-ping" in result.get("stdout_excerpt", "") else "fail",
        "command": result,
        "host_received": echo.received.decode("utf-8", "replace"),
        "host_error": echo.error,
        "host_sock": host_sock,
    }


def run_tun_probe(vm):
    py = (
        "import os,fcntl,struct,stat\n"
        "os.makedirs('/dev/net',exist_ok=True)\n"
        "p='/dev/net/tun'\n"
        "if not os.path.exists(p): os.mknod(p,stat.S_IFCHR|0o666,os.makedev(10,200))\n"
        "TUNSETIFF=0x400454ca; IFF_TUN=0x0001; IFF_TAP=0x0002; IFF_NO_PI=0x1000\n"
        "for name,flag in [('tunpoc0',IFF_TUN),('tappoc0',IFF_TAP)]:\n"
        "    fd=os.open('/dev/net/tun',os.O_RDWR)\n"
        "    ifr=struct.pack('16sH',name.encode(),flag|IFF_NO_PI)\n"
        "    res=fcntl.ioctl(fd,TUNSETIFF,ifr)\n"
        "    print(name,res[:16].split(b'\\0',1)[0].decode())\n"
        "    os.close(fd)\n"
    )
    cmd = "python3 -c {}".format(shlex.quote("exec({!r})".format(py)))
    result = compact_command(vm.command(cmd, timeout=10))
    inspect = compact_command(vm.command("bash -lc 'ls -l /dev/net /dev/net/tun 2>&1; command -v ip || true; ip link show 2>&1 | sed -n \"1,80p\"'", timeout=10))
    return {
        "status": "pass" if result.get("exit_code") == 0 else "fail",
        "create": result,
        "inspect": inspect,
    }


def run_gvisor_tap_vsock_test(vm, tools, run_dir):
    listen_sock = "{}_{}".format(vm.vsock_uds, 1024)
    services_sock = str(Path(run_dir) / "gvproxy-services.sock")
    gvlog = Path(run_dir) / "gvproxy.log"
    gvproxy = None
    server = None
    try:
        gvproxy = start_gvproxy(tools["gvproxy"], listen_sock, services_sock, gvlog)
        make_tun = (
            "python3 -c "
            + shlex.quote(
                "import os,stat; "
                "os.makedirs('/dev/net',exist_ok=True); "
                "p='/dev/net/tun'; "
                "os.path.exists(p) or os.mknod(p,stat.S_IFCHR|0o666,os.makedev(10,200))"
            )
        )
        setup_cmd = (
            "set -e; "
            "{}; "
            "ip tuntap del dev tap0 mode tap 2>/dev/null || true; "
            "ip tuntap add dev tap0 mode tap; "
            "ip addr add 192.168.127.2/24 dev tap0; "
            "ip link set tap0 up; "
            "ip route replace default via 192.168.127.1 dev tap0; "
            "/usr/bin/gvforwarder -debug -url vsock://2:1024/connect -iface tap0 -preexisting -mtu 1500 >/tmp/gvforwarder.log 2>&1 & "
            "echo $! >/tmp/gvforwarder.pid; "
            "sleep 2; "
            "cat /tmp/gvforwarder.log; "
            "echo --ip--; ip addr show tap0; echo --route--; ip route"
        ).format(make_tun)
        setup = compact_command(vm.command(setup_cmd, timeout=20))
        server = OneShotHTTPServer(port=18080)
        server.start()
        if not server.ready.wait(timeout=5):
            raise RuntimeError("host HTTP server did not become ready")
        http_cmd = (
            "python3 -c 'import socket; "
            "s=socket.create_connection((\"192.168.127.254\",18080),timeout=8); "
            "s.sendall(b\"GET / HTTP/1.0\\r\\nHost: host.local\\r\\n\\r\\n\"); "
            "print(s.recv(200).decode(\"utf-8\", \"replace\")); s.close()'"
        )
        host_http = compact_command(vm.command(http_cmd, timeout=15))
        server.done.wait(timeout=5)
        internet_cmd = (
            "python3 -c 'import socket; "
            "s=socket.create_connection((\"1.1.1.1\",80),timeout=8); "
            "s.sendall(b\"GET / HTTP/1.0\\r\\nHost: one.one.one.one\\r\\n\\r\\n\"); "
            "print(s.recv(120).decode(\"utf-8\", \"replace\")); s.close()'"
        )
        internet_http = compact_command(vm.command(internet_cmd, timeout=15))
        stats = run(["curl", "-sS", "--unix-socket", services_sock, "http:/unix/stats"], check=False)
        return {
            "status": "pass" if host_http.get("exit_code") == 0 and "gvisor-tap-vsock-host-ok" in host_http.get("stdout_excerpt", "") else "fail",
            "listen_sock": listen_sock,
            "services_sock": services_sock,
            "setup": setup,
            "host_virtual_ip_http": host_http,
            "internet_http": internet_http,
            "host_server_error": server.error if server else None,
            "host_server_request": (server.request.decode("utf-8", "replace") if server and server.request else ""),
            "gvproxy_stats": {
                "returncode": stats.returncode,
                "stdout": stats.stdout[:4000],
                "stderr": stats.stderr[:4000],
            },
            "gvproxy_log_tail": read_text(gvlog)[-8000:],
        }
    except Exception as exc:
        return {
            "status": "fail",
            "error": compact_error(exc),
            "gvproxy_log_tail": read_text(gvlog)[-8000:],
        }
    finally:
        stop_proc(gvproxy)


def write_reports(result, job_id):
    reports_dir = Path("reports")
    mkdir(reports_dir)
    stem = reports_dir / "firecracker-lumi-net-poc-{}".format(job_id)
    json_path = stem.with_suffix(".json")
    md_path = stem.with_suffix(".md")
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True))
    lines = [
        "# Firecracker LUMI VSOCK Transparent Networking PoC",
        "",
        "- Job: `{}`".format(job_id),
        "- Node: `{}`".format(result.get("host_before", {}).get("hostname")),
        "- Run dir: `{}`".format(result.get("run_dir")),
        "- Firecracker: `{}`".format(result.get("firecracker", {}).get("version")),
        "- Initramfs bytes: `{}`".format(result.get("initramfs", {}).get("image_bytes")),
        "",
        "## Results",
        "",
        "| test | status | key evidence |",
        "|---|---|---|",
    ]
    primitive = result.get("primitive", {})
    lines.append("| guest to host vsock | `{}` | `{}` |".format(
        primitive.get("guest_to_host_vsock", {}).get("status"),
        (primitive.get("guest_to_host_vsock", {}).get("command", {}).get("stdout_excerpt") or "").replace("\n", "\\n")[:160],
    ))
    lines.append("| guest TUN/TAP creation | `{}` | `{}` |".format(
        primitive.get("tun_probe", {}).get("status"),
        (primitive.get("tun_probe", {}).get("create", {}).get("stdout_excerpt") or "").replace("\n", "\\n")[:160],
    ))
    gvtap = result.get("gvisor_tap_vsock", {})
    lines.append("| gvisor-tap-vsock host virtual IP HTTP | `{}` | `{}` |".format(
        gvtap.get("status"),
        (gvtap.get("host_virtual_ip_http", {}).get("stdout_excerpt") or gvtap.get("error", {}).get("error", "") or "").replace("\n", "\\n")[:200],
    ))
    if gvtap.get("internet_http"):
        lines.append("| gvisor-tap-vsock internet direct-IP HTTP | `{}` | `{}` |".format(
            "pass" if gvtap.get("internet_http", {}).get("exit_code") == 0 else "fail",
            (gvtap.get("internet_http", {}).get("stdout_excerpt") or gvtap.get("internet_http", {}).get("stderr_excerpt") or "").replace("\n", "\\n")[:200],
        ))
    lines.extend([
        "",
        "## Notes",
        "",
        "- This run intentionally avoids DHCP by preconfiguring `tap0` in the guest and running `gvforwarder -preexisting`.",
        "- The host virtual-IP test targets `192.168.127.254`, which `gvproxy` maps to host `127.0.0.1` by default.",
        "- Fine-grained egress policy is not implemented in `gvisor-tap-vsock`; this is a transparency/transport baseline.",
    ])
    md_path.write_text("\n".join(lines) + "\n")
    return {"json": str(json_path), "markdown": str(md_path)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--mem-mib", type=int, default=512)
    ap.add_argument("--vcpus", type=int, default=1)
    ap.add_argument("--boot-timeout", type=float, default=45)
    ap.add_argument("--gvtap-version", default=GVTAP_VERSION)
    ap.add_argument("--kernel-path", help="Use an existing Firecracker guest kernel instead of downloading the CI kernel")
    args = ap.parse_args()

    run_dir = Path(args.run_dir)
    mkdir(run_dir)
    cache_dir = run_dir / "cache"
    result = {
        "run_dir": str(run_dir),
        "args": vars(args),
        "host_before": host_snapshot(),
        "host_capabilities": {
            "dev_kvm": os.access("/dev/kvm", os.R_OK | os.W_OK),
            "dev_vhost_vsock": os.access("/dev/vhost-vsock", os.R_OK | os.W_OK),
            "dev_net_tun": os.access("/dev/net/tun", os.R_OK | os.W_OK),
            "host_python_af_vsock": hasattr(socket, "AF_VSOCK"),
            "modules": run(["bash", "-lc", "lsmod | egrep 'kvm|vsock|tun|tap|vhost' || true"], check=False).stdout,
        },
    }
    vm = None
    try:
        log("downloading Firecracker/kernel/gvisor-tap-vsock")
        fc = download_firecracker(cache_dir)
        if args.kernel_path:
            kernel_path = Path(args.kernel_path)
            kernel = {
                "path": str(kernel_path),
                "key": "provided",
                "bytes": kernel_path.stat().st_size,
            }
        else:
            kernel = download_kernel(cache_dir)
        tools = download_gvisor_tap_vsock(cache_dir, args.gvtap_version)
        result["firecracker"] = fc
        result["kernel"] = kernel
        result["gvisor_tap_vsock_tools"] = tools

        log("building initramfs")
        initrd = build_initramfs(run_dir / "build", with_pytest=False)
        initrd = repack_initramfs(initrd, [(tools["gvforwarder"], "/usr/bin/gvforwarder")])
        result["initramfs"] = initrd

        log("booting vsock-enabled VM")
        vm = VsockFirecrackerVM("net-poc", fc["path"], kernel["path"], initrd["image"], run_dir,
                                mem_mib=args.mem_mib, vcpus=args.vcpus)
        boot = vm.boot(timeout=args.boot_timeout)
        result["boot"] = boot

        result["primitive"] = {}
        log("testing guest initiated vsock")
        result["primitive"]["guest_to_host_vsock"] = run_guest_to_host_vsock_test(vm)
        log("testing guest TUN/TAP creation")
        result["primitive"]["tun_probe"] = run_tun_probe(vm)
        log("testing gvisor-tap-vsock transparent path")
        result["gvisor_tap_vsock"] = run_gvisor_tap_vsock_test(vm, tools, run_dir)
    except Exception as exc:
        result.setdefault("errors", []).append(compact_error(exc))
    finally:
        if vm is not None:
            vm.stop()
        result["host_after"] = host_snapshot()
        result["reports"] = write_reports(result, os.environ.get("SLURM_JOB_ID", "local"))
        print(json.dumps({
            "reports": result["reports"],
            "primitive_status": result.get("primitive", {}),
            "gvisor_tap_vsock_status": result.get("gvisor_tap_vsock", {}).get("status"),
        }, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
