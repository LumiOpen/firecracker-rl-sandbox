#!/bin/bash
#SBATCH --job-name=fc-kvm-probe
#SBATCH --account=project_462001516
#SBATCH --partition=dev-g
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=2
#SBATCH --mem=1G
#SBATCH --time=00:02:00
#SBATCH --output=logs/%j.out
#SBATCH --error=logs/%j.err
#SBATCH --open-mode=append

set -uo pipefail

section() {
    printf '\n===== %s =====\n' "$1"
}

section "identity"
date -Ins
hostname
whoami
id
groups

section "kernel and cpu"
uname -a
if command -v lscpu >/dev/null 2>&1; then
    lscpu | grep -E '^(Architecture|CPU\\(s\\)|Vendor ID|Model name|Virtualization):' || true
fi
grep -E '(^flags|^Features)' /proc/cpuinfo | head -1 || true

section "kernel modules"
grep -E '^(kvm|kvm_amd|kvm_intel|tun) ' /proc/modules || true
for param in /sys/module/kvm_amd/parameters/nested /sys/module/kvm_intel/parameters/nested; do
    if [ -e "$param" ]; then
        printf '%s=' "$param"
        cat "$param"
    fi
done

section "device nodes"
for dev in /dev/kvm /dev/net/tun; do
    if [ -e "$dev" ]; then
        ls -l "$dev"
        stat -c '%n mode=%a owner=%U group=%G type=%F major_minor=%t:%T' "$dev"
    else
        printf '%s missing\n' "$dev"
    fi
done

section "kvm ioctls"
python3 - <<'PY'
import errno
import fcntl
import os

KVM_GET_API_VERSION = 0xAE00
KVM_CREATE_VM = 0xAE01

try:
    fd = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC)
except OSError as exc:
    print(f"open /dev/kvm O_RDWR: FAIL errno={exc.errno} {exc.strerror}")
    raise SystemExit(0)

print("open /dev/kvm O_RDWR: OK")
try:
    api_version = fcntl.ioctl(fd, KVM_GET_API_VERSION, 0)
    print(f"KVM_GET_API_VERSION: OK version={api_version}")
except OSError as exc:
    print(f"KVM_GET_API_VERSION: FAIL errno={exc.errno} {exc.strerror}")

try:
    vm_fd = fcntl.ioctl(fd, KVM_CREATE_VM, 0)
    print(f"KVM_CREATE_VM: OK vm_fd={vm_fd}")
    os.close(vm_fd)
except OSError as exc:
    print(f"KVM_CREATE_VM: FAIL errno={exc.errno} {exc.strerror}")

os.close(fd)
PY

section "tun tap capability"
if command -v ip >/dev/null 2>&1; then
    tap_name="fcp${SLURM_JOB_ID}"
    ip tuntap add dev "$tap_name" mode tap user "$USER"
    rc=$?
    printf 'ip tuntap add rc=%s\n' "$rc"
    if [ "$rc" -eq 0 ]; then
        ip link show "$tap_name" || true
        ip link delete "$tap_name" || true
    fi
else
    echo "ip command missing"
fi

section "capabilities"
if command -v capsh >/dev/null 2>&1; then
    capsh --print || true
else
    grep -E '^(CapInh|CapPrm|CapEff|CapBnd|CapAmb):' /proc/self/status || true
fi

section "firecracker binary availability"
command -v firecracker || true
command -v jailer || true
