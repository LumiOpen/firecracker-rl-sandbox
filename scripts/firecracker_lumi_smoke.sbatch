#!/bin/bash
#SBATCH --job-name=fc-smoke
#SBATCH --account=project_462001516
#SBATCH --partition=dev-g
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=2
#SBATCH --mem=2G
#SBATCH --time=00:10:00
#SBATCH --output=logs/%j.out
#SBATCH --error=logs/%j.err
#SBATCH --open-mode=append

set -euo pipefail

section() {
    printf '\n===== %s =====\n' "$1"
}

section "host"
date -Ins
hostname
id
uname -a

workdir="/tmp/firecracker-smoke-${SLURM_JOB_ID}"
mkdir -p "$workdir"
cd "$workdir"

section "download firecracker"
arch="$(uname -m)"
release_url="https://github.com/firecracker-microvm/firecracker/releases"
latest="$(basename "$(curl -fsSLI -o /dev/null -w '%{url_effective}' "${release_url}/latest")")"
echo "latest=${latest}"
curl -fsSL "${release_url}/download/${latest}/firecracker-${latest}-${arch}.tgz" | tar -xz
mv "release-${latest}-${arch}/firecracker-${latest}-${arch}" ./firecracker
chmod +x ./firecracker
./firecracker --version

section "download kernel"
s3="https://s3.amazonaws.com/spec.ccfc.min"
ci_prefix="$(curl -fsSL "${s3}?list-type=2&prefix=firecracker-ci/&delimiter=/" \
    | grep -oP '(?<=<Prefix>)firecracker-ci/[0-9]{8}-[^/]+/(?=</Prefix>)' \
    | sort \
    | tail -1)"
kernel_key="$(curl -fsSL "${s3}?list-type=2&prefix=${ci_prefix}${arch}/vmlinux-" \
    | grep -oP "(?<=<Key>)(${ci_prefix}${arch}/vmlinux-[0-9]+\\.[0-9]+\\.[0-9]{1,3})(?=</Key>)" \
    | sort -V \
    | tail -1)"
echo "kernel_key=${kernel_key}"
curl -fsSLO "${s3}/${kernel_key}"
kernel="./$(basename "$kernel_key")"
ls -lh "$kernel"

section "make empty rootfs"
truncate -s 64M rootfs.ext4
if command -v mkfs.ext4 >/dev/null 2>&1; then
    mkfs.ext4 -F rootfs.ext4 >/tmp/mkfs-${SLURM_JOB_ID}.log 2>&1
    tail -20 /tmp/mkfs-${SLURM_JOB_ID}.log
else
    echo "mkfs.ext4 missing; using sparse zero file"
fi
ls -lh rootfs.ext4

section "start firecracker"
api_socket="/tmp/firecracker-${SLURM_JOB_ID}.socket"
logfile="${workdir}/firecracker.log"
rm -f "$api_socket"
./firecracker --api-sock "$api_socket" >firecracker.stdout 2>firecracker.stderr &
fc_pid=$!
echo "firecracker_pid=${fc_pid}"

for _ in $(seq 1 50); do
    if [ -S "$api_socket" ]; then
        break
    fi
    sleep 0.1
done
if [ ! -S "$api_socket" ]; then
    echo "API socket was not created"
    cat firecracker.stdout || true
    cat firecracker.stderr || true
    exit 1
fi

request() {
    local method="$1"
    local path="$2"
    local data="$3"
    printf '\n-- %s %s --\n' "$method" "$path"
    curl -sS --unix-socket "$api_socket" \
        -X "$method" \
        -H 'Accept: application/json' \
        -H 'Content-Type: application/json' \
        -d "$data" \
        -w '\nHTTP %{http_code}\n' \
        "http://localhost${path}"
}

request PUT /logger "{
  \"log_path\": \"${logfile}\",
  \"level\": \"Debug\",
  \"show_level\": true,
  \"show_log_origin\": true
}"

request PUT /boot-source "{
  \"kernel_image_path\": \"${kernel}\",
  \"boot_args\": \"console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda\"
}"

request PUT /drives/rootfs "{
  \"drive_id\": \"rootfs\",
  \"path_on_host\": \"${workdir}/rootfs.ext4\",
  \"is_root_device\": true,
  \"is_read_only\": false
}"

request PUT /actions '{
  "action_type": "InstanceStart"
}'

sleep 5
if kill -0 "$fc_pid" 2>/dev/null; then
    echo "firecracker_process=running_after_5s"
    kill "$fc_pid" || true
    wait "$fc_pid" || true
else
    echo "firecracker_process=exited"
    wait "$fc_pid" || true
fi

section "firecracker logs"
sed -n '1,220p' "$logfile" || true
section "firecracker stderr"
sed -n '1,120p' firecracker.stderr || true
