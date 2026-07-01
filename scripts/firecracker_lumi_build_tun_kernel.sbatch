#!/bin/bash
#SBATCH --job-name=fc-tun-kernel
#SBATCH --account=project_462001516
#SBATCH --partition=dev-g
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=32
#SBATCH --mem=64G
#SBATCH --time=02:00:00
#SBATCH --output=logs/%j.out
#SBATCH --error=logs/%j.err
#SBATCH --open-mode=append

set -euo pipefail

LUMI_PROJECT="${LUMI_PROJECT:-project_462001516}"
BASE_ROOT="${BASE_ROOT:-/scratch/${LUMI_PROJECT}/users/${USER}/firecracker-bench}"
LINUX_VERSION="${LINUX_VERSION:-6.1.174}"
KERNEL_CONFIG_URL="${KERNEL_CONFIG_URL:-https://raw.githubusercontent.com/firecracker-microvm/firecracker/main/resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config}"
OUT_ROOT="${OUT_ROOT:-${BASE_ROOT}/kernels/linux-${LINUX_VERSION}-tun-${SLURM_JOB_ID}}"
CACHE_ROOT="${CACHE_ROOT:-${BASE_ROOT}/kernel-cache}"
TMP_ROOT="${TMP_ROOT:-/tmp/${USER}-fc-tun-kernel-${SLURM_JOB_ID}}"

mkdir -p "$OUT_ROOT" "$CACHE_ROOT" logs
rm -rf "$TMP_ROOT"
mkdir -p "$TMP_ROOT"
trap 'rm -rf "$TMP_ROOT"' EXIT

echo "job=${SLURM_JOB_ID}"
echo "node=$(hostname)"
echo "linux_version=${LINUX_VERSION}"
echo "out_root=${OUT_ROOT}"
echo "tmp_root=${TMP_ROOT}"
echo "cpus=${SLURM_CPUS_PER_TASK:-1}"
gcc --version | head -1
make --version | head -1

for cmd in gcc make curl tar xz bc flex bison openssl pahole perl python3; do
  command -v "$cmd" >/dev/null
done

tarball="${CACHE_ROOT}/linux-${LINUX_VERSION}.tar.xz"
if [[ ! -s "$tarball" ]]; then
  curl -fsSL -o "${tarball}.tmp" "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${LINUX_VERSION}.tar.xz"
  mv "${tarball}.tmp" "$tarball"
fi

config_in="${CACHE_ROOT}/microvm-kernel-ci-x86_64-6.1.config"
curl -fsSL -o "${config_in}.tmp" "$KERNEL_CONFIG_URL"
mv "${config_in}.tmp" "$config_in"

tar -xf "$tarball" -C "$TMP_ROOT"
src="${TMP_ROOT}/linux-${LINUX_VERSION}"
build="${TMP_ROOT}/build"
mkdir -p "$build"
cp "$config_in" "${build}/.config"

"${src}/scripts/config" --file "${build}/.config" \
  --enable TUN \
  --enable NET_INGRESS \
  --enable NET_EGRESS \
  --disable DEBUG_INFO_BTF \
  --set-str SYSTEM_TRUSTED_KEYS "" \
  --set-str SYSTEM_REVOCATION_KEYS ""

make -C "$src" O="$build" olddefconfig
grep -E 'CONFIG_TUN=|CONFIG_VSOCKETS=|CONFIG_VIRTIO_VSOCKETS=|CONFIG_VIRTIO_MMIO=' "${build}/.config"

make -C "$src" O="$build" -j"${SLURM_CPUS_PER_TASK:-1}" vmlinux

cp "${build}/vmlinux" "${OUT_ROOT}/vmlinux"
cp "${build}/.config" "${OUT_ROOT}/config"
cp "${build}/System.map" "${OUT_ROOT}/System.map"
make --no-print-directory -C "$src" O="$build" kernelrelease > "${OUT_ROOT}/kernelrelease"
sha256sum "${OUT_ROOT}/vmlinux" > "${OUT_ROOT}/vmlinux.sha256"

cat > "${OUT_ROOT}/README.md" <<EOF
# Firecracker TUN Guest Kernel

- Job: ${SLURM_JOB_ID}
- Node: $(hostname)
- Source: Linux ${LINUX_VERSION}
- Base config: ${KERNEL_CONFIG_URL}
- Important delta: CONFIG_TUN=y

Use with:

\`\`\`bash
FC_NET_POC_KERNEL_PATH=${OUT_ROOT}/vmlinux sbatch scripts/firecracker_lumi_net_poc.sbatch
\`\`\`
EOF

ls -lh "$OUT_ROOT"
