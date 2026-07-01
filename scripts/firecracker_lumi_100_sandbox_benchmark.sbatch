#!/bin/bash
#SBATCH --job-name=fc-100bench
#SBATCH --account=project_462001516
#SBATCH --partition=dev-g
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=32
#SBATCH --mem=128G
#SBATCH --time=00:45:00
#SBATCH --output=logs/%j.out
#SBATCH --error=logs/%j.err
#SBATCH --open-mode=append

set -euo pipefail

PROJECT="${PROJECT:-project_462001516}"
BASE_ROOT="${BASE_ROOT:-/scratch/${PROJECT}/users/${USER}/firecracker-bench}"
SRC_ROOT="${SRC_ROOT:-${BASE_ROOT}/firecracker-rl-sandbox-src}"
RUN_ROOT="${RUN_ROOT:-${BASE_ROOT}/benchmark-100-${SLURM_JOB_ID}}"
RETURN_DIR="${RETURN_DIR:-${SRC_ROOT}/return/benchmark-100-sandbox}"
KERNEL_PATH="${KERNEL_PATH:-${BASE_ROOT}/kernels/linux-6.1.174-tun-19627901/vmlinux}"
FIRECRACKER_BIN="${FIRECRACKER_BIN:-${BASE_ROOT}/cache/firecracker/firecracker-v1.16.0-x86_64}"
ROOTFS_PATH="${ROOTFS_PATH:-${BASE_ROOT}/rootfs/ubuntu-24.04-phase5-production-comparator-v1-8215068d1c73bdfa/rootfs.ext4}"

mkdir -p "$RUN_ROOT" "$RETURN_DIR" logs reports

module load cray-python/3.11.7 || true
python3 --version

(ulimit -n 1048576 2>/dev/null || true)
export PYTHONDONTWRITEBYTECODE=1
export TMPDIR="/tmp/${USER}-fc-100bench-${SLURM_JOB_ID}"
mkdir -p "$TMPDIR"
trap 'rm -rf "$TMPDIR"' EXIT

cd "$SRC_ROOT"

PYTHONPATH="$SRC_ROOT:$SRC_ROOT/scripts" python3 scripts/firecracker_lumi_100_sandbox_benchmark.py \
  --firecracker "$FIRECRACKER_BIN" \
  --kernel "$KERNEL_PATH" \
  --rootfs "$ROOTFS_PATH" \
  --run-dir "$RUN_ROOT" \
  --return-dir "$RETURN_DIR" \
  --count "${FC_100_BENCH_COUNT:-100}" \
  --workers "${FC_100_BENCH_WORKERS:-100}" \
  --port "${FC_100_BENCH_PORT:-18766}" \
  --pool-id "${FC_100_BENCH_POOL_ID:-benchmark100}" \
  --mem-mib "${FC_100_BENCH_MEM_MIB:-768}" \
  --vcpus "${FC_100_BENCH_VCPUS:-1}"
