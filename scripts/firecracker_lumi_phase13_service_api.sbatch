#!/bin/bash
#SBATCH --job-name=fc-phase13
#SBATCH --account=project_462001516
#SBATCH --partition=dev-g
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=16
#SBATCH --mem=64G
#SBATCH --time=00:45:00
#SBATCH --output=logs/%j.out
#SBATCH --error=logs/%j.err
#SBATCH --open-mode=append

set -euo pipefail

PROJECT="${PROJECT:-project_462001516}"
BASE_ROOT="${BASE_ROOT:-/scratch/${PROJECT}/users/${USER}/firecracker-bench}"
SRC_ROOT="${SRC_ROOT:-${BASE_ROOT}/phase13-src-2026-07-01}"
RUN_ROOT="${RUN_ROOT:-${BASE_ROOT}/p13-${SLURM_JOB_ID}}"
RETURN_DIR="${RETURN_DIR:-${SRC_ROOT}/return/2026-07-01-firecracker-lumi-phase13-service-api}"
KERNEL_PATH="${KERNEL_PATH:-${BASE_ROOT}/kernels/linux-6.1.174-tun-19627901/vmlinux}"
FIRECRACKER_BIN="${FIRECRACKER_BIN:-${BASE_ROOT}/cache/firecracker-v1.16.0-x86_64}"
ROOTFS_PATH="${ROOTFS_PATH:-${BASE_ROOT}/rootfs/ubuntu-24.04-phase5-production-comparator-v1-8215068d1c73bdfa/rootfs.ext4}"

mkdir -p "$RUN_ROOT" "$RETURN_DIR" logs reports

module load cray-python/3.11.7 || true
python3 --version

ulimit -n 1048576 || true
export PYTHONDONTWRITEBYTECODE=1
export TMPDIR="/tmp/${USER}-fc-phase13-${SLURM_JOB_ID}"
mkdir -p "$TMPDIR"
trap 'rm -rf "$TMPDIR"' EXIT

cd "$SRC_ROOT"

PYTHONPATH="$SRC_ROOT:$SRC_ROOT/scripts" python3 scripts/firecracker_lumi_phase13_service_api.py \
  --firecracker "$FIRECRACKER_BIN" \
  --kernel "$KERNEL_PATH" \
  --rootfs "$ROOTFS_PATH" \
  --run-dir "$RUN_ROOT" \
  --return-dir "$RETURN_DIR" \
  --port "${FC_PHASE13_PORT:-18765}" \
  --pool-id "${FC_PHASE13_POOL_ID:-phase13}" \
  --pool-size "${FC_PHASE13_POOL_SIZE:-2}" \
  --mem-mib "${FC_PHASE13_MEM_MIB:-768}" \
  --vcpus "${FC_PHASE13_VCPUS:-1}"
