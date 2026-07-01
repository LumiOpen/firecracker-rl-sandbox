#!/bin/bash
#SBATCH --job-name=fc-phase10
#SBATCH --account=project_462001516
#SBATCH --partition=dev-g
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=16
#SBATCH --mem=64G
#SBATCH --time=00:30:00
#SBATCH --output=logs/%j.out
#SBATCH --error=logs/%j.err
#SBATCH --open-mode=append

set -euo pipefail

PROJECT="${PROJECT:-project_462001516}"
BASE_ROOT="${BASE_ROOT:-/scratch/${PROJECT}/users/${USER}/firecracker-bench}"
SRC_ROOT="${SRC_ROOT:-${BASE_ROOT}/phase10-src-2026-07-01}"
RUN_ROOT="${RUN_ROOT:-${BASE_ROOT}/p10-${SLURM_JOB_ID}}"
ARTIFACT_CACHE_DIR="${ARTIFACT_CACHE_DIR:-${BASE_ROOT}/cache}"
ROOTFS_CACHE_DIR="${ROOTFS_CACHE_DIR:-${BASE_ROOT}/rootfs}"
PHASE6_MVP_DIR="${PHASE6_MVP_DIR:-${SRC_ROOT}/handoff/2026-06-30-firecracker-lumi-phase6-mvp-backend}"
RETURN_DIR="${RETURN_DIR:-${SRC_ROOT}/return/2026-07-01-firecracker-lumi-phase10-service-hardening-status}"
KERNEL_PATH="${KERNEL_PATH:-${BASE_ROOT}/kernels/linux-6.1.174-tun-19627901/vmlinux}"

mkdir -p "$RUN_ROOT" "$ARTIFACT_CACHE_DIR" "$ROOTFS_CACHE_DIR" "$RETURN_DIR" logs reports

module load cray-python/3.11.7 || true
python3 --version

export PYTHONDONTWRITEBYTECODE=1
export TMPDIR="/tmp/${USER}-fc-phase10-${SLURM_JOB_ID}"
mkdir -p "$TMPDIR"
trap 'rm -rf "$TMPDIR"' EXIT

cd "$SRC_ROOT"

PYTHONPATH=scripts python3 scripts/firecracker_lumi_phase10_service_smoke.py \
  --run-dir "$RUN_ROOT" \
  --kernel-path "$KERNEL_PATH" \
  --artifact-cache-dir "$ARTIFACT_CACHE_DIR" \
  --rootfs-cache-dir "$ROOTFS_CACHE_DIR" \
  --phase6-mvp-dir "$PHASE6_MVP_DIR" \
  --return-dir "$RETURN_DIR" \
  --mem-mib "${FC_PHASE10_MEM_MIB:-768}" \
  --vcpus "${FC_PHASE10_VCPUS:-1}" \
  --pool-size "${FC_PHASE10_POOL_SIZE:-2}"
