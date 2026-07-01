#!/bin/bash
#SBATCH --job-name=fc-phase8
#SBATCH --account=project_462001516
#SBATCH --partition=dev-g
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=32
#SBATCH --mem=128G
#SBATCH --time=02:00:00
#SBATCH --output=logs/%j.out
#SBATCH --error=logs/%j.err
#SBATCH --open-mode=append

set -euo pipefail

PROJECT="${PROJECT:-project_462001516}"
BASE_ROOT="${BASE_ROOT:-/scratch/${PROJECT}/users/${USER}/firecracker-bench}"
SRC_ROOT="${SRC_ROOT:-${BASE_ROOT}/phase8-src-2026-07-01}"
RUN_ROOT="${RUN_ROOT:-${BASE_ROOT}/p8-${SLURM_JOB_ID}}"
ARTIFACT_CACHE_DIR="${ARTIFACT_CACHE_DIR:-${BASE_ROOT}/cache}"
ROOTFS_CACHE_DIR="${ROOTFS_CACHE_DIR:-${BASE_ROOT}/rootfs}"
PHASE8_HANDOFF_DIR="${PHASE8_HANDOFF_DIR:-${SRC_ROOT}/handoff/2026-07-01-firecracker-lumi-phase8-scoring-api-isolation}"
PHASE7_RESULTS_DIR="${PHASE7_RESULTS_DIR:-${SRC_ROOT}/handoff/2026-06-30-firecracker-lumi-phase7-results}"
PHASE6_MVP_DIR="${PHASE6_MVP_DIR:-${SRC_ROOT}/handoff/2026-06-30-firecracker-lumi-phase6-mvp-backend}"
RETURN_DIR="${RETURN_DIR:-${SRC_ROOT}/return/2026-07-01-firecracker-lumi-phase8-results}"
KERNEL_PATH="${KERNEL_PATH:-${BASE_ROOT}/kernels/linux-6.1.174-tun-19627901/vmlinux}"

mkdir -p "$RUN_ROOT" "$ARTIFACT_CACHE_DIR" "$ROOTFS_CACHE_DIR" "$RETURN_DIR" logs reports

module load cray-python/3.11.7 || true
python3 --version

ulimit -n 1048576 || true
export PYTHONDONTWRITEBYTECODE=1
export TMPDIR="/tmp/${USER}-fc-phase8-${SLURM_JOB_ID}"
mkdir -p "$TMPDIR"
trap 'rm -rf "$TMPDIR"' EXIT

cd "$SRC_ROOT"

python3 scripts/firecracker_lumi_phase8.py \
  --run-dir "$RUN_ROOT" \
  --kernel-path "$KERNEL_PATH" \
  --artifact-cache-dir "$ARTIFACT_CACHE_DIR" \
  --rootfs-cache-dir "$ROOTFS_CACHE_DIR" \
  --phase8-handoff-dir "$PHASE8_HANDOFF_DIR" \
  --phase7-results-dir "$PHASE7_RESULTS_DIR" \
  --phase6-mvp-dir "$PHASE6_MVP_DIR" \
  --return-dir "$RETURN_DIR" \
  --mem-mib "${FC_PHASE8_MEM_MIB:-768}" \
  --vcpus "${FC_PHASE8_VCPUS:-1}" \
  --pool-size "${FC_PHASE8_POOL_SIZE:-4}" \
  --density "${FC_PHASE8_DENSITY:-64,128,160,200,300,500}" \
  --noisy-pool-sizes "${FC_PHASE8_NOISY_POOL_SIZES:-64,160}" \
  --noisy-victims "${FC_PHASE8_NOISY_VICTIMS:-16}"
