#!/bin/bash
#SBATCH --job-name=fc-phase4
#SBATCH --account=project_462001516
#SBATCH --partition=dev-g
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=16
#SBATCH --mem=96G
#SBATCH --time=02:00:00
#SBATCH --output=logs/%j.out
#SBATCH --error=logs/%j.err
#SBATCH --open-mode=append

set -euo pipefail

PROJECT="${PROJECT:-project_462001516}"
BASE_ROOT="${BASE_ROOT:-/scratch/${PROJECT}/users/${USER}/firecracker-bench}"
SRC_ROOT="${SRC_ROOT:-${BASE_ROOT}/phase4-src-2026-06-30}"
RUN_ROOT="${RUN_ROOT:-${BASE_ROOT}/phase4-${SLURM_JOB_ID}}"
KERNEL_PATH="${KERNEL_PATH:-${BASE_ROOT}/kernels/linux-6.1.174-tun-19627901/vmlinux}"

mkdir -p "$RUN_ROOT" logs

module load cray-python/3.11.7 || true
python3 --version

export PYTHONDONTWRITEBYTECODE=1
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-${RUN_ROOT}/cache/xdg}"
export PIP_CACHE_DIR="${PIP_CACHE_DIR:-${RUN_ROOT}/cache/pip}"
export TMPDIR="/tmp/${USER}-fc-phase4-${SLURM_JOB_ID}"
mkdir -p "$XDG_CACHE_HOME" "$PIP_CACHE_DIR" "$TMPDIR"
trap 'rm -rf "$TMPDIR"' EXIT

python3 scripts/firecracker_lumi_phase4.py \
  --run-dir "$RUN_ROOT" \
  --kernel-path "$KERNEL_PATH" \
  --mem-mib "${FC_PHASE4_MEM_MIB:-768}" \
  --vcpus "${FC_PHASE4_VCPUS:-1}" \
  --density "${FC_PHASE4_DENSITY:-1,4,8}"
