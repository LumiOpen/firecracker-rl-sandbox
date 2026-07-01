#!/bin/bash
#SBATCH --job-name=fc-bench
#SBATCH --account=project_462001516
#SBATCH --partition=dev-g
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=32
#SBATCH --mem=96G
#SBATCH --time=03:00:00
#SBATCH --output=logs/%j.out
#SBATCH --error=logs/%j.err
#SBATCH --open-mode=append

set -euo pipefail

BENCH_ROOT="${BENCH_ROOT:-/scratch/project_462001516/users/${USER}/firecracker-bench/bench-${SLURM_JOB_ID}}"
mkdir -p "$BENCH_ROOT" logs

export PYTHONDONTWRITEBYTECODE=1
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-${BENCH_ROOT}/cache/xdg}"
export PIP_CACHE_DIR="${PIP_CACHE_DIR:-${BENCH_ROOT}/cache/pip}"
export HF_HOME="${HF_HOME:-${BENCH_ROOT}/cache/huggingface}"
export TMPDIR="/tmp/${USER}-${SLURM_JOB_ID}"
mkdir -p "$XDG_CACHE_HOME" "$PIP_CACHE_DIR" "$HF_HOME" "$TMPDIR"
trap 'rm -rf "$TMPDIR"' EXIT

python3 firecracker_lumi_bench.py \
  --run-dir "$BENCH_ROOT" \
  --mem-mib "${FC_MEM_MIB:-512}" \
  --vcpus "${FC_VCPUS:-1}" \
  --cold-iters "${FC_COLD_ITERS:-5}" \
  --warm-iters "${FC_WARM_ITERS:-100}" \
  --noop-iters "${FC_NOOP_ITERS:-1000}" \
  --reset-iters "${FC_RESET_ITERS:-20}" \
  --workspace-sizes ${FC_WORKSPACE_SIZES:-10 1000 10000} \
  --density-counts ${FC_DENSITY_COUNTS:-1 10 50 100} \
  --snapshot-iters "${FC_SNAPSHOT_ITERS:-20}" \
  --with-pytest
