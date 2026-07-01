#!/bin/bash
#SBATCH --job-name=fc-phase3
#SBATCH --account=project_462001516
#SBATCH --partition=dev-g
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=32
#SBATCH --mem=256G
#SBATCH --time=03:00:00
#SBATCH --output=logs/%j.out
#SBATCH --error=logs/%j.err
#SBATCH --open-mode=append

set -euo pipefail

BENCH_ROOT="${BENCH_ROOT:-/scratch/project_462001516/users/${USER}/firecracker-bench/phase3-${SLURM_JOB_ID}}"
mkdir -p "$BENCH_ROOT" logs

module load cray-python/3.11.7 || true
python3 --version

export PYTHONDONTWRITEBYTECODE=1
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-${BENCH_ROOT}/cache/xdg}"
export PIP_CACHE_DIR="${PIP_CACHE_DIR:-${BENCH_ROOT}/cache/pip}"
export HF_HOME="${HF_HOME:-${BENCH_ROOT}/cache/huggingface}"
export TRANSFORMERS_CACHE="${TRANSFORMERS_CACHE:-${HF_HOME}/transformers}"
export TMPDIR="/tmp/${USER}-${SLURM_JOB_ID}"
mkdir -p "$XDG_CACHE_HOME" "$PIP_CACHE_DIR" "$HF_HOME" "$TRANSFORMERS_CACHE" "$TMPDIR"
ulimit -n 1048576 || true
trap 'rm -rf "$TMPDIR"' EXIT

python3 firecracker_lumi_phase3.py \
  --run-dir "$BENCH_ROOT" \
  --mem-mib "${FC_MEM_MIB:-512}" \
  --vcpus "${FC_VCPUS:-1}" \
  --boot-timeout "${FC_BOOT_TIMEOUT:-45}" \
  --command-timeout "${FC_COMMAND_TIMEOUT:-300}" \
  --large-output-sizes ${FC_PHASE3_LARGE_OUTPUT_SIZES:-65536 1048576 10485760} \
  --reset-file-counts ${FC_PHASE3_RESET_FILE_COUNTS:-1000 10000} \
  --skipped-reset-file-counts ${FC_PHASE3_SKIPPED_RESET_FILE_COUNTS:-100000} \
  --security-disk-fill-mib "${FC_PHASE3_SECURITY_DISK_FILL_MIB:-1024}" \
  ${FC_PHASE3_EXTRA_ARGS:-} \
  --with-pytest
