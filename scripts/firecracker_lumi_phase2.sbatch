#!/bin/bash
#SBATCH --job-name=fc-phase2
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

BENCH_ROOT="${BENCH_ROOT:-/scratch/project_462001516/users/${USER}/firecracker-bench/phase2-${SLURM_JOB_ID}}"
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

python3 firecracker_lumi_phase2.py \
  --run-dir "$BENCH_ROOT" \
  --mem-mib "${FC_MEM_MIB:-512}" \
  --vcpus "${FC_VCPUS:-1}" \
  --boot-timeout "${FC_BOOT_TIMEOUT:-45}" \
  --command-timeout "${FC_COMMAND_TIMEOUT:-45}" \
  --snapshot-reset-workspace-sizes ${FC_PHASE2_SNAPSHOT_RESET_WORKSPACE_SIZES:-1000 10000} \
  --parallel-restore-counts ${FC_PHASE2_PARALLEL_RESTORE_COUNTS:-10 50 100} \
  --parallel-boot-counts ${FC_PHASE2_PARALLEL_BOOT_COUNTS:-10 50 100 200 300 500} \
  --density-counts ${FC_PHASE2_DENSITY_COUNTS:-200 300 500} \
  --active-density-counts ${FC_PHASE2_ACTIVE_DENSITY_COUNTS:-50 100 200} \
  --max-workers "${FC_PHASE2_MAX_WORKERS:-0}" \
  --max-saved-samples "${FC_PHASE2_MAX_SAVED_SAMPLES:-20}" \
  --host-sample-interval-s "${FC_PHASE2_HOST_SAMPLE_INTERVAL_S:-1.0}" \
  --stress-noop-iters "${FC_PHASE2_STRESS_NOOP_ITERS:-1000}" \
  --stress-large-stdout-bytes "${FC_PHASE2_STRESS_LARGE_STDOUT_BYTES:-1048576}" \
  --stress-large-stderr-bytes "${FC_PHASE2_STRESS_LARGE_STDERR_BYTES:-1048576}" \
  --stress-binary-bytes "${FC_PHASE2_STRESS_BINARY_BYTES:-65536}" \
  --security-memory-pressure-mib "${FC_PHASE2_SECURITY_MEMORY_PRESSURE_MIB:-256}" \
  --security-disk-fill-mib "${FC_PHASE2_SECURITY_DISK_FILL_MIB:-64}" \
  --security-process-count "${FC_PHASE2_SECURITY_PROCESS_COUNT:-256}" \
  ${FC_PHASE2_EXTRA_ARGS:-} \
  --with-pytest
