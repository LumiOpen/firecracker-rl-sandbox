#!/bin/bash
#SBATCH --job-name=fc-net-poc
#SBATCH --account=project_462001516
#SBATCH --partition=dev-g
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=8
#SBATCH --mem=64G
#SBATCH --time=01:00:00
#SBATCH --output=logs/%j.out
#SBATCH --error=logs/%j.err
#SBATCH --open-mode=append

set -euo pipefail

BENCH_ROOT="${BENCH_ROOT:-/scratch/project_462001516/users/${USER}/firecracker-bench/net-poc-${SLURM_JOB_ID}}"
mkdir -p "$BENCH_ROOT" logs

module load cray-python/3.11.7 || true
python3 --version

export PYTHONDONTWRITEBYTECODE=1
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-${BENCH_ROOT}/cache/xdg}"
export PIP_CACHE_DIR="${PIP_CACHE_DIR:-${BENCH_ROOT}/cache/pip}"
export TMPDIR="/tmp/${USER}-${SLURM_JOB_ID}"
mkdir -p "$XDG_CACHE_HOME" "$PIP_CACHE_DIR" "$TMPDIR"
trap 'rm -rf "$TMPDIR"' EXIT

kernel_args=()
if [[ -n "${FC_NET_POC_KERNEL_PATH:-}" ]]; then
  kernel_args+=(--kernel-path "$FC_NET_POC_KERNEL_PATH")
fi

python3 scripts/firecracker_lumi_net_poc.py \
  --run-dir "$BENCH_ROOT" \
  --mem-mib "${FC_NET_POC_MEM_MIB:-512}" \
  --vcpus "${FC_NET_POC_VCPUS:-1}" \
  --boot-timeout "${FC_NET_POC_BOOT_TIMEOUT:-45}" \
  --gvtap-version "${FC_NET_POC_GVTAP_VERSION:-v0.8.9}" \
  "${kernel_args[@]}"
