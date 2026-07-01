# LUMI Operations Notes

These notes are intended to be generic operational guidance for running jobs on
LUMI. Replace project names, usernames, paths, and container images with the
values for the account doing the work.

## Filesystems And Quota

- Treat the login/home filesystem as small and quota-sensitive. Do not stage
  datasets, checkpoints, container images, model caches, Python environments,
  build directories, benchmark artifacts, or large logs in `$HOME`.
- Put durable project work under project scratch, using the convention for the
  active project, for example:

  ```bash
  export PROJECT=project_XXXXXXXXX
  export PROJECT_HOME=/scratch/${PROJECT}/users/${USER}
  mkdir -p "$PROJECT_HOME"
  ```

- Put high-churn temporary files on node-local storage inside jobs when possible:

  ```bash
  export JOB_TMP=${TMPDIR:-/tmp/${USER}-${SLURM_JOB_ID}}
  mkdir -p "$JOB_TMP"
  trap 'rm -rf "$JOB_TMP"' EXIT
  ```

- Shared Lustre filesystems can handle large streaming reads/writes better than
  many tiny-file operations. For large test corpora or reset benchmarks, prefer
  packed archives, prebuilt images, or node-local expansion over repeatedly
  creating and deleting tens of thousands of small files on project scratch.
- Before launching jobs that may write large artifacts, check the target
  filesystem and project quota:

  ```bash
  df -h "$PROJECT_HOME"
  du -sh "$PROJECT_HOME" 2>/dev/null || true
  ```

## Cache, Runtime, And Environment Placement

Reusable tools should generally honor the user's existing environment instead
of forcing cache locations. If the shell or service supervisor already sets
`HF_HOME`, `PIP_CACHE_DIR`, `UV_CACHE_DIR`, `APPTAINER_CACHEDIR`,
`SINGULARITY_CACHEDIR`, or similar variables, preserve those choices.

Only redirect cache or environment variables in reusable scripts when there is
a concrete reason, such as an unset variable that would write large data into
`$HOME`, a site policy requiring project scratch, or a short-lived compile cache
that is best kept on node-local storage. When a redirect is necessary, prefer
parameterized defaults rather than account-specific paths:

```bash
export PROJECT=project_XXXXXXXXX
export PROJECT_HOME=/scratch/${PROJECT}/users/${USER}
export CACHE_ROOT=${CACHE_ROOT:-${PROJECT_HOME}/.cache}

# Example only: set these when needed, not as a blanket requirement.
export HF_HOME=${HF_HOME:-${CACHE_ROOT}/huggingface}
export PIP_CACHE_DIR=${PIP_CACHE_DIR:-${CACHE_ROOT}/pip}
export UV_CACHE_DIR=${UV_CACHE_DIR:-${CACHE_ROOT}/uv}
export APPTAINER_CACHEDIR=${APPTAINER_CACHEDIR:-${CACHE_ROOT}/apptainer}
export SINGULARITY_CACHEDIR=${SINGULARITY_CACHEDIR:-${CACHE_ROOT}/singularity}
```

For PyTorch/ROCm compile and autotune caches, job-local storage is often useful
when the cache is purely disposable. Keep persistent caches only when they are
intentional and quota-managed:

```bash
export TRITON_CACHE_DIR=${TRITON_CACHE_DIR:-/tmp/triton-${SLURM_JOB_ID}}
export TORCHINDUCTOR_CACHE_DIR=${TORCHINDUCTOR_CACHE_DIR:-/tmp/inductor-${SLURM_JOB_ID}}
export MIOPEN_USER_DB_PATH=${MIOPEN_USER_DB_PATH:-/tmp/miopen-${SLURM_JOB_ID}}
export MIOPEN_CACHE_DIR=${MIOPEN_CACHE_DIR:-/tmp/miopen-cache-${SLURM_JOB_ID}}
```

For long-lived services, separate durable artifacts from runtime scratch. A
pool manager may create per-VM sockets, logs, tmpfs backing metadata, and other
runtime directories while an environment is alive, but those paths should be
owned by the lifecycle manager and cleaned on release, recycle, or service
shutdown. Keep any debug-retention mode explicit so ordinary use does not leave
per-session files behind.

## SLURM Usage

- Submit from a LUMI user access node, not from a compute node. Run workload
  logic inside SLURM allocations.
- Use the account and partition appropriate for the work. GPU development jobs
  commonly use `dev-g`; longer GPU jobs typically use `small-g` or
  `standard-g`, subject to project policy and allocation.
- Be explicit about resources:

  ```bash
  #SBATCH --account=project_XXXXXXXXX
  #SBATCH --partition=dev-g
  #SBATCH --nodes=1
  #SBATCH --ntasks=1
  #SBATCH --cpus-per-task=16
  #SBATCH --mem=64G
  #SBATCH --time=00:30:00
  #SBATCH --output=logs/%j.out
  #SBATCH --error=logs/%j.err
  #SBATCH --open-mode=append
  ```

- Keep `#SBATCH --open-mode=append` for requeue-safe logs.
- Write logs to project scratch, or keep log volume small if using a path that
  may be quota-sensitive. Compress or delete verbose logs after debugging.
- Poll long-running jobs at practical intervals. Avoid tight monitoring loops
  from login nodes.
- Useful status commands:

  ```bash
  squeue -u "$USER" --format='%.12i %.30j %.10T %.10M %.6D %R'
  sacct -u "$USER" --starttime=now-1day \
    --format=JobID,JobName%30,State,Elapsed,ExitCode,NodeList
  sinfo -p dev-g,small-g,standard-g
  ```

## Containers And Modules

- Container runtimes and GPU-specific tooling may be available only inside
  compute-node allocations. If a command is missing on the login node, test it
  inside a short interactive or batch allocation before concluding it is
  unavailable.
- Prefer project-provided or site-provided ROCm/PyTorch containers when the
  workload depends on GPU libraries. Record the image path and tag/digest in
  reports so results are reproducible.
- Keep container caches and pulled images on project scratch, not `$HOME`.
- Load modules explicitly in job scripts instead of relying on an interactive
  shell state:

  ```bash
  module purge
  module load cray-python
  ```

  Adjust module choices to the workload and document the selected versions.

## GPU And ROCm Settings

Common environment settings for MI250/ROCm jobs include:

```bash
export HSA_FORCE_FINE_GRAIN_PCIE=1
export NCCL_SOCKET_IFNAME=hsn0,hsn1,hsn2,hsn3
export NCCL_NET_GDR_LEVEL=3
export RCCL_MSCCL_ENABLE=0
export PYTORCH_ROCM_ARCH=gfx90a
```

These are workload-dependent. Record any communication, cache, precision,
sequence-length, batch-size, tensor-parallel, pipeline-parallel, and data-parallel
settings in job logs or reports.

## Network, Privileges, And Virtualization

- Do not assume login-node network behavior matches compute-node behavior.
  Validate network access from the allocation if the job downloads artifacts,
  calls external APIs, or opens sockets.
- Avoid workflows that need root or kernel-module changes unless LUMI support
  has explicitly enabled them.
- For Firecracker-style virtualization checks, validate capabilities on compute
  nodes, not only login nodes. The minimum checks are `/dev/kvm` read/write
  access, KVM ioctls, and the intended command channel. Network-backed VM
  control may require TUN/TAP, which can be unavailable even when KVM works.

## Reproducibility And Reporting

Capture enough context for every meaningful run:

```bash
date -Ins
hostname
uname -a
lscpu | sed -n '1,40p'
free -h
env | sort
scontrol show job "$SLURM_JOB_ID"
```

For benchmark work, record:

- Node name and partition.
- Account/project used.
- CPU count, CPU model, visible memory, and memory available before the run.
- Container image or binary release versions.
- Kernel, driver, ROCm, Python, PyTorch, and dependency versions.
- All important numeric constants: learning rates, sequence lengths, batch
  sizes, context lengths, parallelism, cache sizes, memory sizes, iteration
  counts, timeout values, and polling intervals.
- Paths to result JSON/Markdown, plus enough metadata to reproduce the command.

## Cleanup

- Use `trap` cleanup for `/tmp` and other node-local directories.
- Periodically remove failed-run directories, partial downloads, expanded
  datasets, and old caches from project scratch.
- Before deleting shared project data, verify ownership and scope:

  ```bash
  find "$PROJECT_HOME" -maxdepth 2 -type d -name 'run-*' -mtime +14 -print
  ```

- Do not use destructive cleanup commands against broad paths unless the path is
  clearly a job-specific directory.

## Candidate Skill Material

These notes are suitable to fold into a future operational skill or TensorBase
runbook. If converted into a skill, keep the guidance parameterized by project,
user, partition, and cache root so it remains safe across accounts.
