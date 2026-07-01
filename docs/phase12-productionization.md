# Phase 12 Productionization Handoff

Date: 2026-07-01

## Scope

Phase 12 is redefined as a productionization starter kit for
`firecracker-rl-sandbox`. The trace-distribution Gate 8 request is deferred:
broader intended-distribution traces are valuable, but the Firecracker substrate
has enough evidence to continue productionizing.

The goal for this phase is to give other engineers something they can run,
inspect, and extend without needing the full history of prior LUMI phases.

## What Exists Now

- Python package skeleton: `firecracker_rl_sandbox/`.
- Local API compatibility backend: `LocalPool`.
- HTTP service client: `ServiceClient`.
- Node-local pool service: `scripts/firecracker_pool_service.py`.
- Sandbox-style service aliases: `/v1/sandboxes/...`.
- Legacy session routes retained for earlier phase artifacts.
- Service health and observability endpoints:
  - `/healthz`
  - `/readyz`
  - `/varz`
  - `/metrics`
- Mock service backend for local API smoke testing.
- Real Firecracker backend path through `firecracker_lumi_phase6.FirecrackerPool`.
- Image profile tooling in `scripts/firecracker_image_builder.py`.
- Prior LUMI evidence through Phase 11.

## Validation Run Locally

```bash
cd /path/to/lumi
python3 -m unittest discover -s tests -v
PYTHONPATH=. python3 examples/local_quickstart.py
python3 scripts/firecracker_pool_service.py --self-test
```

Mock service client flow:

```bash
PYTHONPATH=scripts:. python3 scripts/firecracker_pool_service.py \
  --backend mock \
  --listen 127.0.0.1:8765
```

In another terminal:

```bash
PYTHONPATH=. python3 examples/service_client_quickstart.py
curl -s http://127.0.0.1:8765/metrics
```

## LUMI Experiment Flow

Run inside a LUMI allocation or sbatch job on `dev-g`.

Use project scratch for runtime files. Do not stage rootfs images, caches, or
runtime directories in a user's home directory.

```bash
export PROJECT="${PROJECT:-project_462001516}"
export BASE_ROOT="${BASE_ROOT:-/scratch/${PROJECT}/users/${USER}/firecracker-bench}"
export RUN_ROOT="${RUN_ROOT:-${BASE_ROOT}/service-run-${SLURM_JOB_ID:-manual}}"
export KERNEL_PATH="${KERNEL_PATH:-${BASE_ROOT}/kernels/linux-6.1.174-tun-19627901/vmlinux}"
export ROOTFS_PATH="${ROOTFS_PATH:-${BASE_ROOT}/rootfs/python-coding.ext4}"
export FIRECRACKER_BIN="${FIRECRACKER_BIN:-${BASE_ROOT}/cache/firecracker/firecracker-v1.16.0-x86_64}"

mkdir -p "$RUN_ROOT"
PYTHONPATH=scripts:. python3 scripts/firecracker_pool_service.py \
  --backend firecracker \
  --listen 127.0.0.1:8765 \
  --pool-size "${POOL_SIZE:-2}" \
  --firecracker "$FIRECRACKER_BIN" \
  --kernel "$KERNEL_PATH" \
  --rootfs "$ROOTFS_PATH" \
  --run-dir "$RUN_ROOT"
```

Then use `ServiceClient` from the same node/allocation:

```python
from firecracker_rl_sandbox import ServiceClient

client = ServiceClient("http://127.0.0.1:8765")
pool = client.create_pool(pool_id="demo", profile="python-coding", size=2)

with pool.allocate(task_id="demo") as sandbox:
    result = sandbox.run("python3 -c 'print(123)'")
    print(result.exit_code, result.stdout_text)
```

## API Direction

Keep the public API small:

```text
allocate_sandbox(profile, resources?) -> sandbox
sandbox.run(command, timeout_ms=0, cwd="/workspace", env=None, stdin=None)
sandbox.start_process(command, interactive=False)
process.status()
process.read()
process.cancel()
sandbox.release(strategy="auto" | "hard")
```

Do not expose VM reset/recycle/snapshot as normal user calls. Those are internal
strategies that should appear in metrics and structured evidence.

Use `profile`, not `image`, in public APIs. A profile can include image,
kernel, memory, vCPU, agent, workspace, mounts, and future network policy.

## Production Priorities

1. Move this into a proper package repo with `uv`.
2. Add real integration tests against a small LUMI Firecracker pool.
3. Finalize process states and process-slot limits.
4. Finish output semantics:
   - bounded stdout/stderr buffers
   - `stdout_blocked` / `stderr_blocked`
   - polling that frees buffer space
   - later bidirectional streaming
5. Add structured errors:
   - `sandbox_not_found`
   - `too_many_process_slots`
   - `command_timeout`
   - `process_cancelled`
   - `sandbox_unhealthy`
   - `release_failed`
6. Add pool admission control using configured guest memory, host RSS/cgroup
   headroom, process slots, and output-buffer budgets.
7. Pressure the system beyond the Phase 11 pass:
   - pool sizes 200/300/500 if feasible
   - fully parallel boot
   - active density with Python, grep/find, pytest
   - output flood with slow readers
   - daemon/background process cleanup
   - fork/memory/disk pressure
8. Improve image build tooling:
   - declarative profiles
   - reproducible rootfs build
   - boot smoke
   - package inventory
   - manifest
9. Add service deployment docs:
   - loopback by default
   - auth required before non-loopback
   - `/healthz`, `/readyz`, `/varz`, `/metrics`
10. Create an RL/eval integration demo.

## Known Rough Edges

- Network ACL/policy is deferred. The MVP should be treated as offline by
  default. If networking is enabled, do not assume fine-grained egress
  filtering yet.
- VSOCK network tunneling remains the likely path for unprivileged HPC systems
  where users cannot create host TUN/TAP devices. A host TUN/TAP backend can be
  added later for sites that allow it.
- The current image tooling validates and emits profile plans, but does not yet
  replace the older phase-specific rootfs composer.
- Streaming is not implemented. The current service is request/response plus
  process polling.
- `LocalPool` is not a sandbox. It exists only to make the API easy to try.
- Intended-distribution trace replay is deferred as coverage work, not as a
  blocker for service productionization.

## Recommended Hand-Off Tasks

- First engineer: package cleanup, API tests, service route tests, and docs.
- Second engineer: LUMI real-pool service smoke with pool size 2/8/64 and
  Prometheus metrics capture.
- Third engineer: pressure tests for output blocking, process slots, and
  release cleanup.
- Fourth engineer: image builder replacement for the phase-specific composer.
