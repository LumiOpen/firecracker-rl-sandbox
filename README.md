# firecracker-rl-sandbox

`firecracker-rl-sandbox` manages and provisions Firecracker microVM environment
capacity for workloads such as RL environment rollouts, coding-agent evaluation,
and terminal-based training tasks. It provides a straightforward,
harness-friendly API for allocating environments, running commands, collecting
stdout/stderr/exit status, and releasing environments back to a pool.

The goal is to provide enough isolation that one misbehaving sandbox cannot
poison its neighbors: commands run inside separate microVMs, workspace state is
reset before reuse, and unhealthy VM slots can be recycled or replaced by the
pool owner.

Firecracker usually enables guest network egress by attaching a host-side TAP
device to the VM. This project was built for restricted HPC environments where
ordinary users often cannot create host TUN/TAP devices or load kernel network
drivers. The network path is therefore designed around guest-side TUN/TAP plus
VSOCK: `gvisor-tap-vsock` runs `gvforwarder` in the sandbox to tunnel traffic
over VSOCK to host-side `gvproxy`, where traffic is transparently proxied and,
in future work, subject to access-control policy. Network egress is opt-in; the
default profile should be treated as offline.

The package has two real usage modes:

- `LocalPool`: runs real Firecracker microVMs in the current Python process.
- `ServiceClient`: talks to a node-local HTTP service that owns Firecracker
  pools.

Both modes expose the same basic shape: create a pool, allocate a sandbox, run
commands, release the sandbox.

This project is in active development. The core Firecracker lifecycle,
workspace reset, and service API paths have been exercised on LUMI; network
policy, streaming IO, and image build ergonomics are still being hardened.

## Requirements

You need a Linux host or allocation where the user can access KVM:

```bash
test -r /dev/kvm -a -w /dev/kvm && echo kvm-ok
```

You also need three VM artifacts:

- **Firecracker binary**: the VMM executable that launches each microVM.
- **Guest kernel**: the kernel booted inside the VM. This is not the host
  kernel. The host kernel only needs to provide KVM.
- **Rootfs image**: an ext4 guest filesystem containing the command agent and
  userland tools.

The quick start below fetches/builds defaults for all three. You can override
any of them if your site provides pinned artifacts.

## Quick Start: Local Firecracker Pool

Prepare the default artifacts in scratch or another large filesystem:

```bash
export PROJECT="${PROJECT:?set your LUMI project id, for example project_123456789}"
export BASE_ROOT="${BASE_ROOT:-/scratch/${PROJECT}/users/${USER}/firecracker-rl-sandbox}"

PYTHONPATH=scripts:. python3 scripts/firecracker_prepare_artifacts.py \
  --base-root "$BASE_ROOT" \
  --profile python-coding \
  --env-output .firecracker-env

source .firecracker-env
export FIRECRACKER_RUN_DIR="${BASE_ROOT}/run"
```

`firecracker_prepare_artifacts.py` downloads the Firecracker executable,
downloads a known-good default guest kernel, and composes a basic
`python-coding` rootfs from `image_profiles/python-coding.yaml`. To use your
own artifacts instead:

```bash
PYTHONPATH=scripts:. python3 scripts/firecracker_prepare_artifacts.py \
  --base-root "$BASE_ROOT" \
  --firecracker-bin /path/to/firecracker-v1.16.0-x86_64 \
  --kernel /path/to/vmlinux \
  --rootfs /path/to/rootfs.ext4 \
  --env-output .firecracker-env
```

Run commands in an isolated Firecracker sandbox:

```python
from firecracker_rl_sandbox import LocalPool

pool = LocalPool(
    profile="python-coding",
    size=2,
    mem_mib=768,
    vcpus=1,
    # network="egress",  # uncomment to allow network egress
)

with pool.allocate() as sandbox:
    result = sandbox.run("python3 -c 'print(1 + 1)'")
    print(result.exit_code)
    print(result.stdout_text)

pool.close()
```

`sandbox.sandbox_id` is the ephemeral sandbox handle. `task_id` is optional
caller metadata accepted by `pool.allocate(task_id="episode-...")` for
correlating service logs with an RL episode or eval row. It is not required and
it is not the sandbox identifier.

For long-running commands or interactive programs, use a process handle. The
current client API is not a continuous stream. It is chunked polling: start the
process, read available stdout/stderr, write stdin when the process was launched
as interactive, close stdin when appropriate, then collect the exit code.

```python
with pool.allocate() as sandbox:
    proc = sandbox.start_process(
        "printf 'name? '; read name; echo \"hello $name\"",
        interactive=True,
    )

    prompt = proc.read(wait_ms=1000)
    print(prompt.stdout_text, end="")

    proc.write("Ada\n")
    proc.close_stdin()

    while True:
        chunk = proc.read(wait_ms=1000)
        print(chunk.stdout_text, end="")
        print(chunk.stderr_text, end="")
        if chunk.exit_code is not None:
            print("exit", chunk.exit_code)
            break
```

Use `proc.status()` for a cheap state check and `proc.cancel()` to terminate the
process group. The service API is expected to grow a true bidirectional stream
transport, but the process lifecycle should remain the same.

## Quick Start: Standalone Service

Start the service inside the same allocation or node where KVM is available:

```bash
source .firecracker-env

PYTHONPATH=scripts:. python3 scripts/firecracker_pool_service.py \
  --backend firecracker \
  --listen 127.0.0.1:8765 \
  --pool-id default \
  --profile python-coding \
  --pool-size 8 \
  --auto-create-pool \
  --firecracker "$FIRECRACKER_BIN" \
  --kernel "$FIRECRACKER_KERNEL" \
  --rootfs "$FIRECRACKER_ROOTFS" \
  --run-dir "$FIRECRACKER_RUN_DIR"
```

Use the same sandbox API through the service client:

```python
from firecracker_rl_sandbox import ServiceClient

client = ServiceClient("http://127.0.0.1:8765")
pool = client.pool("default", profile="python-coding")

with pool.allocate() as sandbox:
    result = sandbox.run("pwd; python3 -m pytest -q tests")
    print(result.exit_code)
    print(result.stdout_text)
```

Use `client.create_pool(...)` when the service should provision another pool at
runtime, for example a different profile or capacity target. That call boots VM
capacity; `client.pool(...)` is just a handle to an existing service-owned pool.

Useful service endpoints:

```text
GET  /healthz
GET  /readyz
GET  /varz
GET  /metrics
POST /v1/pools
POST /v1/sandboxes
POST /v1/sandboxes/{sandbox_id}/run
POST /v1/sandboxes/{sandbox_id}/processes
POST /v1/sandboxes/{sandbox_id}/processes/{process_id}/read
POST /v1/sandboxes/{sandbox_id}/processes/{process_id}/write
POST /v1/sandboxes/{sandbox_id}/processes/{process_id}/status
POST /v1/sandboxes/{sandbox_id}/processes/{process_id}/close_stdin
POST /v1/sandboxes/{sandbox_id}/processes/{process_id}/cancel
POST /v1/sandboxes/{sandbox_id}/release
```

The service binds to loopback by default. Require deployment-specific auth and
network controls before binding it to anything broader than `127.0.0.1`.

## Resource Defaults

The examples spell out the current defaults:

- `mem_mib=768`: configured guest memory per sandbox.
- `vcpus=1`: configured guest vCPU count per sandbox.
- `network` omitted: no network egress by default.

These are conservative defaults for command-execution rollouts. Increase memory
for package-heavy Python tasks, compilers, or larger in-guest corpora. The pool
owner should size `pool.size * mem_mib` against the Slurm cgroup memory limit
with room for VMM RSS, rootfs page cache, and service overhead.

## Benchmark Snapshot

One LUMI `dev-g` node run on July 1, 2026 used 32 host CPUs, a 128 GiB Slurm
memory allocation, 100 Firecracker sandboxes, `mem_mib=768`, `vcpus=1`, and no
network egress. The benchmark created the pool, allocated 100 sandboxes through
the service API, ran `python3 -c 'print(1)'` in all sandboxes, released all
sandboxes, and closed the pool.

Pool creation, allocation, and command execution are parallel. Release requests
are issued concurrently by the benchmark client, but the current service
serializes reset/release inside a pool.

| phase | wall time |
| --- | ---: |
| create 100-VM pool | 2.741 s |
| allocate 100 sandboxes | 64 ms |
| run 100 Python commands | 173 ms |
| release/reset 100 sandboxes | 7.981 s |
| close pool | 11.763 s |
| total lifecycle | 23.793 s |

Per-operation p50/p90/p99 latencies from the same run:

| operation | p50 | p90 | p99 |
| --- | ---: | ---: | ---: |
| allocate sandbox | 7.4 ms | 9.7 ms | 11.0 ms |
| `python3 -c 'print(1)'` | 131.1 ms | 144.0 ms | 151.7 ms |
| release/reset sandbox | 4.130 s | 7.172 s | 7.872 s |

The run completed with 0 failures and cleaned up all VM runtime directories.

## Images And Profiles

Profiles live in `image_profiles/`:

- `base.yaml`: shell/coreutils profile.
- `python-coding.yaml`: Python, pytest, git, and common text tools.
- `full-coding.yaml`: Python plus C/C++ build tools and extra diagnostics.

The current builder path is intentionally simple: use
`scripts/firecracker_prepare_artifacts.py` for a default image, then customize
the profile and rootfs builder as needed. More details are in
`docs/firecracker-image-build-tooling.md`.

## Current Rough Edges

- Network egress is explicit opt-in and policy/ACL semantics are not finished.
  The default profile should be treated as offline.
- Bidirectional streaming is still design work; the service currently supports
  request/response runs and process-handle polling.
- Output buffers are bounded in the guest-agent path; final polling/streaming
  semantics and process-slot limits still need hardening.

## Development

Development checks and mock backends are documented in `CONTRIBUTING.md`.
