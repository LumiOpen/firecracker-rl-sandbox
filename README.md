# firecracker-rl-sandbox

Prototype Firecracker-backed sandbox pooling for RL, evaluation, and coding-agent
workloads on LUMI-like HPC systems.

The current code is an experimental productionization bundle, not a published
library. It includes:

- A Python client API in `firecracker_rl_sandbox/`.
- A subprocess-backed `LocalPool` for API experimentation without KVM.
- A node-local HTTP service prototype in `scripts/firecracker_pool_service.py`.
- LUMI Firecracker benchmark, recovery, noisy-neighbor, and image tooling
  scripts in `scripts/`.
- Operations and image-build notes in `docs/`.

## Quick Start

Local API smoke, no Firecracker required:

```bash
python3 -m unittest discover -s tests -v
PYTHONPATH=. python3 examples/local_quickstart.py
python3 scripts/firecracker_pool_service.py --self-test
```

Run the mock HTTP service and client:

```bash
PYTHONPATH=scripts:. python3 scripts/firecracker_pool_service.py \
  --backend mock \
  --listen 127.0.0.1:8765
```

In another terminal:

```bash
PYTHONPATH=. python3 examples/service_client_quickstart.py
curl -s http://127.0.0.1:8765/healthz
curl -s http://127.0.0.1:8765/readyz
curl -s http://127.0.0.1:8765/metrics
```

Use `uv` once this is moved into a proper package repo:

```bash
uv sync
uv run python -m unittest discover -s tests -v
```

## Python API Shape

The intended user-facing API is the same for local experiments and service
backends:

```python
from firecracker_rl_sandbox import LocalPool, ServiceClient

pool = LocalPool(profile="python-coding", size=2)
# or:
# pool = ServiceClient("http://127.0.0.1:8765").pool("default", profile="python-coding")

with pool.allocate(task_id="demo") as sandbox:
    result = sandbox.run("python3 -c 'print(1 + 1)'")
    assert result.exit_code == 0
    print(result.stdout_text)
```

`LocalPool` is only a development helper. It is not an isolation boundary. The
Firecracker backend is owned by the service process and should run inside a
LUMI allocation or another host with KVM and Firecracker access.

## Service

The service is IP-based HTTP by default and binds to loopback unless configured
otherwise:

```bash
PYTHONPATH=scripts:. python3 scripts/firecracker_pool_service.py \
  --backend firecracker \
  --listen 127.0.0.1:8765 \
  --pool-size 8 \
  --firecracker /path/to/firecracker \
  --kernel /path/to/vmlinux \
  --rootfs /path/to/rootfs.ext4 \
  --run-dir /scratch/$PROJECT/users/$USER/firecracker-service-run
```

Expose beyond loopback only with a deployment-specific auth and network plan.
The prototype supports a bearer token through `FIRECRACKER_POOL_TOKEN` or
`--auth-token`.

Useful endpoints:

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
POST /v1/sandboxes/{sandbox_id}/processes/{process_id}/cancel
POST /v1/sandboxes/{sandbox_id}/release
```

The older `/v1/sessions` routes are still present as compatibility aliases for
earlier phase artifacts.

## Current Rough Edges

- Network is offline by default. If network tunneling is enabled today, do not
  assume fine-grained egress filtering.
- Firecracker image build tooling is profile-driven but not yet a complete
  end-to-end image factory.
- The service has a request/response API. Bidirectional streaming is still
  design work.
- Output buffers are bounded in the guest-agent path; the public API still
  needs final polling/streaming semantics and process-slot limits.
- `LocalPool` is not secure; use it only to learn the API.
- Intended-distribution trace coverage is deferred. It should broaden
  confidence later, but it is not blocking productionization work.

## Important Docs

- `docs/phase12-productionization.md`
- `docs/firecracker-pool-service.md`
- `docs/firecracker-image-build-tooling.md`
- `docs/lumi-operations.md`
