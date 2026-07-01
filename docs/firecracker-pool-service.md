# Firecracker Pool Service

This is the node/allocation-local service boundary around the Firecracker pool.
The service owns VM slots, logical sandbox leases, process lifecycle, output
bounds, recovery, metrics, and cleanup. Normal clients should interact with
logical sandboxes, not Firecracker VM slots.

## User API

Preferred production-facing routes:

```text
POST /v1/sandboxes
POST /v1/sandboxes/{sandbox_id}/run
POST /v1/sandboxes/{sandbox_id}/processes
POST /v1/sandboxes/{sandbox_id}/processes/{process_id}/read
POST /v1/sandboxes/{sandbox_id}/processes/{process_id}/status
POST /v1/sandboxes/{sandbox_id}/processes/{process_id}/cancel
POST /v1/sandboxes/{sandbox_id}/release
```

Compatibility routes from the earlier prototype still exist under
`/v1/sessions`, but new clients should use `/v1/sandboxes`.

## Admin API

```text
GET    /healthz
GET    /readyz
GET    /varz
GET    /metrics
POST   /v1/pools
GET    /v1/pools/{pool_id}
DELETE /v1/pools/{pool_id}
```

`/metrics` emits Prometheus text format. `/varz` is JSON for human inspection.

## Semantics

- Pool creation is outside the agent loop.
- Sandbox IDs are logical leases and should not be recycled.
- Sandbox acquisition has explicit queue timeout.
- Default command timeout is disabled with `timeout_ms=0`.
- `run` supports cwd/env/stdin and bounded stdout/stderr.
- `start_process` returns process handles for status/read/cancel.
- `release(strategy="auto")` returns the slot only after cleanup is proven
  clean, escalating internally if needed.
- `release(strategy="hard")` requests hard recycle/restore behavior.
- Pool deletion drains sandboxes and closes VMMs.
- Transcripts and metrics are supervisor-owned.
- Optional bearer auth is available with `FIRECRACKER_POOL_TOKEN`.

## Smoke Test

The service has a mock backend for API testing without KVM:

```bash
python3 scripts/firecracker_pool_service.py --self-test
```

Run with the real backend inside a LUMI allocation:

```bash
PYTHONPATH=scripts python3 scripts/firecracker_pool_service.py \
  --backend firecracker \
  --listen 127.0.0.1:8765 \
  --pool-size 64 \
  --firecracker /path/to/firecracker \
  --kernel /path/to/vmlinux \
  --rootfs /path/to/rootfs.ext4 \
  --run-dir /scratch/$PROJECT/users/$USER/firecracker-service-run
```

## Remaining Hardening

- Add complete process-slot accounting and structured `too_many_process_slots`
  errors.
- Finish polling versus streaming output semantics.
- Add bidirectional process streaming.
- Add admission control across configured guest memory, active process slots,
  stdout/stderr buffers, and host RSS/cgroup headroom.
- Add periodic health checks and pool draining.
- Add structured error classes for timeout, OOM-like exit, output block,
  reset failure, and worker recycle.
- Add TLS/auth/proxy story before any non-loopback deployment.
- Add integration tests against a real LUMI Firecracker pool.
