# Contributing

Use `uv` for local development when possible:

```bash
uv sync
uv run python -m unittest discover -s tests -v
```

The dependency-free checks are:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/firecracker_pool_service.py --self-test
```

The quick-start examples use the real APIs. `examples/local_quickstart.py`
requires KVM plus Firecracker artifacts, and `examples/service_client_quickstart.py`
requires a running service.

`SubprocessPool` and the service `--backend mock` mode are for client API tests
only. They run host subprocesses and do not provide Firecracker isolation.
Production and integration examples should use `LocalPool` or the real
Firecracker service backend.

Before pushing:

```bash
python3 -m compileall firecracker_rl_sandbox scripts examples tests
python3 -m unittest discover -s tests -v
python3 scripts/firecracker_pool_service.py --self-test
git diff --check
```
