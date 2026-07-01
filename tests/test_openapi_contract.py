from __future__ import annotations

from pathlib import Path
import re
import unittest

from scripts.firecracker_pool_service import route


PUBLIC_ROUTES = {
    ("GET", "/healthz"),
    ("GET", "/readyz"),
    ("GET", "/varz"),
    ("GET", "/metrics"),
    ("POST", "/v1/pools"),
    ("GET", "/v1/pools/{pool_id}"),
    ("DELETE", "/v1/pools/{pool_id}"),
    ("POST", "/v1/sandboxes"),
    ("POST", "/v1/sandboxes/{sandbox_id}/run"),
    ("POST", "/v1/sandboxes/{sandbox_id}/processes"),
    ("POST", "/v1/sandboxes/{sandbox_id}/processes/{process_id}/read"),
    ("POST", "/v1/sandboxes/{sandbox_id}/processes/{process_id}/write"),
    ("POST", "/v1/sandboxes/{sandbox_id}/processes/{process_id}/close_stdin"),
    ("POST", "/v1/sandboxes/{sandbox_id}/processes/{process_id}/status"),
    ("POST", "/v1/sandboxes/{sandbox_id}/processes/{process_id}/cancel"),
    ("POST", "/v1/sandboxes/{sandbox_id}/reset"),
    ("POST", "/v1/sandboxes/{sandbox_id}/release"),
    ("GET", "/v1/sandboxes/{sandbox_id}/transcript"),
    ("GET", "/v1/sandboxes/{sandbox_id}/metrics"),
}


SAMPLE_PAYLOADS = {
    ("POST", "/v1/pools"): {"pool_id": "default", "size": 1},
    ("POST", "/v1/sandboxes"): {"pool_id": "default"},
    ("POST", "/v1/sandboxes/{sandbox_id}/run"): {"command": "true"},
    ("POST", "/v1/sandboxes/{sandbox_id}/processes"): {"command": "sleep 1"},
    ("POST", "/v1/sandboxes/{sandbox_id}/processes/{process_id}/read"): {"wait_ms": 0},
    ("POST", "/v1/sandboxes/{sandbox_id}/processes/{process_id}/write"): {"stdin_b64": ""},
    ("POST", "/v1/sandboxes/{sandbox_id}/processes/{process_id}/close_stdin"): {},
    ("POST", "/v1/sandboxes/{sandbox_id}/processes/{process_id}/status"): {},
    ("POST", "/v1/sandboxes/{sandbox_id}/processes/{process_id}/cancel"): {},
    ("POST", "/v1/sandboxes/{sandbox_id}/reset"): {},
    ("POST", "/v1/sandboxes/{sandbox_id}/release"): {},
}


class OpenApiContractTests(unittest.TestCase):
    def test_openapi_routes_match_public_service_routes(self):
        documented = documented_openapi_routes(Path("docs/openapi.yaml"))
        self.assertEqual(PUBLIC_ROUTES, documented)

    def test_documented_routes_are_accepted_by_router(self):
        service = FakeService()
        for method, template in sorted(PUBLIC_ROUTES):
            with self.subTest(method=method, path=template):
                result = route(service, method, concrete_path(template), SAMPLE_PAYLOADS.get((method, template), {}))
                self.assertIsInstance(result, dict)


def documented_openapi_routes(path: Path) -> set[tuple[str, str]]:
    routes: set[tuple[str, str]] = set()
    in_paths = False
    current_path: str | None = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if raw_line == "paths:":
            in_paths = True
            continue
        if in_paths and raw_line and not raw_line.startswith(" "):
            break
        if not in_paths:
            continue
        path_match = re.match(r"^  (/[^:]+):$", raw_line)
        if path_match:
            current_path = path_match.group(1)
            continue
        method_match = re.match(r"^    (get|post|delete|put|patch):$", raw_line)
        if current_path and method_match:
            routes.add((method_match.group(1).upper(), current_path))
    return routes


def concrete_path(template: str) -> str:
    return template.replace("{pool_id}", "default").replace("{sandbox_id}", "sandbox-1").replace("{process_id}", "process-1")


class FakeService:
    def healthz(self):
        return {"ok": True}

    def readyz(self):
        return {"ok": True}

    def varz(self):
        return {"ok": True}

    def prometheus_metrics(self):
        return "metric 1\n"

    def create_pool(self, payload):
        return {"ok": True, "payload": payload}

    def pool_status(self, pool_id):
        return {"ok": True, "pool_id": pool_id}

    def close_pool(self, pool_id):
        return {"ok": True, "pool_id": pool_id}

    def create_sandbox(self, payload):
        return {"ok": True, "sandbox_id": "sandbox-1", "payload": payload}

    def run(self, sandbox_id, payload):
        return {"ok": True, "sandbox_id": sandbox_id, "payload": payload}

    def start(self, sandbox_id, payload):
        return {"ok": True, "sandbox_id": sandbox_id, "process_id": "process-1", "payload": payload}

    def process_action(self, sandbox_id, process_id, action, payload):
        return {"ok": True, "sandbox_id": sandbox_id, "process_id": process_id, "action": action, "payload": payload}

    def reset_session(self, sandbox_id):
        return {"ok": True, "sandbox_id": sandbox_id}

    def release_sandbox(self, sandbox_id, payload):
        return {"ok": True, "sandbox_id": sandbox_id, "payload": payload}

    def transcript(self, sandbox_id):
        return {"ok": True, "sandbox_id": sandbox_id, "transcript": []}

    def metrics(self, sandbox_id):
        return {"ok": True, "sandbox_id": sandbox_id, "metrics": []}


if __name__ == "__main__":
    unittest.main()
