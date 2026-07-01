from __future__ import annotations

import json
import subprocess
import sys
import unittest


class ServiceSelfTestTests(unittest.TestCase):
    def test_pool_service_self_test_cli_passes(self):
        result = subprocess.run(
            [sys.executable, "scripts/firecracker_pool_service.py", "--self-test"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["assessment"], "pass")


if __name__ == "__main__":
    unittest.main()
